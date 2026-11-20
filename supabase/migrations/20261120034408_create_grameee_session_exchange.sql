-- S4-T2: isolated server-side exchange-code and application-session storage.
--
-- This migration is additive and dark by default. It does not register any
-- client, alter any existing session, or enable the exchange service.

alter table public.grameee_security_flags
  drop constraint grameee_security_flags_known_key;

alter table public.grameee_security_flags
  add constraint grameee_security_flags_known_key check (
    flag_key in (
      'insecure_auth_verification_enabled',
      'public_tool_submission_enabled',
      'admin_cookie_bridge_enabled',
      'session_exchange_enabled'
    )
  );

insert into public.grameee_security_flags (flag_key, enabled, user_message)
values (
  'session_exchange_enabled',
  false,
  'Cross-application session exchange is not enabled.'
)
on conflict (flag_key) do nothing;

create table public.grameee_session_exchange_clients (
  client_id text primary key,
  audience text not null unique,
  redirect_uris text[] not null,
  client_secret_hash text not null,
  enabled boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint grameee_session_exchange_clients_id_valid
    check (client_id ~ '^[a-z][a-z0-9_-]{2,63}$'),
  constraint grameee_session_exchange_clients_audience_valid
    check (audience ~ '^[a-z][a-z0-9._-]{2,127}$'),
  constraint grameee_session_exchange_clients_redirects_valid
    check (
      cardinality(redirect_uris) between 1 and 10
      and array_position(redirect_uris, null) is null
    ),
  constraint grameee_session_exchange_clients_secret_hash_valid
    check (client_secret_hash ~ '^[0-9a-f]{64}$')
);

comment on table public.grameee_session_exchange_clients is
  'Server-only registry for exact session-exchange audiences and callbacks. Never store plaintext client credentials.';
comment on column public.grameee_session_exchange_clients.client_secret_hash is
  'Lowercase HMAC-SHA-256 made with the exchange server key. The plaintext client secret exists only in the target server secret store.';

create table public.grameee_session_exchange_codes (
  exchange_id uuid primary key default gen_random_uuid(),
  code_hash text not null unique,
  user_id uuid not null,
  source_session_id uuid not null,
  client_id text not null references public.grameee_session_exchange_clients(client_id),
  audience text not null,
  redirect_uri text not null,
  pkce_challenge text not null,
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  redeem_attempt_count smallint not null default 0,
  last_failure_reason text,
  issue_context_hash text not null,
  redeem_context_hash text,

  constraint grameee_session_exchange_codes_hash_valid
    check (code_hash ~ '^[0-9a-f]{64}$'),
  constraint grameee_session_exchange_codes_pkce_valid
    check (pkce_challenge ~ '^[A-Za-z0-9_-]{43}$'),
  constraint grameee_session_exchange_codes_lifetime_valid
    check (
      expires_at > issued_at
      and expires_at <= issued_at + interval '60 seconds'
    ),
  constraint grameee_session_exchange_codes_consumed_valid
    check (consumed_at is null or consumed_at >= issued_at),
  constraint grameee_session_exchange_codes_attempts_valid
    check (redeem_attempt_count between 0 and 5),
  constraint grameee_session_exchange_codes_failure_valid
    check (
      last_failure_reason is null
      or last_failure_reason in (
        'binding_mismatch',
        'expired',
        'replay',
        'source_session_inactive',
        'session_create_failed'
      )
    ),
  constraint grameee_session_exchange_codes_issue_context_valid
    check (issue_context_hash ~ '^[0-9a-f]{64}$'),
  constraint grameee_session_exchange_codes_redeem_context_valid
    check (redeem_context_hash is null or redeem_context_hash ~ '^[0-9a-f]{64}$')
);

comment on table public.grameee_session_exchange_codes is
  'Short-lived, single-use, server-only exchange transactions. Raw exchange codes must never be stored.';
comment on column public.grameee_session_exchange_codes.code_hash is
  'Keyed hash of a 256-bit random exchange code. The raw code may exist only in the one issue response and callback URL.';
comment on column public.grameee_session_exchange_codes.issue_context_hash is
  'Privacy-minimized keyed request-context hash. Never store IP addresses, user agents, cookies, tokens, state, or codes.';

create index grameee_session_exchange_codes_expiry_idx
  on public.grameee_session_exchange_codes (expires_at);
create index grameee_session_exchange_codes_user_client_idx
  on public.grameee_session_exchange_codes (user_id, client_id, issued_at desc);
create index grameee_session_exchange_codes_session_idx
  on public.grameee_session_exchange_codes (source_session_id);

create table public.grameee_application_sessions (
  application_session_id uuid primary key default gen_random_uuid(),
  session_token_hash text not null unique,
  user_id uuid not null,
  source_session_id uuid not null,
  client_id text not null references public.grameee_session_exchange_clients(client_id),
  audience text not null,
  trusted_role text not null,
  trusted_privileges jsonb not null default '{}'::jsonb,
  issued_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  idle_expires_at timestamptz not null,
  absolute_expires_at timestamptz not null,
  revoked_at timestamptz,
  revocation_reason text,
  rotated_to uuid references public.grameee_application_sessions(application_session_id),

  constraint grameee_application_sessions_hash_valid
    check (session_token_hash ~ '^[0-9a-f]{64}$'),
  constraint grameee_application_sessions_role_valid
    check (trusted_role in ('admin', 'moderator', 'curator', 'user')),
  constraint grameee_application_sessions_privileges_object
    check (jsonb_typeof(trusted_privileges) = 'object'),
  constraint grameee_application_sessions_lifetime_valid
    check (
      last_seen_at >= issued_at
      and idle_expires_at > issued_at
      and idle_expires_at <= absolute_expires_at
      and absolute_expires_at <= issued_at + interval '7 days'
    ),
  constraint grameee_application_sessions_revocation_valid
    check (
      (revoked_at is null and revocation_reason is null)
      or (
        revoked_at is not null
        and revoked_at >= issued_at
        and revocation_reason in (
          'local_logout',
          'global_logout',
          'source_session_inactive',
          'account_inactive',
          'role_changed',
          'rotated',
          'security_response'
        )
      )
    )
);

comment on table public.grameee_application_sessions is
  'Opaque, host/audience-bound application sessions. Browser cookies contain only the raw opaque token; this table stores its keyed hash.';
comment on column public.grameee_application_sessions.trusted_role is
  'Server-derived app_metadata role snapshot. Never derive authorization from user_metadata or browser summary data.';

create index grameee_application_sessions_active_idx
  on public.grameee_application_sessions (client_id, user_id, absolute_expires_at)
  where revoked_at is null;
create index grameee_application_sessions_source_idx
  on public.grameee_application_sessions (source_session_id)
  where revoked_at is null;

create table public.grameee_session_exchange_events (
  event_id bigint generated always as identity primary key,
  occurred_at timestamptz not null default now(),
  event_type text not null,
  outcome text not null,
  exchange_id uuid references public.grameee_session_exchange_codes(exchange_id) on delete set null,
  application_session_id uuid references public.grameee_application_sessions(application_session_id) on delete set null,
  user_id uuid,
  client_id text,
  audience text,
  reason text,
  request_context_hash text,

  constraint grameee_session_exchange_events_type_valid
    check (event_type in ('issue', 'redeem', 'validate', 'revoke')),
  constraint grameee_session_exchange_events_outcome_valid
    check (outcome in ('success', 'denied', 'expired', 'replay', 'revoked')),
  constraint grameee_session_exchange_events_reason_valid
    check (reason is null or char_length(reason) between 1 and 80),
  constraint grameee_session_exchange_events_context_valid
    check (request_context_hash is null or request_context_hash ~ '^[0-9a-f]{64}$')
);

comment on table public.grameee_session_exchange_events is
  'Privacy-minimized exchange/session audit events. Never store raw codes, session tokens, client secrets, authorization headers, cookies, emails, IP addresses, or user agents.';

create index grameee_session_exchange_events_occurred_idx
  on public.grameee_session_exchange_events (occurred_at desc);
create index grameee_session_exchange_events_client_idx
  on public.grameee_session_exchange_events (client_id, occurred_at desc);

alter table public.grameee_session_exchange_clients enable row level security;
alter table public.grameee_session_exchange_clients force row level security;
alter table public.grameee_session_exchange_codes enable row level security;
alter table public.grameee_session_exchange_codes force row level security;
alter table public.grameee_application_sessions enable row level security;
alter table public.grameee_application_sessions force row level security;
alter table public.grameee_session_exchange_events enable row level security;
alter table public.grameee_session_exchange_events force row level security;

revoke all on table public.grameee_session_exchange_clients from public, anon, authenticated;
revoke all on table public.grameee_session_exchange_codes from public, anon, authenticated;
revoke all on table public.grameee_application_sessions from public, anon, authenticated;
revoke all on table public.grameee_session_exchange_events from public, anon, authenticated;
revoke all on sequence public.grameee_session_exchange_events_event_id_seq from public, anon, authenticated;

grant select, insert, update, delete on table public.grameee_session_exchange_clients to service_role;
grant select, insert, update, delete on table public.grameee_session_exchange_codes to service_role;
grant select, insert, update, delete on table public.grameee_application_sessions to service_role;
grant select, insert on table public.grameee_session_exchange_events to service_role;
grant usage, select on sequence public.grameee_session_exchange_events_event_id_seq to service_role;

select cron.schedule(
  'grameee-session-exchange-retention',
  '29 2 * * *',
  $cleanup$
    delete from public.grameee_session_exchange_codes
    where expires_at < now() - interval '24 hours';

    delete from public.grameee_application_sessions
    where absolute_expires_at < now() - interval '30 days'
       or (revoked_at is not null and revoked_at < now() - interval '30 days');

    delete from public.grameee_session_exchange_events
    where occurred_at < now() - interval '90 days';
  $cleanup$
);

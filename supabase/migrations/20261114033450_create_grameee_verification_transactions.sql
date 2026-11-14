-- S1-T1: server-side verification transactions for registration and recovery.
--
-- This migration only adds isolated infrastructure. Existing users, sessions,
-- and authentication data are not read or modified.

create extension if not exists pg_cron with schema pg_catalog;

create table public.grameee_verification_transactions (
  transaction_id uuid primary key default gen_random_uuid(),
  normalized_target text not null,
  purpose text not null,
  otp_hash text not null,
  expires_at timestamptz not null,
  attempt_count smallint not null default 0,
  max_attempts smallint not null default 5,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  request_metadata jsonb not null default '{}'::jsonb,
  target_rate_limit_key text not null,
  origin_rate_limit_key text not null,

  constraint grameee_verification_transactions_target_normalized
    check (
      normalized_target = lower(btrim(normalized_target))
      and char_length(normalized_target) between 3 and 320
    ),
  constraint grameee_verification_transactions_purpose_allowed
    check (purpose in ('register', 'forgot-password')),
  constraint grameee_verification_transactions_otp_hash_format
    check (otp_hash ~ '^[0-9a-f]{64}$'),
  constraint grameee_verification_transactions_attempts_valid
    check (
      attempt_count between 0 and 20
      and max_attempts between 1 and 20
      and attempt_count <= max_attempts
    ),
  constraint grameee_verification_transactions_expiry_valid
    check (expires_at > created_at),
  constraint grameee_verification_transactions_consumed_valid
    check (consumed_at is null or consumed_at >= created_at),
  constraint grameee_verification_transactions_metadata_object
    check (jsonb_typeof(request_metadata) = 'object'),
  constraint grameee_verification_transactions_target_key_format
    check (target_rate_limit_key ~ '^[0-9a-f]{64}$'),
  constraint grameee_verification_transactions_origin_key_format
    check (origin_rate_limit_key ~ '^[0-9a-f]{64}$')
);

comment on table public.grameee_verification_transactions is
  'Internal one-time verification transactions. Service-role access only; never expose OTPs or raw rate-limit identifiers.';
comment on column public.grameee_verification_transactions.transaction_id is
  'Opaque identifier returned to the client in place of a verifier-bearing token.';
comment on column public.grameee_verification_transactions.otp_hash is
  'Lowercase hexadecimal HMAC-SHA-256 of the OTP using a server-only key; never store a plaintext OTP.';
comment on column public.grameee_verification_transactions.request_metadata is
  'Non-secret creation context only. Do not store authorization headers, cookies, tokens, OTPs, or raw IP addresses.';
comment on column public.grameee_verification_transactions.target_rate_limit_key is
  'Lowercase hexadecimal server-keyed hash of the normalized target for rate limiting.';
comment on column public.grameee_verification_transactions.origin_rate_limit_key is
  'Lowercase hexadecimal server-keyed hash of the request origin identifier for rate limiting.';

create index grameee_verification_transactions_expiry_idx
  on public.grameee_verification_transactions (expires_at);
create index grameee_verification_transactions_target_rate_idx
  on public.grameee_verification_transactions (target_rate_limit_key, purpose, created_at desc);
create index grameee_verification_transactions_origin_rate_idx
  on public.grameee_verification_transactions (origin_rate_limit_key, purpose, created_at desc);

alter table public.grameee_verification_transactions enable row level security;
alter table public.grameee_verification_transactions force row level security;

-- No RLS policies are intentionally created. Client roles have neither table
-- privileges nor a policy path. The server-side Edge Function uses the
-- service_role, which has BYPASSRLS, and receives only the required DML grants.
revoke all on table public.grameee_verification_transactions from public, anon, authenticated;
grant select, insert, update, delete on table public.grameee_verification_transactions to service_role;

select cron.schedule(
  'grameee-verification-transactions-retention',
  '17 2 * * *',
  $cleanup$
    delete from public.grameee_verification_transactions
    where expires_at < now() - interval '24 hours'
       or (consumed_at is not null and consumed_at < now() - interval '24 hours')
  $cleanup$
);

create table if not exists public.grameee_security_audit_events (
  event_id uuid primary key default gen_random_uuid(),
  correlation_id uuid not null,
  event_type text not null,
  outcome text not null,
  user_id uuid,
  sessions_revoked integer not null default 0,
  notification_sent boolean not null default false,
  failure_phase text,
  request_metadata jsonb not null default '{}'::jsonb,
  occurred_at timestamptz not null default now(),
  constraint grameee_security_audit_event_type_check
    check (event_type = 'password_reset'),
  constraint grameee_security_audit_outcome_check
    check (outcome in ('success', 'failure')),
  constraint grameee_security_audit_sessions_check
    check (sessions_revoked >= 0),
  constraint grameee_security_audit_failure_phase_check
    check (failure_phase is null or failure_phase in ('session_revoke', 'password_update')),
  constraint grameee_security_audit_metadata_object_check
    check (jsonb_typeof(request_metadata) = 'object')
);

comment on table public.grameee_security_audit_events is
  'Service-only security events. Never store passwords, tokens, OTPs, email addresses, login IDs, or raw IP addresses.';

create index if not exists grameee_security_audit_events_user_time_idx
  on public.grameee_security_audit_events (user_id, occurred_at desc);

create index if not exists grameee_security_audit_events_type_time_idx
  on public.grameee_security_audit_events (event_type, occurred_at desc);

alter table public.grameee_security_audit_events enable row level security;
alter table public.grameee_security_audit_events force row level security;

revoke all on table public.grameee_security_audit_events from public, anon, authenticated;
grant select, insert on table public.grameee_security_audit_events to service_role;

create or replace function public.grameee_revoke_user_sessions(p_user_id uuid)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  revoked_count integer;
begin
  if p_user_id is null then
    raise exception 'User ID is required.' using errcode = '22004';
  end if;

  delete from auth.sessions
  where user_id = p_user_id;

  get diagnostics revoked_count = row_count;
  return revoked_count;
end;
$$;

comment on function public.grameee_revoke_user_sessions(uuid) is
  'Revokes every Supabase Auth session for one user after verified password recovery. Service role only.';

revoke all on function public.grameee_revoke_user_sessions(uuid) from public, anon, authenticated;
grant execute on function public.grameee_revoke_user_sessions(uuid) to service_role;

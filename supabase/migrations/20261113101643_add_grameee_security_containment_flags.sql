create table if not exists public.grameee_security_flags (
  flag_key text primary key,
  enabled boolean not null default false,
  user_message text not null,
  updated_at timestamptz not null default now(),
  constraint grameee_security_flags_known_key check (
    flag_key in (
      'insecure_auth_verification_enabled',
      'public_tool_submission_enabled',
      'admin_cookie_bridge_enabled'
    )
  )
);

comment on table public.grameee_security_flags is
  'Publicly readable, operator-controlled emergency containment flags. No secrets may be stored here.';

alter table public.grameee_security_flags enable row level security;

revoke all on table public.grameee_security_flags from anon, authenticated;
grant select on table public.grameee_security_flags to anon, authenticated;

drop policy if exists "public can read grameee security flags"
  on public.grameee_security_flags;

create policy "public can read grameee security flags"
  on public.grameee_security_flags
  for select
  to anon, authenticated
  using (
    flag_key in (
      'insecure_auth_verification_enabled',
      'public_tool_submission_enabled',
      'admin_cookie_bridge_enabled'
    )
  );

insert into public.grameee_security_flags (flag_key, enabled, user_message)
values
  (
    'insecure_auth_verification_enabled',
    false,
    'Account registration and password recovery are temporarily unavailable while we complete a security upgrade. Existing users can continue to sign in.'
  ),
  (
    'public_tool_submission_enabled',
    false,
    'New tool submissions are temporarily paused while we improve the review system. The approved tool directory remains available.'
  ),
  (
    'admin_cookie_bridge_enabled',
    false,
    'Cross-site administrator access is temporarily disabled. Use the application administrator login.'
  )
on conflict (flag_key) do nothing;

drop policy if exists "public can submit pending grameee tools"
  on public.grameee_tools;

create policy "public can submit pending grameee tools"
  on public.grameee_tools
  for insert
  to anon, authenticated
  with check (
    status = 'pending'
    and approved_at is null
    and exists (
      select 1
      from public.grameee_security_flags as security_flag
      where security_flag.flag_key = 'public_tool_submission_enabled'
        and security_flag.enabled = true
    )
  );


-- Roll back only the dark S4-T2 exchange infrastructure.

select cron.unschedule(jobid)
from cron.job
where jobname = 'grameee-session-exchange-retention';

drop table if exists public.grameee_session_exchange_events;
drop table if exists public.grameee_application_sessions;
drop table if exists public.grameee_session_exchange_codes;
drop table if exists public.grameee_session_exchange_clients;

delete from public.grameee_security_flags
where flag_key = 'session_exchange_enabled';

alter table public.grameee_security_flags
  drop constraint if exists grameee_security_flags_known_key;

alter table public.grameee_security_flags
  add constraint grameee_security_flags_known_key check (
    flag_key in (
      'insecure_auth_verification_enabled',
      'public_tool_submission_enabled',
      'admin_cookie_bridge_enabled'
    )
  );

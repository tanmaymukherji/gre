revoke all on function public.grameee_revoke_user_sessions(uuid) from service_role;
drop function if exists public.grameee_revoke_user_sessions(uuid);

revoke all on table public.grameee_security_audit_events from service_role;
drop table if exists public.grameee_security_audit_events;

-- Read-only S4-T2 production acceptance checks.

select flag_key, enabled
from public.grameee_security_flags
where flag_key = 'session_exchange_enabled';

select
  relname,
  relrowsecurity,
  relforcerowsecurity
from pg_class
where oid in (
  'public.grameee_session_exchange_clients'::regclass,
  'public.grameee_session_exchange_codes'::regclass,
  'public.grameee_application_sessions'::regclass,
  'public.grameee_session_exchange_events'::regclass
)
order by relname;

select
  table_name,
  has_table_privilege('anon', format('public.%I', table_name), 'select') as anon_select,
  has_table_privilege('anon', format('public.%I', table_name), 'insert') as anon_insert,
  has_table_privilege('authenticated', format('public.%I', table_name), 'select') as authenticated_select,
  has_table_privilege('authenticated', format('public.%I', table_name), 'insert') as authenticated_insert,
  has_table_privilege('service_role', format('public.%I', table_name), 'select') as service_select
from (
  values
    ('grameee_session_exchange_clients'),
    ('grameee_session_exchange_codes'),
    ('grameee_application_sessions'),
    ('grameee_session_exchange_events')
) as tables(table_name)
order by table_name;

select
  (select count(*) from public.grameee_session_exchange_clients) as clients,
  (select count(*) from public.grameee_session_exchange_codes) as codes,
  (select count(*) from public.grameee_application_sessions) as sessions,
  (select count(*) from public.grameee_session_exchange_events) as events;

select jobname, schedule, active
from cron.job
where jobname = 'grameee-session-exchange-retention';

-- Read-only S3-T1 acceptance checks for the production schema.
select
  has_table_privilege('anon', 'public.grameee_tools', 'select') as anon_can_select,
  has_table_privilege('anon', 'public.grameee_tools', 'insert') as anon_can_insert,
  has_table_privilege('anon', 'public.grameee_tools', 'update') as anon_can_update,
  has_table_privilege('anon', 'public.grameee_tools', 'delete') as anon_can_delete,
  has_table_privilege('authenticated', 'public.grameee_tools', 'select') as authenticated_can_select,
  has_table_privilege('authenticated', 'public.grameee_tools', 'insert') as authenticated_can_insert,
  has_table_privilege('authenticated', 'public.grameee_tools', 'update') as authenticated_can_update,
  has_table_privilege('authenticated', 'public.grameee_tools', 'delete') as authenticated_can_delete;

select polname, polcmd, polroles::regrole[] as roles
from pg_policy
where polrelid = 'public.grameee_tools'::regclass
order by polname;

select conname, pg_get_constraintdef(oid) as definition
from pg_constraint
where conrelid = 'public.grameee_tools'::regclass
order by conname;

select flag_key, enabled
from public.grameee_security_flags
where flag_key = 'public_tool_submission_enabled';

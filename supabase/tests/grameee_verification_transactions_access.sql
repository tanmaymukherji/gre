-- S1-T1 production acceptance query. It is read-only and returns one row.
-- All client privilege columns must be false, policy_count must be zero, and
-- both row_security columns must be true.

select
  c.relrowsecurity as row_security_enabled,
  c.relforcerowsecurity as row_security_forced,
  (
    select count(*)
    from pg_policies p
    where p.schemaname = 'public'
      and p.tablename = 'grameee_verification_transactions'
  ) as policy_count,
  has_table_privilege('anon', c.oid, 'select') as anon_select,
  has_table_privilege('anon', c.oid, 'insert') as anon_insert,
  has_table_privilege('anon', c.oid, 'update') as anon_update,
  has_table_privilege('anon', c.oid, 'delete') as anon_delete,
  has_table_privilege('authenticated', c.oid, 'select') as authenticated_select,
  has_table_privilege('authenticated', c.oid, 'insert') as authenticated_insert,
  has_table_privilege('authenticated', c.oid, 'update') as authenticated_update,
  has_table_privilege('authenticated', c.oid, 'delete') as authenticated_delete,
  has_table_privilege('service_role', c.oid, 'select,insert,update,delete') as service_role_dml
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relname = 'grameee_verification_transactions';

-- Roll back S1-T1 without touching any existing user, session, or auth data.
-- Keep pg_cron installed because it is a shared database extension and may be
-- used by other jobs after this migration.

select cron.unschedule(jobid)
from cron.job
where jobname = 'grameee-verification-transactions-retention';

drop table if exists public.grameee_verification_transactions;

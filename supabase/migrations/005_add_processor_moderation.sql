create extension if not exists pgcrypto;

alter table public.processors
  add column if not exists id uuid default gen_random_uuid(),
  add column if not exists status text not null default 'approved',
  add column if not exists submitted_by text,
  add column if not exists approved_at timestamptz,
  add column if not exists approved_by text;

update public.processors
set id = gen_random_uuid()
where id is null;

alter table public.processors
  alter column id set not null;

do $$
begin
  if exists (
    select 1
    from information_schema.table_constraints
    where table_schema = 'public'
      and table_name = 'processors'
      and constraint_name = 'processors_pkey'
  ) then
    alter table public.processors drop constraint processors_pkey;
  end if;
end $$;

alter table public.processors
  add constraint processors_pkey primary key (id);

update public.processors
set
  status = coalesce(status, 'approved'),
  approved_at = coalesce(approved_at, created_at, now()),
  approved_by = coalesce(approved_by, 'seed')
where status is distinct from 'approved'
   or approved_at is null
   or approved_by is null;

do $$
begin
  if not exists (
    select 1
    from information_schema.table_constraints
    where table_schema = 'public'
      and table_name = 'processors'
      and constraint_name = 'processors_status_check'
  ) then
    alter table public.processors
      add constraint processors_status_check check (status in ('pending', 'approved'));
  end if;
end $$;

create unique index if not exists processors_name_lower_key
on public.processors (lower(name));

create index if not exists processors_status_idx
on public.processors (status, created_at desc);

alter table public.grameee_admin_accounts enable row level security;
alter table public.grameee_admin_sessions enable row level security;

drop policy if exists "public can read processors" on public.processors;
drop policy if exists "public can insert processors" on public.processors;
drop policy if exists "public can update processors" on public.processors;
drop policy if exists "public can delete processors" on public.processors;

create policy "approved processors are public"
on public.processors
for select
to anon, authenticated
using (status = 'approved');

create policy "public can submit pending processors"
on public.processors
for insert
to anon, authenticated
with check (
  status = 'pending'
  and approved_at is null
  and approved_by is null
);

alter table public.grameee_tools
  drop constraint if exists grameee_tools_submitter_email_valid,
  drop constraint if exists grameee_tools_submitter_name_valid,
  drop constraint if exists grameee_tools_description_valid,
  drop constraint if exists grameee_tools_category_valid,
  drop constraint if exists grameee_tools_url_valid,
  drop constraint if exists grameee_tools_name_valid;

grant insert on table public.grameee_tools to anon, authenticated;

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

comment on table public.grameee_tools is null;

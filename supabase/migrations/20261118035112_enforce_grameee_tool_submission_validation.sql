-- S3-T1: accept public tool submissions only through the validating Edge Function.
-- Existing approved/pending records have been checked against these bounds.

drop policy if exists "public can submit pending grameee tools"
  on public.grameee_tools;

revoke insert, update, delete, truncate, references, trigger
  on table public.grameee_tools
  from anon, authenticated;

grant select
  on table public.grameee_tools
  to anon, authenticated;

alter table public.grameee_tools
  add constraint grameee_tools_name_valid
    check (
      char_length(name) between 1 and 160
      and name = btrim(name)
      and name !~ '[[:cntrl:]<>]'
    ),
  add constraint grameee_tools_url_valid
    check (
      char_length(url) between 1 and 2048
      and url = btrim(url)
      and url ~ '^https://[^/?#[:space:]<>"''`]+(?:[/?#][^[:cntrl:]<>"''`]*)?$'
    ),
  add constraint grameee_tools_category_valid
    check (
      category is null
      or (
        char_length(category) between 1 and 120
        and category = btrim(category)
        and category !~ '[[:cntrl:]<>]'
      )
    ),
  add constraint grameee_tools_description_valid
    check (
      description is null
      or (
        char_length(description) between 1 and 900000
        and description = btrim(description)
        and description !~ E'[\\x01-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F<>]'
      )
    ),
  add constraint grameee_tools_submitter_name_valid
    check (
      submitted_by_name is null
      or (
        char_length(submitted_by_name) between 1 and 160
        and submitted_by_name = btrim(submitted_by_name)
        and submitted_by_name !~ '[[:cntrl:]<>]'
      )
    ),
  add constraint grameee_tools_submitter_email_valid
    check (
      submitted_by_email is null
      or (
        char_length(submitted_by_email) between 3 and 320
        and submitted_by_email = btrim(submitted_by_email)
        and submitted_by_email ~* '^[A-Z0-9.!#$%&''*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:[.][A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$'
      )
    );

comment on table public.grameee_tools is
  'Publicly readable approved tool directory. Public writes must use the validating grameee-admin submitTool action; client roles have no direct DML grants.';

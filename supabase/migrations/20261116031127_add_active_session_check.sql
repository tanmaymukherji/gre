create or replace function public.grameee_is_active_session(
  p_session_id uuid,
  p_user_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from auth.sessions as session_record
    join auth.users as user_record
      on user_record.id = session_record.user_id
    where session_record.id = p_session_id
      and session_record.user_id = p_user_id
      and (session_record.not_after is null or session_record.not_after > now())
      and user_record.deleted_at is null
      and lower(coalesce(user_record.raw_app_meta_data ->> 'grameee_removed', 'false')) <> 'true'
      and lower(coalesce(user_record.raw_app_meta_data ->> 'grameee_role', 'user')) <> 'removed'
  );
$$;

comment on function public.grameee_is_active_session(uuid, uuid) is
  'Returns whether a verified Supabase user still has the referenced active session. Service role only.';

revoke all on function public.grameee_is_active_session(uuid, uuid) from public;
revoke all on function public.grameee_is_active_session(uuid, uuid) from anon;
revoke all on function public.grameee_is_active_session(uuid, uuid) from authenticated;
grant execute on function public.grameee_is_active_session(uuid, uuid) to service_role;

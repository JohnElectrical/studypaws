-- StudyPaws Stage 3 setup. Supabase > SQL Editor > New query > paste all > Run.
create table public.profiles(
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  role text not null default 'user' check (role in ('user','admin')),
  status text not null default 'active' check (status in ('active','suspended')),
  created_at timestamptz not null default now());
create table public.user_data(
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now());
create table public.app_settings(key text primary key, value text not null default '', updated_at timestamptz default now());
insert into public.app_settings(key,value) values('announcement','');
alter table public.profiles enable row level security;
alter table public.user_data enable row level security;
alter table public.app_settings enable row level security;

create function public.is_admin() returns boolean language sql security definer set search_path=public stable
as $$ select exists(select 1 from public.profiles where id=auth.uid() and role='admin' and status='active') $$;
create function public.is_active() returns boolean language sql security definer set search_path=public stable
as $$ select exists(select 1 from public.profiles where id=auth.uid() and status='active') $$;

-- profiles: you can read your own; admins can read all. Users may only change display_name (column grant), never role/status.
create policy "read own or admin" on public.profiles for select to authenticated using (id=auth.uid() or public.is_admin());
create policy "edit own name" on public.profiles for update to authenticated using (id=auth.uid()) with check (id=auth.uid());
revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;
grant update(display_name) on public.profiles to authenticated;

-- user_data: strictly your own row
create policy "own data select" on public.user_data for select to authenticated using (user_id=auth.uid() and public.is_active());
create policy "own data insert" on public.user_data for insert to authenticated with check (user_id=auth.uid() and public.is_active());
create policy "own data update" on public.user_data for update to authenticated using (user_id=auth.uid() and public.is_active()) with check (user_id=auth.uid());
create policy "own data delete" on public.user_data for delete to authenticated using (user_id=auth.uid());
revoke all on public.user_data from anon;

-- app_settings: everyone can read, only admins can write
create policy "read settings" on public.app_settings for select to anon, authenticated using (true);
create policy "admin writes settings" on public.app_settings for all to authenticated using (public.is_admin()) with check (public.is_admin());
revoke insert, update, delete on public.app_settings from anon;

-- auto-create a profile for every new account (always role 'user')
create function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public
as $$ begin insert into public.profiles(id,display_name) values(new.id, split_part(new.email,'@',1)); return new; end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

-- admin-only functions (each re-checks is_admin() on the server)
create function public.admin_stats() returns json language plpgsql security definer set search_path=public as $$
begin if not public.is_admin() then raise exception 'not authorized'; end if;
return json_build_object('users',(select count(*) from public.profiles),
 'new_week',(select count(*) from public.profiles where created_at>now()-interval '7 days'),
 'suspended',(select count(*) from public.profiles where status='suspended'),
 'sessions',(select coalesce(sum(jsonb_array_length(coalesce(data->'study'->'history','[]'::jsonb))),0) from public.user_data));
end $$;
create function public.admin_users() returns table(id uuid,email text,display_name text,role text,status text,created_at timestamptz,last_sign_in_at timestamptz)
language plpgsql security definer set search_path=public as $$
begin if not public.is_admin() then raise exception 'not authorized'; end if;
return query select p.id,u.email::text,p.display_name,p.role,p.status,p.created_at,u.last_sign_in_at from public.profiles p join auth.users u on u.id=p.id order by p.created_at desc;
end $$;
create function public.admin_set_status(target uuid,new_status text) returns void language plpgsql security definer set search_path=public as $$
begin if not public.is_admin() then raise exception 'not authorized'; end if;
if target=auth.uid() then raise exception 'cannot change yourself'; end if;
if new_status not in ('active','suspended') then raise exception 'bad status'; end if;
update public.profiles set status=new_status where id=target and role<>'admin'; end $$;
revoke execute on function public.admin_stats(), public.admin_users(), public.admin_set_status(uuid,text) from public, anon;
grant execute on function public.admin_stats(), public.admin_users(), public.admin_set_status(uuid,text) to authenticated;

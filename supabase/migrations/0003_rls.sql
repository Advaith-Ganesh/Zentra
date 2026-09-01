-- =============================================================================
-- Zentra 0003 — Row Level Security
-- =============================================================================
-- RLS is the last line of defence. The FastAPI service also performs explicit
-- server-side authorization on every request; these policies additionally
-- constrain any direct PostgREST/Supabase-client access made by the browser
-- using the end user's own JWT.
--
-- Roles mirror Supabase: `anon` (unauthenticated), `authenticated` (a signed-in
-- end user) and `service_role` (trusted backend, bypasses RLS).
-- =============================================================================

do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    create role service_role nologin noinherit bypassrls;
  end if;
end $$;

grant usage on schema public to anon, authenticated, service_role;
grant usage on schema auth to anon, authenticated, service_role;

-- ---------------------------------------------------------------------------
-- Tenancy helper functions.
-- SECURITY DEFINER so that evaluating a policy on organization_members does not
-- recurse into that table's own policy. search_path is pinned to defeat
-- search-path hijacking.
-- ---------------------------------------------------------------------------
create or replace function public.is_org_member(target_org uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.organization_members m
    where m.user_id = auth.uid()
      and m.status = 'active'
      and (
        m.organization_id = target_org
        -- MSSP: a member of a parent MSSP organization may read its managed
        -- client organizations. parent_organization_id is null for every
        -- ordinary customer, so this never widens standard tenant isolation.
        or m.organization_id = (
          select o.parent_organization_id from public.organizations o where o.id = target_org
        )
      )
  );
$$;

create or replace function public.has_org_role(target_org uuid, allowed org_role[])
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.organization_members m
    where m.user_id = auth.uid()
      and m.status = 'active'
      and m.organization_id = target_org
      and m.role = any(allowed)
  );
$$;

create or replace function public.is_platform_admin()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select coalesce(
    (select u.is_platform_admin from public.users u where u.id = auth.uid()),
    false
  );
$$;

revoke all on function public.is_org_member(uuid) from public;
revoke all on function public.has_org_role(uuid, org_role[]) from public;
revoke all on function public.is_platform_admin() from public;
grant execute on function public.is_org_member(uuid) to authenticated, service_role;
grant execute on function public.has_org_role(uuid, org_role[]) to authenticated, service_role;
grant execute on function public.is_platform_admin() to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- Enable + force RLS on every table. `force` also applies policies to the
-- table owner, so a mistake in service configuration cannot silently expose
-- cross-tenant rows.
-- ---------------------------------------------------------------------------
do $$
declare t text;
begin
  foreach t in array array[
    'users','organizations','organization_members','invitations','subscriptions',
    'vendors','vendor_domains','scans','scan_results','findings',
    'finding_status_history','alerts','api_keys','integration_connections',
    'slack_workspaces','benchmark_data','audit_logs','reports','report_exports',
    'webhook_events','public_scans'
  ] loop
    execute format('alter table public.%I enable row level security;', t);
    execute format('alter table public.%I force row level security;', t);
    execute format('revoke all on public.%I from anon, authenticated;', t);
  end loop;
end $$;

-- Column-level grants: `authenticated` may read/write tenant tables subject to
-- the policies below. `anon` gets nothing at all.
grant select, insert, update, delete on
  public.vendors, public.vendor_domains, public.findings,
  public.finding_status_history, public.alerts, public.reports
  to authenticated;
grant select on
  public.users, public.organizations, public.organization_members,
  public.subscriptions, public.scans, public.scan_results, public.api_keys,
  public.integration_connections, public.report_exports, public.audit_logs,
  public.benchmark_data, public.invitations
  to authenticated;
grant all on all tables in schema public to service_role;

-- ---------------------------------------------------------------------------
-- users: a user sees only their own row, plus co-members of their orgs.
-- ---------------------------------------------------------------------------
drop policy if exists users_select on public.users;
create policy users_select on public.users
  for select to authenticated
  using (
    id = auth.uid()
    or exists (
      select 1
      from public.organization_members mine
      join public.organization_members theirs
        on theirs.organization_id = mine.organization_id
      where mine.user_id = auth.uid()
        and mine.status = 'active'
        and theirs.user_id = public.users.id
    )
  );

drop policy if exists users_update_self on public.users;
create policy users_update_self on public.users
  for update to authenticated
  using (id = auth.uid())
  with check (id = auth.uid());

-- ---------------------------------------------------------------------------
-- organizations
-- ---------------------------------------------------------------------------
drop policy if exists organizations_select on public.organizations;
create policy organizations_select on public.organizations
  for select to authenticated
  using (public.is_org_member(id));

drop policy if exists organizations_update on public.organizations;
create policy organizations_update on public.organizations
  for update to authenticated
  using (public.has_org_role(id, array['owner','admin']::org_role[]))
  with check (public.has_org_role(id, array['owner','admin']::org_role[]));

-- ---------------------------------------------------------------------------
-- organization_members
-- ---------------------------------------------------------------------------
drop policy if exists org_members_select on public.organization_members;
create policy org_members_select on public.organization_members
  for select to authenticated
  using (public.is_org_member(organization_id));

drop policy if exists org_members_write on public.organization_members;
create policy org_members_write on public.organization_members
  for all to authenticated
  using (public.has_org_role(organization_id, array['owner','admin']::org_role[]))
  with check (public.has_org_role(organization_id, array['owner','admin']::org_role[]));

-- ---------------------------------------------------------------------------
-- Read-for-members / write-for-staff tenant tables
-- ---------------------------------------------------------------------------
do $$
declare t text;
begin
  foreach t in array array[
    'invitations','subscriptions','vendors','vendor_domains','scans','scan_results',
    'findings','finding_status_history','alerts','api_keys',
    'integration_connections','slack_workspaces','reports','report_exports','audit_logs'
  ] loop
    execute format('drop policy if exists %1$s_tenant_select on public.%1$s;', t);
    execute format(
      'create policy %1$s_tenant_select on public.%1$s
         for select to authenticated
         using (public.is_org_member(organization_id));', t);
  end loop;

  -- Members with a working role may create/modify operational records.
  foreach t in array array['vendors','vendor_domains','findings','finding_status_history','reports','alerts'] loop
    execute format('drop policy if exists %1$s_tenant_write on public.%1$s;', t);
    execute format('drop policy if exists %1$s_tenant_update on public.%1$s;', t);
    execute format('drop policy if exists %1$s_tenant_delete on public.%1$s;', t);
    execute format(
      'create policy %1$s_tenant_write on public.%1$s
         for insert to authenticated
         with check (public.has_org_role(organization_id, array[''owner'',''admin'',''analyst'']::org_role[]));', t);
    execute format(
      'create policy %1$s_tenant_update on public.%1$s
         for update to authenticated
         using (public.has_org_role(organization_id, array[''owner'',''admin'',''analyst'']::org_role[]))
         with check (public.has_org_role(organization_id, array[''owner'',''admin'',''analyst'']::org_role[]));', t);
    execute format(
      'create policy %1$s_tenant_delete on public.%1$s
         for delete to authenticated
         using (public.has_org_role(organization_id, array[''owner'',''admin'']::org_role[]));', t);
  end loop;
end $$;

-- ---------------------------------------------------------------------------
-- api_keys: the hash column must never be readable by an end user session.
-- Only admins may see key metadata; the API issues/revokes via service_role.
-- ---------------------------------------------------------------------------
drop policy if exists api_keys_tenant_select on public.api_keys;
create policy api_keys_tenant_select on public.api_keys
  for select to authenticated
  using (public.has_org_role(organization_id, array['owner','admin']::org_role[]));

revoke select on public.api_keys from authenticated;
grant select (id, organization_id, name, key_prefix, scopes, created_by,
              last_used_at, expires_at, revoked_at, created_at)
  on public.api_keys to authenticated;

-- integration secrets are never exposed to an end-user session
revoke select on public.integration_connections from authenticated;
grant select (id, organization_id, provider, external_id, display_name, status,
              config, created_by, created_at, updated_at)
  on public.integration_connections to authenticated;

revoke select on public.slack_workspaces from authenticated;
grant select (id, organization_id, team_id, team_name, bot_user_id,
              default_channel_id, installed_by, created_at, updated_at)
  on public.slack_workspaces to authenticated;

-- ---------------------------------------------------------------------------
-- Aggregate benchmark data is readable by any signed-in user. It contains no
-- per-customer rows by construction.
-- ---------------------------------------------------------------------------
drop policy if exists benchmark_select on public.benchmark_data;
create policy benchmark_select on public.benchmark_data
  for select to authenticated
  using (sample_size >= 5);

-- ---------------------------------------------------------------------------
-- webhook_events and public_scans are backend-only: no policy for
-- authenticated/anon means no row is ever visible to them.
-- ---------------------------------------------------------------------------

-- =============================================================================
-- Zentra 0002 — core multi-tenant schema
-- =============================================================================

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
create table if not exists public.users (
  id                uuid primary key default gen_random_uuid(),
  email             citext not null unique,
  full_name         text,
  avatar_url        text,
  -- Only populated when AUTH_PROVIDER=local. Under Supabase Auth the
  -- credential lives in auth.users and this column stays null.
  password_hash     text,
  is_platform_admin boolean not null default false,
  email_verified_at timestamptz,
  last_login_at     timestamptz,
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now(),
  deleted_at        timestamptz,
  constraint users_email_length check (char_length(email::text) between 3 and 320)
);

-- Link to Supabase Auth when that schema is present (hosted Supabase only).
do $$
begin
  if exists (select 1 from information_schema.tables
             where table_schema = 'auth' and table_name = 'users')
     and not exists (select 1 from pg_constraint where conname = 'users_auth_fk')
  then
    execute 'alter table public.users add constraint users_auth_fk
             foreign key (id) references auth.users(id) on delete cascade';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- organizations
-- ---------------------------------------------------------------------------
create table if not exists public.organizations (
  id                       uuid primary key default gen_random_uuid(),
  name                     text not null,
  slug                     citext not null unique,
  org_type                 org_type not null default 'customer',
  -- MSSP hierarchy: a client org may be managed by an MSSP parent org.
  parent_organization_id   uuid references public.organizations(id) on delete set null,
  website_domain           text,
  industry                 text,
  company_size             text,
  country                  text default 'GB',
  plan                     plan_tier not null default 'free',
  vendor_limit             integer not null default 3,
  branding                 jsonb not null default '{}'::jsonb,
  settings                 jsonb not null default '{}'::jsonb,
  data_retention_days      integer not null default 730,
  benchmark_opt_in         boolean not null default true,
  is_demo                  boolean not null default false,
  created_at               timestamptz not null default now(),
  updated_at               timestamptz not null default now(),
  deleted_at               timestamptz,
  constraint organizations_name_length check (char_length(name) between 1 and 200),
  constraint organizations_no_self_parent check (parent_organization_id is null or parent_organization_id <> id),
  constraint organizations_retention check (data_retention_days between 30 and 3650)
);

create index if not exists idx_organizations_parent on public.organizations(parent_organization_id)
  where parent_organization_id is not null;

-- ---------------------------------------------------------------------------
-- organization_members
-- ---------------------------------------------------------------------------
create table if not exists public.organization_members (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id         uuid not null references public.users(id) on delete cascade,
  role            org_role not null default 'viewer',
  status          member_status not null default 'active',
  invited_by      uuid references public.users(id) on delete set null,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  unique (organization_id, user_id)
);

create index if not exists idx_org_members_user on public.organization_members(user_id);
create index if not exists idx_org_members_org on public.organization_members(organization_id);

-- ---------------------------------------------------------------------------
-- invitations
-- ---------------------------------------------------------------------------
create table if not exists public.invitations (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  email           citext not null,
  role            org_role not null default 'viewer',
  token_hash      text not null unique,
  invited_by      uuid references public.users(id) on delete set null,
  expires_at      timestamptz not null,
  accepted_at     timestamptz,
  revoked_at      timestamptz,
  created_at      timestamptz not null default now()
);

create unique index if not exists uq_invitations_pending
  on public.invitations(organization_id, email)
  where accepted_at is null and revoked_at is null;

-- ---------------------------------------------------------------------------
-- subscriptions
-- ---------------------------------------------------------------------------
create table if not exists public.subscriptions (
  id                     uuid primary key default gen_random_uuid(),
  organization_id        uuid not null unique references public.organizations(id) on delete cascade,
  stripe_customer_id     text unique,
  stripe_subscription_id text unique,
  plan                   plan_tier not null default 'free',
  status                 subscription_status not null default 'active',
  current_period_start   timestamptz,
  current_period_end     timestamptz,
  cancel_at_period_end   boolean not null default false,
  canceled_at            timestamptz,
  report_pack_credits    integer not null default 0,
  created_at             timestamptz not null default now(),
  updated_at             timestamptz not null default now(),
  constraint subscriptions_credits_non_negative check (report_pack_credits >= 0)
);

create index if not exists idx_subscriptions_stripe_customer on public.subscriptions(stripe_customer_id);

-- ---------------------------------------------------------------------------
-- vendors
-- ---------------------------------------------------------------------------
create table if not exists public.vendors (
  id                 uuid primary key default gen_random_uuid(),
  organization_id    uuid not null references public.organizations(id) on delete cascade,
  name               text not null,
  domain             text not null,
  description        text,
  category           text,
  criticality        vendor_criticality not null default 'medium',
  owner_user_id      uuid references public.users(id) on delete set null,
  owner_label        text,
  status             vendor_status not null default 'active',
  current_score      integer,
  current_risk_level risk_level,
  previous_score     integer,
  current_confidence numeric(4,3),
  last_scanned_at    timestamptz,
  next_scan_at       timestamptz,
  scan_interval_hours integer not null default 24,
  is_demo            boolean not null default false,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),
  constraint vendors_name_length check (char_length(name) between 1 and 200),
  constraint vendors_domain_length check (char_length(domain) between 3 and 253),
  constraint vendors_score_range check (current_score is null or current_score between 0 and 100),
  constraint vendors_prev_score_range check (previous_score is null or previous_score between 0 and 100),
  constraint vendors_interval check (scan_interval_hours between 1 and 720)
);

-- One vendor per domain per organization.
create unique index if not exists uq_vendors_org_domain on public.vendors(organization_id, lower(domain));
create index if not exists idx_vendors_org_status on public.vendors(organization_id, status);
create index if not exists idx_vendors_org_score on public.vendors(organization_id, current_score desc nulls last);
create index if not exists idx_vendors_next_scan on public.vendors(next_scan_at)
  where status = 'active';

-- ---------------------------------------------------------------------------
-- vendor_domains (additional domains monitored for a vendor)
-- ---------------------------------------------------------------------------
create table if not exists public.vendor_domains (
  id              uuid primary key default gen_random_uuid(),
  vendor_id       uuid not null references public.vendors(id) on delete cascade,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  domain          text not null,
  is_primary      boolean not null default false,
  created_at      timestamptz not null default now()
);

create unique index if not exists uq_vendor_domains on public.vendor_domains(vendor_id, lower(domain));
create index if not exists idx_vendor_domains_org on public.vendor_domains(organization_id);

-- ---------------------------------------------------------------------------
-- scans
-- ---------------------------------------------------------------------------
create table if not exists public.scans (
  id               uuid primary key default gen_random_uuid(),
  organization_id  uuid not null references public.organizations(id) on delete cascade,
  vendor_id        uuid not null references public.vendors(id) on delete cascade,
  trigger          scan_trigger not null default 'manual',
  status           scan_status not null default 'queued',
  score            integer,
  risk_level       risk_level,
  confidence       numeric(4,3),
  coverage         numeric(4,3),
  score_breakdown  jsonb,
  verdict          jsonb,
  checks_total     integer not null default 0,
  checks_succeeded integer not null default 0,
  error_code       text,
  error_message    text,
  task_id          text,
  idempotency_key  text,
  requested_by     uuid references public.users(id) on delete set null,
  queued_at        timestamptz not null default now(),
  started_at       timestamptz,
  completed_at     timestamptz,
  created_at       timestamptz not null default now(),
  constraint scans_score_range check (score is null or score between 0 and 100)
);

create index if not exists idx_scans_vendor_created on public.scans(vendor_id, created_at desc);
create index if not exists idx_scans_org_created on public.scans(organization_id, created_at desc);
create index if not exists idx_scans_status on public.scans(status) where status in ('queued', 'running');
create unique index if not exists uq_scans_idempotency on public.scans(vendor_id, idempotency_key)
  where idempotency_key is not null;

-- ---------------------------------------------------------------------------
-- scan_results (one normalized row per check performed)
-- ---------------------------------------------------------------------------
create table if not exists public.scan_results (
  id              uuid primary key default gen_random_uuid(),
  scan_id         uuid not null references public.scans(id) on delete cascade,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  vendor_id       uuid not null references public.vendors(id) on delete cascade,
  check_type      text not null,
  status          check_status not null,
  severity        severity_level not null default 'info',
  summary         text not null,
  details         jsonb not null default '{}'::jsonb,
  evidence        jsonb not null default '[]'::jsonb,
  source          text not null,
  confidence      numeric(4,3) not null default 1.0,
  provider_status text,
  duration_ms     integer,
  checked_at      timestamptz not null default now(),
  created_at      timestamptz not null default now(),
  constraint scan_results_confidence check (confidence >= 0 and confidence <= 1)
);

create index if not exists idx_scan_results_scan on public.scan_results(scan_id);
create index if not exists idx_scan_results_vendor_check on public.scan_results(vendor_id, check_type, checked_at desc);

-- ---------------------------------------------------------------------------
-- findings (deduplicated, tracked remediation items)
-- ---------------------------------------------------------------------------
create table if not exists public.findings (
  id               uuid primary key default gen_random_uuid(),
  organization_id  uuid not null references public.organizations(id) on delete cascade,
  vendor_id        uuid not null references public.vendors(id) on delete cascade,
  first_scan_id    uuid references public.scans(id) on delete set null,
  last_scan_id     uuid references public.scans(id) on delete set null,
  fingerprint      text not null,
  check_type       text not null,
  severity         severity_level not null,
  title            text not null,
  description      text not null,
  recommendation   text not null,
  evidence         jsonb not null default '[]'::jsonb,
  source           text not null,
  confidence       numeric(4,3) not null default 1.0,
  status           finding_status not null default 'open',
  assigned_to      uuid references public.users(id) on delete set null,
  first_seen_at    timestamptz not null default now(),
  last_seen_at     timestamptz not null default now(),
  resolved_at      timestamptz,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);

create unique index if not exists uq_findings_vendor_fingerprint on public.findings(vendor_id, fingerprint);
create index if not exists idx_findings_org_status on public.findings(organization_id, status);
create index if not exists idx_findings_vendor_status on public.findings(vendor_id, status, severity);

-- ---------------------------------------------------------------------------
-- finding_status_history
-- ---------------------------------------------------------------------------
create table if not exists public.finding_status_history (
  id              uuid primary key default gen_random_uuid(),
  finding_id      uuid not null references public.findings(id) on delete cascade,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  from_status     finding_status,
  to_status       finding_status not null,
  note            text,
  actor_user_id   uuid references public.users(id) on delete set null,
  created_at      timestamptz not null default now()
);

create index if not exists idx_finding_history_finding on public.finding_status_history(finding_id, created_at desc);

-- ---------------------------------------------------------------------------
-- alerts
-- ---------------------------------------------------------------------------
create table if not exists public.alerts (
  id                  uuid primary key default gen_random_uuid(),
  organization_id     uuid not null references public.organizations(id) on delete cascade,
  vendor_id           uuid references public.vendors(id) on delete cascade,
  scan_id             uuid references public.scans(id) on delete set null,
  kind                alert_kind not null,
  severity            severity_level not null default 'medium',
  title               text not null,
  message             text not null,
  old_score           integer,
  new_score           integer,
  score_delta         integer,
  reason              text,
  notification_status notification_status not null default 'pending',
  notified_at         timestamptz,
  acknowledged_at     timestamptz,
  acknowledged_by     uuid references public.users(id) on delete set null,
  dedupe_key          text,
  created_at          timestamptz not null default now()
);

create index if not exists idx_alerts_org_created on public.alerts(organization_id, created_at desc);
create unique index if not exists uq_alerts_dedupe on public.alerts(organization_id, dedupe_key)
  where dedupe_key is not null;

-- ---------------------------------------------------------------------------
-- api_keys (only the hash is stored; the secret is shown once)
-- ---------------------------------------------------------------------------
create table if not exists public.api_keys (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name            text not null,
  key_prefix      text not null,
  key_hash        text not null unique,
  scopes          text[] not null default array['vendors:read','vendors:write','scans:write','reports:read'],
  created_by      uuid references public.users(id) on delete set null,
  last_used_at    timestamptz,
  expires_at      timestamptz,
  revoked_at      timestamptz,
  created_at      timestamptz not null default now(),
  constraint api_keys_name_length check (char_length(name) between 1 and 100)
);

create index if not exists idx_api_keys_org on public.api_keys(organization_id);
create index if not exists idx_api_keys_prefix on public.api_keys(key_prefix);

-- ---------------------------------------------------------------------------
-- integration_connections
-- ---------------------------------------------------------------------------
create table if not exists public.integration_connections (
  id               uuid primary key default gen_random_uuid(),
  organization_id  uuid not null references public.organizations(id) on delete cascade,
  provider         integration_provider not null,
  external_id      text,
  display_name     text,
  status           text not null default 'active',
  config           jsonb not null default '{}'::jsonb,
  -- Encrypted at rest with SECRETS_ENCRYPTION_KEY. Never returned by the API.
  encrypted_secret text,
  created_by       uuid references public.users(id) on delete set null,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);

create unique index if not exists uq_integration_conn
  on public.integration_connections(organization_id, provider, coalesce(external_id, ''));

-- ---------------------------------------------------------------------------
-- slack_workspaces
-- ---------------------------------------------------------------------------
create table if not exists public.slack_workspaces (
  id                  uuid primary key default gen_random_uuid(),
  organization_id     uuid not null references public.organizations(id) on delete cascade,
  team_id             text not null unique,
  team_name           text,
  bot_user_id         text,
  encrypted_bot_token text not null,
  scopes              text,
  default_channel_id  text,
  installed_by        uuid references public.users(id) on delete set null,
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now()
);

create index if not exists idx_slack_workspaces_org on public.slack_workspaces(organization_id);

-- ---------------------------------------------------------------------------
-- benchmark_data (aggregate only — never per-customer rows)
-- ---------------------------------------------------------------------------
create table if not exists public.benchmark_data (
  id            uuid primary key default gen_random_uuid(),
  cohort_key    text not null,
  industry      text,
  company_size  text,
  metric        text not null,
  sample_size   integer not null,
  p25           numeric(6,2),
  p50           numeric(6,2),
  p75           numeric(6,2),
  average       numeric(6,2),
  computed_at   timestamptz not null default now(),
  constraint benchmark_sample_positive check (sample_size >= 0)
);

create unique index if not exists uq_benchmark_cohort_metric on public.benchmark_data(cohort_key, metric);

-- ---------------------------------------------------------------------------
-- reports & report_exports
-- ---------------------------------------------------------------------------
create table if not exists public.reports (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  kind            report_kind not null default 'vendor_risk_register',
  title           text not null,
  status          report_status not null default 'queued',
  scope           jsonb not null default '{}'::jsonb,
  summary         jsonb,
  generated_by    uuid references public.users(id) on delete set null,
  idempotency_key text,
  error_message   text,
  created_at      timestamptz not null default now(),
  completed_at    timestamptz
);

create index if not exists idx_reports_org_created on public.reports(organization_id, created_at desc);
create unique index if not exists uq_reports_idempotency on public.reports(organization_id, idempotency_key)
  where idempotency_key is not null;

create table if not exists public.report_exports (
  id              uuid primary key default gen_random_uuid(),
  report_id       uuid not null references public.reports(id) on delete cascade,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  format          text not null default 'pdf',
  file_path       text not null,
  file_size       integer,
  checksum        text,
  download_count  integer not null default 0,
  expires_at      timestamptz,
  created_at      timestamptz not null default now()
);

create index if not exists idx_report_exports_report on public.report_exports(report_id);

-- ---------------------------------------------------------------------------
-- audit_logs
-- ---------------------------------------------------------------------------
create table if not exists public.audit_logs (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid references public.organizations(id) on delete cascade,
  actor_type      text not null default 'user',
  actor_user_id   uuid references public.users(id) on delete set null,
  actor_api_key_id uuid references public.api_keys(id) on delete set null,
  action          text not null,
  resource_type   text,
  resource_id     uuid,
  metadata        jsonb not null default '{}'::jsonb,
  ip_address      inet,
  user_agent      text,
  request_id      text,
  created_at      timestamptz not null default now()
);

create index if not exists idx_audit_org_created on public.audit_logs(organization_id, created_at desc);
create index if not exists idx_audit_action on public.audit_logs(action, created_at desc);

-- ---------------------------------------------------------------------------
-- webhook_events (idempotency ledger for Stripe / Slack callbacks)
-- ---------------------------------------------------------------------------
create table if not exists public.webhook_events (
  id           uuid primary key default gen_random_uuid(),
  provider     text not null,
  event_id     text not null,
  event_type   text,
  status       text not null default 'received',
  error_message text,
  processed_at timestamptz,
  created_at   timestamptz not null default now(),
  unique (provider, event_id)
);

-- ---------------------------------------------------------------------------
-- public_scans (anonymous free-tier scans; no tenant, minimal retention)
-- ---------------------------------------------------------------------------
create table if not exists public.public_scans (
  id            uuid primary key default gen_random_uuid(),
  domain        text not null,
  -- Salted hash only; we never persist a raw requester IP address.
  requester_hash text,
  score         integer,
  risk_level    risk_level,
  result        jsonb not null default '{}'::jsonb,
  created_at    timestamptz not null default now()
);

create index if not exists idx_public_scans_domain on public.public_scans(lower(domain), created_at desc);
create index if not exists idx_public_scans_created on public.public_scans(created_at desc);

-- ---------------------------------------------------------------------------
-- updated_at triggers
-- ---------------------------------------------------------------------------
do $$
declare t text;
begin
  foreach t in array array[
    'users','organizations','organization_members','subscriptions','vendors',
    'findings','integration_connections','slack_workspaces'
  ] loop
    execute format(
      'drop trigger if exists trg_%1$s_updated_at on public.%1$s;
       create trigger trg_%1$s_updated_at before update on public.%1$s
       for each row execute function public.set_updated_at();', t);
  end loop;
end $$;

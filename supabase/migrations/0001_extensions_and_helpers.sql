-- =============================================================================
-- Zentra 0001 — extensions, enums and tenancy helper functions
-- =============================================================================
-- These migrations run against hosted Supabase (`supabase db push`) and against
-- a plain PostgreSQL instance (`make migrate`). Supabase provides `auth.uid()`;
-- when it is absent we create an equivalent shim that reads the same
-- `request.jwt.claims` GUC, so Row Level Security behaves identically in local
-- development and CI.
-- =============================================================================

create extension if not exists "pgcrypto";
create extension if not exists "citext";

create schema if not exists auth;

-- Supabase-compatible auth.uid() shim (no-op when Supabase already defines it).
create or replace function auth.uid()
returns uuid
language sql
stable
as $$
  select nullif(
    coalesce(
      current_setting('request.jwt.claim.sub', true),
      (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
    ),
    ''
  )::uuid;
$$;

-- ---------------------------------------------------------------------------
-- Enumerations
-- ---------------------------------------------------------------------------
do $$ begin
  create type org_role as enum ('owner', 'admin', 'analyst', 'viewer');
exception when duplicate_object then null; end $$;

do $$ begin
  create type org_type as enum ('customer', 'mssp');
exception when duplicate_object then null; end $$;

do $$ begin
  create type member_status as enum ('active', 'invited', 'suspended');
exception when duplicate_object then null; end $$;

do $$ begin
  create type plan_tier as enum ('free', 'starter', 'growth', 'scale');
exception when duplicate_object then null; end $$;

do $$ begin
  create type subscription_status as enum (
    'trialing', 'active', 'past_due', 'canceled', 'incomplete', 'incomplete_expired', 'unpaid'
  );
exception when duplicate_object then null; end $$;

do $$ begin
  create type vendor_criticality as enum ('low', 'medium', 'high', 'critical');
exception when duplicate_object then null; end $$;

do $$ begin
  create type vendor_status as enum ('active', 'paused', 'archived');
exception when duplicate_object then null; end $$;

do $$ begin
  create type risk_level as enum ('low', 'medium', 'high', 'critical');
exception when duplicate_object then null; end $$;

do $$ begin
  create type scan_trigger as enum ('initial', 'manual', 'scheduled', 'public', 'api');
exception when duplicate_object then null; end $$;

do $$ begin
  create type scan_status as enum ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled');
exception when duplicate_object then null; end $$;

do $$ begin
  -- `unknown` and `error` are deliberately distinct from `fail`: an upstream
  -- provider outage must never be recorded as a security failure.
  create type check_status as enum ('pass', 'warn', 'fail', 'unknown', 'error');
exception when duplicate_object then null; end $$;

do $$ begin
  create type severity_level as enum ('info', 'low', 'medium', 'high', 'critical');
exception when duplicate_object then null; end $$;

do $$ begin
  create type finding_status as enum ('open', 'in_progress', 'resolved', 'accepted_risk');
exception when duplicate_object then null; end $$;

do $$ begin
  create type alert_kind as enum (
    'score_increase', 'score_decrease', 'new_critical_finding', 'scan_failed', 'certificate_expiring'
  );
exception when duplicate_object then null; end $$;

do $$ begin
  create type notification_status as enum ('pending', 'sent', 'failed', 'suppressed');
exception when duplicate_object then null; end $$;

do $$ begin
  create type report_kind as enum ('vendor_risk_register', 'single_vendor', 'executive_summary');
exception when duplicate_object then null; end $$;

do $$ begin
  create type report_status as enum ('queued', 'generating', 'completed', 'failed');
exception when duplicate_object then null; end $$;

do $$ begin
  create type integration_provider as enum ('slack', 'teams', 'webhook');
exception when duplicate_object then null; end $$;

-- ---------------------------------------------------------------------------
-- Shared trigger: keep updated_at honest
-- ---------------------------------------------------------------------------
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

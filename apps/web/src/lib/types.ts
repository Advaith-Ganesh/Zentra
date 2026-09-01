/**
 * API types.
 *
 * These mirror the Pydantic response models in `apps/api/zentra/api/schemas.py`.
 * Scoring is never recomputed here: the frontend renders exactly what the
 * backend returns.
 */

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type Criticality = 'low' | 'medium' | 'high' | 'critical';
export type VendorStatus = 'active' | 'paused' | 'archived';
export type ScanStatus =
  | 'queued'
  | 'running'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'cancelled';
export type CheckStatus = 'pass' | 'warn' | 'fail' | 'unknown' | 'error';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type FindingStatus = 'open' | 'in_progress' | 'resolved' | 'accepted_risk';
export type PlanId = 'free' | 'starter' | 'growth' | 'scale';

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    request_id?: string;
  };
}

export interface User {
  id: string;
  email: string;
  full_name: string | null;
  is_platform_admin: boolean;
  email_verified: boolean;
  created_at: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  org_type: string;
  industry: string | null;
  company_size: string | null;
  country: string | null;
  plan: PlanId;
  branding: Record<string, unknown>;
  created_at: string;
}

export interface Entitlements {
  plan: PlanId;
  plan_name: string;
  status: string;
  vendor_limit: number;
  vendors_used: number;
  vendors_remaining: number;
  unlimited_vendors: boolean;
  member_limit: number;
  scan_interval_hours: number;
  report_pack_credits: number;
  features: string[];
}

export interface Me {
  user: User;
  organization: Organization;
  role: 'owner' | 'admin' | 'analyst' | 'viewer';
  entitlements: Entitlements;
  feature_flags: Record<string, boolean>;
  organizations: { id: string; name: string; slug: string; role: string }[];
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string | null;
  token_type: 'bearer';
  expires_in: number;
  email_verification_required: boolean;
  user: User;
  organization: Organization | null;
}

export interface Vendor {
  id: string;
  organization_id: string;
  name: string;
  domain: string;
  description: string | null;
  category: string | null;
  criticality: Criticality;
  owner_label: string | null;
  status: VendorStatus;
  current_score: number | null;
  current_risk_level: RiskLevel | null;
  previous_score: number | null;
  current_confidence: number | null;
  score_trend: number | null;
  last_scanned_at: string | null;
  next_scan_at: string | null;
  scan_interval_hours: number;
  is_demo: boolean;
  created_at: string;
  updated_at: string;
}

export interface VendorList {
  items: Vendor[];
  total: number;
  limit: number;
  offset: number;
}

export interface ScoreCategory {
  category: string;
  display_name: string;
  description: string;
  points: number;
  max_points: number;
  assessed: boolean;
  confidence: number;
  status: 'clear' | 'minor' | 'attention' | 'severe' | 'unavailable' | 'not_assessed';
  contributing_checks: {
    check_type: string;
    status: CheckStatus;
    severity: Severity;
    summary: string;
    confidence: number;
    points: number;
    note: string | null;
    source: string;
  }[];
}

export interface ScoreBreakdown {
  score: number | null;
  raw_score: number;
  base_score: number;
  applied_floor: {
    severity: string;
    finding_count: number;
    floor: number;
    explanation: string;
  } | null;
  risk_level: RiskLevel | null;
  is_scorable: boolean;
  confidence: number;
  coverage: number;
  inconclusive: boolean;
  uncertainty_points: number;
  scoring_version: string;
  checks: { total: number; conclusive: number; provider_unavailable: number };
  categories: ScoreCategory[];
  top_findings: {
    check_type: string;
    title: string;
    summary: string;
    severity: Severity;
    status: CheckStatus;
    recommendation: string | null;
    source: string;
    confidence: number;
  }[];
}

export interface Verdict {
  headline: string;
  explanation: string;
  biggest_risk: string | null;
  why_it_matters: string | null;
  recommended_action: string;
  coverage_note: string | null;
  disclaimers: string[];
}

export interface VendorScore {
  vendor_id: string;
  score: number | null;
  risk_level: RiskLevel | null;
  confidence: number | null;
  coverage: number | null;
  previous_score: number | null;
  trend: number | null;
  last_scanned_at: string | null;
  breakdown: ScoreBreakdown | null;
  verdict: Verdict | null;
  history: { scan_id: string; date: string | null; score: number; risk_level: RiskLevel }[];
}

export interface Scan {
  id: string;
  vendor_id: string;
  trigger: string;
  status: ScanStatus;
  score: number | null;
  risk_level: RiskLevel | null;
  confidence: number | null;
  coverage: number | null;
  checks_total: number;
  checks_succeeded: number;
  error_code: string | null;
  error_message: string | null;
  queued_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface ScanResult {
  id: string;
  check_type: string;
  status: CheckStatus;
  severity: Severity;
  summary: string;
  details: Record<string, unknown>;
  evidence: { label: string; value: string; source: string; observed_at: string }[];
  source: string;
  confidence: number;
  provider_status: string | null;
  checked_at: string;
}

export interface ScanDetail extends Scan {
  score_breakdown: ScoreBreakdown | null;
  verdict: Verdict | null;
  results: ScanResult[];
}

export interface Finding {
  id: string;
  vendor_id: string;
  check_type: string;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  evidence: { label: string; value: string; source: string }[];
  source: string;
  confidence: number;
  status: FindingStatus;
  assigned_to: string | null;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
}

export interface FindingHistoryEntry {
  id: string;
  from_status: FindingStatus | null;
  to_status: FindingStatus;
  note: string | null;
  actor_user_id: string | null;
  created_at: string;
}

export interface Alert {
  id: string;
  vendor_id: string | null;
  scan_id: string | null;
  kind: string;
  severity: Severity;
  title: string;
  message: string;
  old_score: number | null;
  new_score: number | null;
  score_delta: number | null;
  notification_status: string;
  acknowledged_at: string | null;
  created_at: string;
}

export interface DashboardSummary {
  total_vendors: number;
  critical_vendors: number;
  high_risk_vendors: number;
  medium_risk_vendors: number;
  low_risk_vendors: number;
  unscored_vendors: number;
  average_score: number | null;
  vendors_needing_attention: number;
  open_findings: number;
  critical_open_findings: number;
  scans_in_progress: number;
}

export interface Dashboard {
  summary: DashboardSummary;
  vendors_needing_attention: Vendor[];
  recent_alerts: Alert[];
  recent_scans: Scan[];
  entitlements: Entitlements;
}

export interface Report {
  id: string;
  kind: string;
  title: string;
  status: 'queued' | 'generating' | 'completed' | 'failed';
  summary: Record<string, unknown> | null;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
  download_url: string | null;
  file_size: number | null;
}

export interface PlanOption {
  plan: string;
  name: string;
  price_pence: number;
  price_display: string;
  currency: string;
  vendor_limit?: number;
  unlimited_vendors?: boolean;
  description: string;
  features: string[];
  purchasable: boolean;
}

export interface Billing {
  plan: PlanId;
  status: string;
  entitlements: Entitlements;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  stripe_configured: boolean;
  available_plans: PlanOption[];
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface Member {
  id: string;
  user_id: string;
  email: string;
  full_name: string | null;
  role: string;
  status: string;
  created_at: string;
}

export interface PublicScanResult {
  domain: string;
  score: number | null;
  risk_level: RiskLevel | null;
  confidence: number;
  coverage: number;
  headline: string;
  explanation: string;
  recommended_action: string;
  top_findings: {
    title: string;
    summary: string;
    severity: Severity;
    recommendation: string | null;
  }[];
  categories: {
    display_name: string;
    assessed: boolean;
    status: string;
    points: number;
    max_points: number;
  }[];
  disclaimer: string;
  scanned_at: string;
}

export interface Benchmark {
  available: boolean;
  cohort_label: string | null;
  sample_size: number;
  your_average_score: number | null;
  cohort_median: number | null;
  cohort_p25: number | null;
  cohort_p75: number | null;
  message: string;
}

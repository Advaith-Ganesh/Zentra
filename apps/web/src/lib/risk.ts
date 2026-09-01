/**
 * Presentation helpers for risk levels and severities.
 *
 * Colour is never the only signal: each mapping also supplies a text label and
 * a shape/icon hint, so the UI stays readable for colour-blind users and in
 * high-contrast modes.
 */

import type { RiskLevel, Severity, CheckStatus, FindingStatus } from './types';

export interface RiskPresentation {
  label: string;
  /** Short plain-English meaning, used in tooltips and screen-reader text. */
  meaning: string;
  className: string;
  dotClassName: string;
  barClassName: string;
  /** Non-colour glyph so the level is distinguishable without colour. */
  glyph: string;
}

export const RISK_PRESENTATION: Record<RiskLevel | 'unknown', RiskPresentation> = {
  low: {
    label: 'Low',
    meaning: 'No signals associated with elevated risk were detected.',
    className: 'text-risk-low border-risk-low/45 bg-risk-low-dim',
    dotClassName: 'bg-risk-low',
    barClassName: 'bg-risk-low',
    glyph: '●',
  },
  medium: {
    label: 'Medium',
    meaning: 'Some issues worth raising with the vendor at your next review.',
    className: 'text-risk-medium border-risk-medium/45 bg-risk-medium-dim',
    dotClassName: 'bg-risk-medium',
    barClassName: 'bg-risk-medium',
    glyph: '◆',
  },
  high: {
    label: 'High',
    meaning: 'Significant issues. Ask the vendor for a remediation date.',
    className: 'text-risk-high border-risk-high/45 bg-risk-high-dim',
    dotClassName: 'bg-risk-high',
    barClassName: 'bg-risk-high',
    glyph: '▲',
  },
  critical: {
    label: 'Critical',
    meaning: 'Urgent. Raise with the vendor now.',
    className: 'text-risk-critical border-risk-critical/50 bg-risk-critical-dim',
    dotClassName: 'bg-risk-critical',
    barClassName: 'bg-risk-critical',
    glyph: '■',
  },
  unknown: {
    label: 'Not assessed',
    meaning:
      'Too few checks completed to publish a risk level. This is not an indication of low risk.',
    className: 'text-risk-unknown border-risk-unknown/40 bg-risk-unknown-dim',
    dotClassName: 'bg-risk-unknown',
    barClassName: 'bg-risk-unknown',
    glyph: '—',
  },
};

export function riskPresentation(level: RiskLevel | null | undefined): RiskPresentation {
  return RISK_PRESENTATION[level ?? 'unknown'];
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const SEVERITY_PRESENTATION: Record<Severity, { label: string; className: string; glyph: string }> = {
  critical: { label: 'Critical', className: 'text-risk-critical border-risk-critical/50', glyph: '■' },
  high: { label: 'High', className: 'text-risk-high border-risk-high/45', glyph: '▲' },
  medium: { label: 'Medium', className: 'text-risk-medium border-risk-medium/45', glyph: '◆' },
  low: { label: 'Low', className: 'text-silver-400 border-silver-500/40', glyph: '●' },
  info: { label: 'Info', className: 'text-silver-500 border-silver-600/40', glyph: '·' },
};

export const CHECK_STATUS_PRESENTATION: Record<
  CheckStatus,
  { label: string; meaning: string; className: string; glyph: string }
> = {
  pass: {
    label: 'Pass',
    meaning: 'Checked, and no problem found.',
    className: 'text-risk-low border-risk-low/45 bg-risk-low-dim',
    glyph: '✓',
  },
  warn: {
    label: 'Attention',
    meaning: 'Checked, and something is worth improving.',
    className: 'text-risk-medium border-risk-medium/45 bg-risk-medium-dim',
    glyph: '!',
  },
  fail: {
    label: 'Problem',
    meaning: 'Checked, and a real problem was found.',
    className: 'text-risk-critical border-risk-critical/50 bg-risk-critical-dim',
    glyph: '✕',
  },
  unknown: {
    label: 'Not assessed',
    meaning:
      'This could not be determined from public sources. It is not counted as a problem.',
    className: 'text-silver-400 border-silver-600/40 bg-ink-800',
    glyph: '?',
  },
  error: {
    label: 'Unavailable',
    meaning:
      'The data source could not be reached. This is not an indication that the vendor is safe.',
    className: 'text-silver-400 border-silver-600/40 bg-ink-800',
    glyph: '⚠',
  },
};

export const FINDING_STATUS_PRESENTATION: Record<
  FindingStatus,
  { label: string; className: string }
> = {
  open: { label: 'Open', className: 'text-risk-high border-risk-high/45' },
  in_progress: { label: 'In progress', className: 'text-risk-medium border-risk-medium/45' },
  resolved: { label: 'Resolved', className: 'text-risk-low border-risk-low/45' },
  accepted_risk: { label: 'Accepted risk', className: 'text-silver-400 border-silver-500/40' },
};

/** Human label for a scanner check type. */
export const CHECK_TYPE_LABELS: Record<string, string> = {
  tls_certificate: 'TLS certificate',
  tls_configuration: 'TLS configuration',
  dns_spf: 'Email sender protection (SPF)',
  dns_dmarc: 'Email spoofing policy (DMARC)',
  dns_dkim: 'Email signing (DKIM)',
  dns_caa: 'Certificate authority restriction (CAA)',
  breach_history: 'Breach history',
  internet_exposure: 'Internet exposure',
  technology_stack: 'Technology in use',
  cve_exposure: 'Known vulnerabilities',
  http_security_headers: 'Browser security headers',
};

export function checkTypeLabel(checkType: string): string {
  return CHECK_TYPE_LABELS[checkType] ?? checkType.replace(/_/g, ' ');
}

/** Plain-English explanation of what a check looks at, for tooltips. */
export const CHECK_TYPE_EXPLANATIONS: Record<string, string> = {
  tls_certificate:
    'Whether the certificate that proves the vendor’s identity is valid and in date.',
  tls_configuration:
    'Whether the vendor uses modern encryption settings for traffic to their service.',
  dns_spf:
    'Whether the vendor lists which servers may send email as them, which limits impersonation.',
  dns_dmarc:
    'Whether the vendor tells mail providers to reject email that fails authentication.',
  dns_dkim:
    'Whether a DKIM signing key could be found. Keys live under a private selector name, so not finding one proves nothing.',
  dns_caa:
    'Whether the vendor restricts which certificate authorities may issue certificates for their domain.',
  breach_history:
    'Whether the vendor’s domain appears in publicly catalogued data breaches.',
  internet_exposure:
    'Which services are already visible on the public internet, according to third-party scan data.',
  technology_stack:
    'Which software the vendor’s servers publicly declare they are running.',
  cve_exposure:
    'Whether published vulnerabilities match software versions the vendor discloses.',
  http_security_headers:
    'Whether the vendor’s website sets the browser headers that limit common web attacks.',
};

export function scoreToPercent(points: number, maxPoints: number): number {
  if (!maxPoints) return 0;
  return Math.max(0, Math.min(100, Math.round((points / maxPoints) * 100)));
}

/** Trend direction. A rising score is worse. */
export function trendPresentation(trend: number | null | undefined): {
  label: string;
  className: string;
  glyph: string;
} {
  if (trend === null || trend === undefined || trend === 0) {
    return { label: 'No change', className: 'text-silver-500', glyph: '→' };
  }
  if (trend > 0) {
    return {
      label: `+${trend} (worse)`,
      className: 'text-risk-high',
      glyph: '↑',
    };
  }
  return { label: `${trend} (better)`, className: 'text-risk-low', glyph: '↓' };
}

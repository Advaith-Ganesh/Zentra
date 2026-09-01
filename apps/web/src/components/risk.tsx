/**
 * Risk presentation components.
 *
 * These render exactly what the backend returned. No scoring logic lives here.
 */

'use client';

import * as React from 'react';
import { Badge, InfoTooltip } from '@/components/ui';
import { cn } from '@/lib/utils';
import {
  CHECK_STATUS_PRESENTATION,
  CHECK_TYPE_EXPLANATIONS,
  FINDING_STATUS_PRESENTATION,
  SEVERITY_PRESENTATION,
  checkTypeLabel,
  riskPresentation,
  scoreToPercent,
  trendPresentation,
} from '@/lib/risk';
import type {
  CheckStatus,
  FindingStatus,
  RiskLevel,
  ScoreCategory,
  Severity,
} from '@/lib/types';

// ------------------------------------------------------------------ RiskBadge
export function RiskBadge({
  level,
  className,
  showMeaning = false,
}: {
  level: RiskLevel | null | undefined;
  className?: string;
  showMeaning?: boolean;
}) {
  const presentation = riskPresentation(level);
  return (
    <Badge
      className={cn(presentation.className, className)}
      glyph={presentation.glyph}
      title={showMeaning ? presentation.meaning : undefined}
    >
      <span className="sr-only">Risk level: </span>
      {presentation.label}
    </Badge>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const presentation = SEVERITY_PRESENTATION[severity];
  return (
    <Badge className={presentation.className} glyph={presentation.glyph}>
      <span className="sr-only">Severity: </span>
      {presentation.label}
    </Badge>
  );
}

export function CheckStatusBadge({ status }: { status: CheckStatus }) {
  const presentation = CHECK_STATUS_PRESENTATION[status];
  return (
    <Badge className={presentation.className} glyph={presentation.glyph} title={presentation.meaning}>
      <span className="sr-only">Check result: </span>
      {presentation.label}
    </Badge>
  );
}

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  const presentation = FINDING_STATUS_PRESENTATION[status];
  return <Badge className={presentation.className}>{presentation.label}</Badge>;
}

// -------------------------------------------------------------- ScoreIndicator
export function ScoreIndicator({
  score,
  level,
  size = 'md',
  trend,
}: {
  score: number | null | undefined;
  level: RiskLevel | null | undefined;
  size?: 'sm' | 'md' | 'lg';
  trend?: number | null;
}) {
  const sizes = {
    sm: { number: 'text-xl', suffix: 'text-2xs' },
    md: { number: 'text-4xl', suffix: 'text-xs' },
    lg: { number: 'text-6xl', suffix: 'text-sm' },
  } as const;
  const trendInfo = trendPresentation(trend);

  return (
    <div className="flex items-baseline gap-3">
      <div className="flex items-baseline gap-1">
        <span
          className={cn(
            'font-semibold tabular-nums leading-none tracking-tight text-silver-50',
            sizes[size].number,
          )}
        >
          {score ?? '—'}
        </span>
        <span className={cn('text-silver-500', sizes[size].suffix)}>/ 100</span>
      </div>
      <RiskBadge level={level} showMeaning />
      {trend !== undefined && trend !== null && (
        <span
          className={cn('flex items-center gap-1 text-xs tabular-nums', trendInfo.className)}
          title="A higher score means more observed risk."
        >
          <span aria-hidden="true">{trendInfo.glyph}</span>
          {trendInfo.label}
        </span>
      )}
    </div>
  );
}

/** A compact numeric score for table rows. */
export function ScoreCell({
  score,
  level,
}: {
  score: number | null | undefined;
  level: RiskLevel | null | undefined;
}) {
  const presentation = riskPresentation(level);
  return (
    <span className="inline-flex items-center gap-2">
      <span
        aria-hidden="true"
        className={cn('inline-block h-2 w-2 shrink-0 rounded-full', presentation.dotClassName)}
      />
      <span className="font-medium tabular-nums text-silver-100">{score ?? '—'}</span>
    </span>
  );
}

// ------------------------------------------------------------- ScoreBreakdown
export function ScoreBreakdown({ categories }: { categories: ScoreCategory[] }) {
  return (
    <div className="space-y-3">
      <p className="text-xs text-silver-500">
        Points are risk contributed, so a lower number is better. Categories marked
        “not assessed” contributed no points at all.
      </p>
      <ul className="space-y-2.5">
        {categories.map((category) => {
          const percent = scoreToPercent(category.points, category.max_points);
          const barTone =
            !category.assessed
              ? 'bg-silver-600'
              : category.status === 'severe'
                ? 'bg-risk-critical'
                : category.status === 'attention'
                  ? 'bg-risk-high'
                  : category.status === 'minor'
                    ? 'bg-risk-medium'
                    : 'bg-risk-low';
          return (
            <li key={category.category}>
              <div className="flex items-baseline justify-between gap-3">
                <span className="flex items-center text-sm text-silver-200">
                  {category.display_name}
                  {!category.assessed && (
                    <span className="ml-2 text-2xs uppercase tracking-governance text-silver-500">
                      Not assessed
                    </span>
                  )}
                  <InfoTooltip label={category.description} />
                </span>
                <span className="shrink-0 font-mono text-xs tabular-nums text-silver-300">
                  {category.points} / {category.max_points}
                </span>
              </div>
              <div
                className="mt-1.5 h-1.5 w-full overflow-hidden rounded-sm bg-ink-800"
                role="meter"
                aria-valuenow={category.points}
                aria-valuemin={0}
                aria-valuemax={category.max_points}
                aria-label={`${category.display_name}: ${category.points} of ${category.max_points} risk points`}
              >
                <div
                  className={cn('h-full transition-all', barTone)}
                  style={{ width: `${category.assessed ? percent : 100}%`, opacity: category.assessed ? 1 : 0.25 }}
                />
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

// ------------------------------------------------------------------ CheckRow
export function CheckCard({
  checkType,
  status,
  severity,
  summary,
  source,
  checkedAt,
  confidence,
  evidence,
  recommendation,
}: {
  checkType: string;
  status: CheckStatus;
  severity: Severity;
  summary: string;
  source: string;
  checkedAt: string;
  confidence: number;
  evidence?: { label: string; value: string; source: string }[];
  recommendation?: string | null;
}) {
  const [expanded, setExpanded] = React.useState(false);
  const explanation = CHECK_TYPE_EXPLANATIONS[checkType];

  return (
    <div className="border-b border-ink-800 last:border-b-0">
      <div className="flex flex-col gap-3 px-5 py-4 sm:flex-row sm:items-start sm:gap-5">
        <div className="flex shrink-0 items-center gap-3 sm:w-56">
          <CheckStatusBadge status={status} />
          <span className="flex items-center text-sm font-medium text-silver-100">
            {checkTypeLabel(checkType)}
            {explanation && <InfoTooltip label={explanation} />}
          </span>
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm text-silver-300">{summary}</p>
          {recommendation && (
            <p className="mt-2 text-sm text-silver-200">
              <span className="text-silver-500">What to do: </span>
              {recommendation}
            </p>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-2xs text-silver-500">
            <span>Source: {source}</span>
            <span>Checked: {new Date(checkedAt).toLocaleString('en-GB')}</span>
            <span>Confidence: {Math.round(confidence * 100)}%</span>
            {severity !== 'info' && <SeverityBadge severity={severity} />}
          </div>
          {evidence && evidence.length > 0 && (
            <div className="mt-2">
              <button
                type="button"
                onClick={() => setExpanded((v) => !v)}
                aria-expanded={expanded}
                className="text-2xs uppercase tracking-governance text-silver-400 underline-offset-4 hover:text-silver-200 hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-silver-300"
              >
                {expanded ? 'Hide evidence' : `Show evidence (${evidence.length})`}
              </button>
              {expanded && (
                <dl className="mt-2 space-y-1.5 border-l border-ink-700 pl-3">
                  {evidence.map((item, index) => (
                    <div key={`${item.label}-${index}`} className="text-xs">
                      <dt className="text-silver-500">{item.label}</dt>
                      <dd className="break-all font-mono text-silver-300">{item.value}</dd>
                    </div>
                  ))}
                </dl>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ ScanStatus
export function ScanStatusIndicator({
  status,
  className,
}: {
  status: string;
  className?: string;
}) {
  const map: Record<string, { label: string; className: string; live: boolean }> = {
    queued: { label: 'Queued', className: 'text-silver-400 border-silver-600/40', live: true },
    running: { label: 'Scanning', className: 'text-silver-100 border-silver-400/50', live: true },
    completed: { label: 'Completed', className: 'text-risk-low border-risk-low/45', live: false },
    partial: {
      label: 'Partly completed',
      className: 'text-risk-medium border-risk-medium/45',
      live: false,
    },
    failed: { label: 'Failed', className: 'text-risk-critical border-risk-critical/45', live: false },
    cancelled: { label: 'Cancelled', className: 'text-silver-500 border-silver-600/40', live: false },
  };
  const presentation = map[status] ?? {
    label: status,
    className: 'text-silver-400 border-silver-600/40',
    live: false,
  };
  return (
    <Badge className={cn(presentation.className, className)}>
      {presentation.live && (
        <span
          aria-hidden="true"
          className="mr-0.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-current"
        />
      )}
      {presentation.label}
    </Badge>
  );
}

/**
 * Honest scan progress: named stages, no fabricated percentage.
 */
export function ScanProgress({ status }: { status: string }) {
  const stages = [
    'Checking TLS and certificates',
    'Checking email and DNS security',
    'Checking breach history',
    'Checking public exposure',
    'Calculating risk',
  ];
  const active = status === 'running';
  return (
    <div role="status" aria-live="polite" className="space-y-2">
      <p className="text-sm text-silver-200">
        {status === 'queued' ? 'Scan queued…' : 'Scanning vendor…'}
      </p>
      <ul className="space-y-1 text-xs text-silver-500">
        {stages.map((stage) => (
          <li key={stage} className="flex items-center gap-2">
            <span
              aria-hidden="true"
              className={cn(
                'inline-block h-1.5 w-1.5 rounded-full',
                active ? 'animate-pulse bg-silver-400' : 'bg-ink-600',
              )}
            />
            {stage}
          </li>
        ))}
      </ul>
      <p className="text-2xs text-silver-600">
        Scans run in the background. You can navigate away and come back.
      </p>
    </div>
  );
}

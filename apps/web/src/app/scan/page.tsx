'use client';

import * as React from 'react';
import Link from 'next/link';
import { z } from 'zod';
import { MarketingFooter, MarketingHeader } from '@/components/marketing';
import { Banner, Button, Card, CardBody, CardHeader, Field, Input } from '@/components/ui';
import { RiskBadge, ScoreIndicator, SeverityBadge } from '@/components/risk';
import { ApiError, api } from '@/lib/api';
import { scoreToPercent } from '@/lib/risk';
import type { PublicScanResult } from '@/lib/types';
import { cn } from '@/lib/utils';

/**
 * Client-side validation mirrors the server's rules so obvious mistakes are
 * caught before a request is made. The server remains the authority.
 */
const domainSchema = z
  .string()
  .trim()
  .min(3, 'Enter a domain such as example.com')
  .max(253, 'That domain is too long')
  .transform((value) =>
    value
      .replace(/^https?:\/\//i, '')
      .replace(/\/.*$/, '')
      .toLowerCase(),
  )
  .refine((value) => /^[a-z0-9.-]+$/.test(value), 'Enter a bare domain, such as example.com')
  .refine((value) => value.includes('.'), 'Enter a full domain, such as example.com')
  .refine(
    (value) => !/^(localhost|\d+\.\d+\.\d+\.\d+)$/.test(value),
    'Enter a public company domain, not a local or IP address',
  );

export default function PublicScanPage() {
  const [domain, setDomain] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
  const [scanning, setScanning] = React.useState(false);
  const [result, setResult] = React.useState<PublicScanResult | null>(null);
  const [rateLimited, setRateLimited] = React.useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setResult(null);
    setRateLimited(false);

    const parsed = domainSchema.safeParse(domain);
    if (!parsed.success) {
      setError(parsed.error.issues[0]?.message ?? 'Enter a valid domain.');
      return;
    }

    setScanning(true);
    try {
      const scan = await api.publicScan(parsed.data);
      setResult(scan);
    } catch (caught) {
      if (caught instanceof ApiError) {
        if (caught.isRateLimited) {
          setRateLimited(true);
          setError(caught.message);
        } else {
          setError(caught.message);
        }
      } else {
        setError('The scan could not be completed. Please try again.');
      }
    } finally {
      setScanning(false);
    }
  }

  return (
    <>
      <MarketingHeader />
      <main id="main" className="mx-auto max-w-3xl px-6 py-16">
        <p className="text-2xs font-semibold uppercase tracking-governance text-silver-500">
          Free vendor scan
        </p>
        <h1 className="mt-3 text-3xl font-semibold tracking-tight text-silver-50 sm:text-4xl">
          Check a vendor’s public security posture
        </h1>
        <p className="mt-4 max-w-2xl text-sm leading-relaxed text-silver-400">
          Enter a company’s domain. Zentra runs a reduced set of passive checks against publicly
          available sources and gives you a risk score with a plain-English explanation. No account
          needed.
        </p>

        <Card className="mt-8">
          <CardBody>
            <form onSubmit={onSubmit} noValidate>
              <Field
                label="Vendor domain"
                htmlFor="domain"
                hint="For example: stripe.com, or the domain on their website."
                error={error}
                required
              >
                <div className="flex flex-col gap-3 sm:flex-row">
                  <Input
                    id="domain"
                    name="domain"
                    type="text"
                    inputMode="url"
                    autoComplete="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    placeholder="example.com"
                    value={domain}
                    invalid={Boolean(error)}
                    onChange={(event) => setDomain(event.target.value)}
                    disabled={scanning}
                    className="sm:flex-1"
                  />
                  <Button type="submit" loading={scanning} loadingLabel="Scanning…" className="sm:w-40">
                    Run free scan
                  </Button>
                </div>
              </Field>
            </form>

            {scanning && (
              <div className="mt-6 border-t border-ink-800 pt-5" role="status" aria-live="polite">
                <p className="text-sm text-silver-200">Scanning {domain}…</p>
                <ul className="mt-3 space-y-1.5 text-xs text-silver-500">
                  {[
                    'Checking TLS and certificates',
                    'Checking email and DNS security',
                    'Checking breach history',
                    'Checking web hardening',
                    'Calculating risk',
                  ].map((stage) => (
                    <li key={stage} className="flex items-center gap-2">
                      <span
                        aria-hidden="true"
                        className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-silver-400"
                      />
                      {stage}
                    </li>
                  ))}
                </ul>
                <p className="mt-3 text-2xs text-silver-600">
                  This usually takes a few seconds. Some checks wait on third-party sources.
                </p>
              </div>
            )}

            {rateLimited && (
              <div className="mt-5">
                <Banner tone="warning" title="Free scan limit reached">
                  Free scans are limited to protect the service. Create an account to monitor
                  vendors continuously, with daily rescans and alerts.
                  <div className="mt-3">
                    <Link
                      href="/auth/sign-up"
                      className="inline-flex h-9 items-center rounded-sm bg-silver-50 px-4 text-xs font-medium text-ink-950 hover:bg-white"
                    >
                      Create a free account
                    </Link>
                  </div>
                </Banner>
              </div>
            )}
          </CardBody>
        </Card>

        {result && <PublicScanReport result={result} />}

        <p className="mt-10 text-2xs leading-relaxed text-silver-600">
          Zentra performs passive checks against publicly available sources only. It does not
          attempt authentication, exploitation or intrusive testing against any vendor. The free
          scan runs a reduced check set; a full assessment additionally covers internet exposure
          and known vulnerabilities.
        </p>
      </main>
      <MarketingFooter />
    </>
  );
}

function PublicScanReport({ result }: { result: PublicScanResult }) {
  const scorable = result.score !== null && result.risk_level !== null;
  return (
    <div className="mt-8 space-y-6 animate-fade-in">
      <Card>
        <CardHeader
          title={result.domain}
          description={`Assessed ${new Date(result.scanned_at).toLocaleString('en-GB')}`}
          action={<RiskBadge level={result.risk_level} showMeaning />}
        />
        <CardBody className="space-y-5">
          {scorable ? (
            <ScoreIndicator score={result.score} level={result.risk_level} size="lg" />
          ) : (
            <Banner tone="warning" title="Assessment incomplete">
              Zentra could not complete enough checks to publish a risk level for this domain. That
              is not an indication that it is low risk.
            </Banner>
          )}

          <div>
            <h2 className="text-sm font-medium text-silver-50">{result.headline}</h2>
            <p className="mt-2 text-sm leading-relaxed text-silver-300">{result.explanation}</p>
          </div>

          <div className="rounded-sm border border-ink-700 bg-ink-850 p-4">
            <p className="text-2xs font-semibold uppercase tracking-governance text-silver-500">
              Recommended next step
            </p>
            <p className="mt-2 text-sm text-silver-200">{result.recommended_action}</p>
          </div>

          <dl className="grid grid-cols-2 gap-4 border-t border-ink-800 pt-4 text-xs">
            <div>
              <dt className="text-silver-500">Check coverage</dt>
              <dd className="mt-1 text-silver-200">{Math.round(result.coverage * 100)}% of checks completed</dd>
            </div>
            <div>
              <dt className="text-silver-500">Confidence</dt>
              <dd className="mt-1 text-silver-200">{Math.round(result.confidence * 100)}%</dd>
            </div>
          </dl>
        </CardBody>
      </Card>

      {result.top_findings.length > 0 && (
        <Card>
          <CardHeader
            title="What Zentra found"
            description="The most significant issues, worst first."
          />
          <ul>
            {result.top_findings.map((finding, index) => (
              <li key={`${finding.title}-${index}`} className="border-b border-ink-800 px-5 py-4 last:border-b-0">
                <div className="flex flex-wrap items-center gap-3">
                  <SeverityBadge severity={finding.severity} />
                  <h3 className="text-sm font-medium text-silver-100">{finding.title}</h3>
                </div>
                <p className="mt-2 text-sm text-silver-400">{finding.summary}</p>
                {finding.recommendation && (
                  <p className="mt-2 text-sm text-silver-300">
                    <span className="text-silver-500">What to do: </span>
                    {finding.recommendation}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card>
        <CardHeader
          title="Score breakdown"
          description="Points are risk contributed, so a lower number is better."
        />
        <CardBody>
          <ul className="space-y-2.5">
            {result.categories.map((category) => (
              <li key={category.display_name}>
                <div className="flex items-baseline justify-between gap-3">
                  <span className="text-sm text-silver-200">
                    {category.display_name}
                    {!category.assessed && (
                      <span className="ml-2 text-2xs uppercase tracking-governance text-silver-500">
                        Not assessed
                      </span>
                    )}
                  </span>
                  <span className="font-mono text-xs tabular-nums text-silver-300">
                    {category.points} / {category.max_points}
                  </span>
                </div>
                <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-sm bg-ink-800">
                  <div
                    className={cn(
                      'h-full',
                      !category.assessed
                        ? 'bg-silver-600 opacity-25'
                        : category.status === 'severe'
                          ? 'bg-risk-critical'
                          : category.status === 'attention'
                            ? 'bg-risk-high'
                            : category.status === 'minor'
                              ? 'bg-risk-medium'
                              : 'bg-risk-low',
                    )}
                    style={{
                      width: `${category.assessed ? scoreToPercent(category.points, category.max_points) : 100}%`,
                    }}
                  />
                </div>
              </li>
            ))}
          </ul>
        </CardBody>
      </Card>

      <Card className="border-silver-500/30">
        <CardBody className="flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
          <div>
            <h2 className="text-sm font-medium text-silver-50">
              Monitor {result.domain} with Zentra
            </h2>
            <p className="mt-1 text-sm text-silver-400">
              Daily rescans, alerts when risk changes, and an audit-ready register covering every
              vendor you depend on.
            </p>
          </div>
          <Link
            href="/auth/sign-up"
            className="inline-flex h-10 shrink-0 items-center rounded-sm bg-silver-50 px-5 text-sm font-medium text-ink-950 hover:bg-white"
          >
            Monitor this vendor
          </Link>
        </CardBody>
      </Card>

      <p className="text-2xs leading-relaxed text-silver-600">{result.disclaimer}</p>
    </div>
  );
}

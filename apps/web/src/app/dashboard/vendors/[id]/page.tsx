'use client';

import * as React from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  Badge,
  Banner,
  Button,
  Card,
  CardBody,
  CardHeader,
  Dialog,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  Select,
  Table,
  Td,
  Textarea,
  Th,
} from '@/components/ui';
import { TrendChart } from '@/components/charts';
import {
  CheckCard,
  FindingStatusBadge,
  ScanProgress,
  ScanStatusIndicator,
  ScoreBreakdown,
  ScoreIndicator,
  SeverityBadge,
} from '@/components/risk';
import { useAsync } from '@/hooks/useSession';
import { ApiError, api } from '@/lib/api';
import { formatDateTime, relativeTime } from '@/lib/utils';
import type { Finding, FindingStatus, Scan, ScanDetail, Vendor, VendorScore } from '@/lib/types';

const POLL_INTERVAL_MS = 4000;

export default function VendorDetailPage() {
  const params = useParams<{ id: string }>();
  const vendorId = params.id;

  const [nonce, setNonce] = React.useState(0);
  const reloadAll = React.useCallback(() => setNonce((n) => n + 1), []);

  const vendorQuery = useAsync<Vendor>(() => api.vendors.get(vendorId), [vendorId, nonce]);
  const scoreQuery = useAsync<VendorScore>(() => api.vendors.score(vendorId), [vendorId, nonce]);
  const scansQuery = useAsync<Scan[]>(() => api.vendors.scans(vendorId), [vendorId, nonce]);
  const findingsQuery = useAsync<Finding[]>(() => api.vendors.findings(vendorId), [vendorId, nonce]);

  const activeScan = scansQuery.data?.find((scan) =>
    ['queued', 'running'].includes(scan.status),
  );
  const latestScan = scansQuery.data?.find((scan) =>
    ['completed', 'partial'].includes(scan.status),
  );

  const [scanDetail, setScanDetail] = React.useState<ScanDetail | null>(null);
  const latestScanId = latestScan?.id;
  React.useEffect(() => {
    let cancelled = false;
    const load = async () => {
      if (!latestScanId) {
        setScanDetail(null);
        return;
      }
      try {
        const detail = await api.scans.get(latestScanId);
        if (!cancelled) setScanDetail(detail);
      } catch {
        if (!cancelled) setScanDetail(null);
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [latestScanId]);

  // Poll only while a scan is in flight, then stop. No websockets needed.
  const activeScanId = activeScan?.id;
  React.useEffect(() => {
    if (!activeScanId) return;
    const timer = setInterval(reloadAll, POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [activeScanId, reloadAll]);

  const [scanning, setScanning] = React.useState(false);
  const [actionError, setActionError] = React.useState<string | null>(null);

  async function triggerScan() {
    setScanning(true);
    setActionError(null);
    try {
      await api.vendors.scan(vendorId);
      reloadAll();
    } catch (caught) {
      setActionError(caught instanceof ApiError ? caught.message : 'The scan could not be queued.');
    } finally {
      setScanning(false);
    }
  }

  if (vendorQuery.loading) return <LoadingState label="Loading vendor…" rows={6} />;
  if (vendorQuery.error)
    return (
      <ErrorState
        title={vendorQuery.error.status === 404 ? 'Vendor not found' : 'Could not load this vendor'}
        message={vendorQuery.error.message}
        onRetry={reloadAll}
        requestId={vendorQuery.error.requestId}
      />
    );

  const vendor = vendorQuery.data;
  if (!vendor) return null;

  const score = scoreQuery.data;
  const verdict = score?.verdict;
  const openFindings = (findingsQuery.data ?? []).filter((f) =>
    ['open', 'in_progress'].includes(f.status),
  );

  return (
    <div className="space-y-6">
      <div>
        <Link
          href="/dashboard/vendors"
          className="text-xs text-silver-400 underline-offset-4 hover:text-silver-100 hover:underline"
        >
          ← Back to vendors
        </Link>
        <div className="mt-3 flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-xl font-semibold tracking-tight text-silver-50">{vendor.name}</h1>
            <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-silver-400">
              <span>{vendor.domain}</span>
              {vendor.category && <span>· {vendor.category}</span>}
              <Badge className="border-ink-600 text-silver-400">
                {vendor.criticality} criticality
              </Badge>
              {vendor.is_demo && (
                <Badge className="border-risk-medium/45 text-risk-medium">Demo data</Badge>
              )}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="secondary"
              onClick={() => void triggerScan()}
              loading={scanning}
              disabled={Boolean(activeScan)}
            >
              {activeScan ? 'Scan in progress' : 'Scan now'}
            </Button>
            <Link
              href={`/dashboard/reports?vendor=${vendor.id}`}
              className="inline-flex h-10 items-center rounded-sm border border-silver-500/40 px-4 text-sm text-silver-100 hover:border-silver-400 hover:bg-ink-850"
            >
              Generate report
            </Link>
          </div>
        </div>
      </div>

      {actionError && <Banner tone="danger">{actionError}</Banner>}

      {activeScan && (
        <Card>
          <CardBody className="flex flex-wrap items-center justify-between gap-4">
            <ScanProgress status={activeScan.status} />
            <ScanStatusIndicator status={activeScan.status} />
          </CardBody>
        </Card>
      )}

      {/* --------------------------------------------------------- score */}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader
            title="Risk assessment"
            description={
              vendor.last_scanned_at
                ? `Last assessed ${relativeTime(vendor.last_scanned_at)}`
                : 'Not yet assessed'
            }
            action={
              vendor.next_scan_at ? (
                <span className="text-2xs text-silver-500">
                  Next scan {relativeTime(vendor.next_scan_at)}
                </span>
              ) : null
            }
          />
          <CardBody className="space-y-5">
            {scoreQuery.loading && <LoadingState rows={3} />}
            {score && score.score === null && (
              <Banner tone="warning" title="Assessment incomplete">
                Zentra could not complete enough checks to publish a risk level for this vendor.
                That is not an indication that it is low risk. Try scanning again shortly.
              </Banner>
            )}
            {score && score.score !== null && (
              <ScoreIndicator
                score={score.score}
                level={score.risk_level}
                size="lg"
                trend={score.trend}
              />
            )}

            {verdict && (
              <div className="space-y-4">
                <div>
                  <h2 className="text-sm font-medium text-silver-50">{verdict.headline}</h2>
                  <p className="mt-2 text-sm leading-relaxed text-silver-300">
                    {verdict.explanation}
                  </p>
                </div>
                {verdict.why_it_matters && (
                  <div>
                    <p className="text-2xs font-semibold uppercase tracking-governance text-silver-500">
                      Why this matters
                    </p>
                    <p className="mt-1.5 text-sm text-silver-300">{verdict.why_it_matters}</p>
                  </div>
                )}
                <div className="rounded-sm border border-ink-700 bg-ink-850 p-4">
                  <p className="text-2xs font-semibold uppercase tracking-governance text-silver-500">
                    Recommended action
                  </p>
                  <p className="mt-2 text-sm text-silver-200">{verdict.recommended_action}</p>
                </div>
              </div>
            )}

            {score && (
              <dl className="grid grid-cols-2 gap-4 border-t border-ink-800 pt-4 text-xs sm:grid-cols-4">
                <div>
                  <dt className="text-silver-500">Coverage</dt>
                  <dd className="mt-1 text-silver-200">
                    {score.coverage !== null ? `${Math.round(score.coverage * 100)}%` : '—'}
                  </dd>
                </div>
                <div>
                  <dt className="text-silver-500">Confidence</dt>
                  <dd className="mt-1 text-silver-200">
                    {score.confidence !== null ? `${Math.round(score.confidence * 100)}%` : '—'}
                  </dd>
                </div>
                <div>
                  <dt className="text-silver-500">Previous score</dt>
                  <dd className="mt-1 text-silver-200">{score.previous_score ?? '—'}</dd>
                </div>
                <div>
                  <dt className="text-silver-500">Open findings</dt>
                  <dd className="mt-1 text-silver-200">{openFindings.length}</dd>
                </div>
              </dl>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Score breakdown" description="Where the points came from." />
          <CardBody>
            {score?.breakdown ? (
              <>
                <ScoreBreakdown categories={score.breakdown.categories} />
                {score.breakdown.applied_floor && (
                  <p className="mt-4 border-t border-ink-800 pt-3 text-xs text-silver-500">
                    {score.breakdown.applied_floor.explanation}
                  </p>
                )}
              </>
            ) : (
              <p className="text-sm text-silver-500">
                A breakdown appears after the first completed scan.
              </p>
            )}
          </CardBody>
        </Card>
      </div>

      {/* --------------------------------------------------------- trend */}
      <Card>
        <CardHeader
          title="Score history"
          description="A rising line means rising risk."
        />
        <CardBody>
          <TrendChart history={score?.history ?? []} />
        </CardBody>
      </Card>

      {/* -------------------------------------------------------- checks */}
      <Card>
        <CardHeader
          title="Security checks"
          description="Every check Zentra ran, with its source, date and confidence."
        />
        {scanDetail ? (
          scanDetail.results.length > 0 ? (
            <div>
              {scanDetail.results.map((result) => (
                <CheckCard
                  key={result.id}
                  checkType={result.check_type}
                  status={result.status}
                  severity={result.severity}
                  summary={result.summary}
                  source={result.source}
                  checkedAt={result.checked_at}
                  confidence={result.confidence}
                  evidence={result.evidence}
                />
              ))}
            </div>
          ) : (
            <EmptyState title="No check results" description="The last scan produced no results." />
          )
        ) : (
          <EmptyState
            title="No completed scan yet"
            description="Check results appear here once the first scan finishes."
          />
        )}
      </Card>

      {/* ------------------------------------------------------ findings */}
      <FindingsSection
        findings={findingsQuery.data ?? []}
        loading={findingsQuery.loading}
        onChanged={reloadAll}
      />

      {/* ---------------------------------------------------- scan history */}
      <Card>
        <CardHeader title="Scan history" />
        {scansQuery.data && scansQuery.data.length > 0 ? (
          <Table>
            <thead>
              <tr>
                <Th>Queued</Th>
                <Th className="w-28">Trigger</Th>
                <Th className="w-40">Status</Th>
                <Th className="w-24">Score</Th>
                <Th className="w-36">Checks</Th>
                <Th className="w-40">Completed</Th>
              </tr>
            </thead>
            <tbody>
              {scansQuery.data.map((scan) => (
                <tr key={scan.id} className="hover:bg-ink-850">
                  <Td className="text-xs text-silver-400">{formatDateTime(scan.queued_at)}</Td>
                  <Td className="text-xs capitalize text-silver-400">{scan.trigger}</Td>
                  <Td>
                    <ScanStatusIndicator status={scan.status} />
                    {scan.error_message && (
                      <p className="mt-1 text-2xs text-silver-500">{scan.error_message}</p>
                    )}
                  </Td>
                  <Td className="text-sm tabular-nums text-silver-200">{scan.score ?? '—'}</Td>
                  <Td className="text-xs text-silver-400">
                    {scan.checks_succeeded}/{scan.checks_total} conclusive
                  </Td>
                  <Td className="text-xs text-silver-400">
                    {scan.completed_at ? formatDateTime(scan.completed_at) : '—'}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <EmptyState title="No scans yet" description="The first scan runs shortly after a vendor is added." />
        )}
      </Card>

    </div>
  );
}

function FindingsSection({
  findings,
  loading,
  onChanged,
}: {
  findings: Finding[];
  loading: boolean;
  onChanged: () => void;
}) {
  const [editing, setEditing] = React.useState<Finding | null>(null);
  const [status, setStatus] = React.useState<FindingStatus>('open');
  const [note, setNote] = React.useState('');
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  function openDialog(finding: Finding) {
    setEditing(finding);
    setStatus(finding.status);
    setNote('');
    setError(null);
  }

  async function save() {
    if (!editing) return;
    setSaving(true);
    setError(null);
    try {
      await api.findings.update(editing.id, { status, note: note.trim() || undefined });
      setEditing(null);
      onChanged();
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : 'The finding could not be updated.',
      );
    } finally {
      setSaving(false);
    }
  }

  const open = findings.filter((f) => ['open', 'in_progress'].includes(f.status));
  const closed = findings.filter((f) => ['resolved', 'accepted_risk'].includes(f.status));

  return (
    <>
      <Card>
        <CardHeader
          title="Findings and remediation"
          description="Tracked issues. Update the status as you work through them with the vendor."
        />
        {loading && <LoadingState rows={3} />}
        {!loading && findings.length === 0 && (
          <EmptyState
            title="No findings"
            description="Zentra has not detected any tracked issues for this vendor."
          />
        )}
        {!loading && findings.length > 0 && (
          <ul className="divide-y divide-ink-800">
            {[...open, ...closed].map((finding) => (
              <li key={finding.id} className="px-5 py-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={finding.severity} />
                      <FindingStatusBadge status={finding.status} />
                      <h3 className="text-sm font-medium text-silver-100">{finding.title}</h3>
                    </div>
                    <p className="mt-2 text-sm text-silver-400">{finding.description}</p>
                    <p className="mt-2 text-sm text-silver-300">
                      <span className="text-silver-500">What to do: </span>
                      {finding.recommendation}
                    </p>
                    <p className="mt-2 text-2xs text-silver-600">
                      Source: {finding.source} · First seen {relativeTime(finding.first_seen_at)} ·
                      Last confirmed {relativeTime(finding.last_seen_at)} · Confidence{' '}
                      {Math.round(finding.confidence * 100)}%
                    </p>
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => openDialog(finding)}>
                    Update
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Dialog
        open={editing !== null}
        onClose={() => setEditing(null)}
        title="Update finding"
        description={editing?.title}
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditing(null)} disabled={saving}>
              Cancel
            </Button>
            <Button onClick={() => void save()} loading={saving} loadingLabel="Saving…">
              Save
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          {error && <Banner tone="danger">{error}</Banner>}
          <Field label="Status" htmlFor="finding-status">
            <Select
              id="finding-status"
              value={status}
              onChange={(event) => setStatus(event.target.value as FindingStatus)}
            >
              <option value="open">Open</option>
              <option value="in_progress">In progress — raised with the vendor</option>
              <option value="resolved">Resolved</option>
              <option value="accepted_risk">Accepted risk</option>
            </Select>
          </Field>
          <Field
            label="Note"
            htmlFor="finding-note"
            hint="Recorded in the finding’s history, and included in reports."
          >
            <Textarea
              id="finding-note"
              rows={3}
              placeholder="Raised with the vendor on 1 September. They expect to renew by the 8th."
              value={note}
              onChange={(event) => setNote(event.target.value)}
            />
          </Field>
        </div>
      </Dialog>
    </>
  );
}

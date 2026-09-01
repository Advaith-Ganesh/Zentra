'use client';

import * as React from 'react';
import Link from 'next/link';
import {
  Banner,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  Field,
  Input,
  LoadingState,
  Table,
  Td,
  Th,
} from '@/components/ui';
import { Badge } from '@/components/ui';
import { useAsync } from '@/hooks/useSession';
import { ApiError, api } from '@/lib/api';
import { formatBytes, formatDateTime } from '@/lib/utils';
import type { Report } from '@/lib/types';

const POLL_INTERVAL_MS = 3000;

export default function ReportsPage() {
  const [nonce, setNonce] = React.useState(0);
  const { data, loading, error, reload } = useAsync<Report[]>(() => api.reports.list(), [nonce]);

  const [title, setTitle] = React.useState('');
  const [creating, setCreating] = React.useState(false);
  const [createError, setCreateError] = React.useState<{ message: string; upgrade: boolean } | null>(
    null,
  );
  const [downloadingId, setDownloadingId] = React.useState<string | null>(null);
  const [downloadError, setDownloadError] = React.useState<string | null>(null);

  const pending = data?.some((report) => ['queued', 'generating'].includes(report.status));
  React.useEffect(() => {
    if (!pending) return;
    const timer = setInterval(() => setNonce((n) => n + 1), POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [pending]);

  async function generate(event: React.FormEvent) {
    event.preventDefault();
    setCreating(true);
    setCreateError(null);
    try {
      await api.reports.create(title.trim() ? { title: title.trim() } : {});
      setTitle('');
      setNonce((n) => n + 1);
    } catch (caught) {
      if (caught instanceof ApiError) {
        setCreateError({ message: caught.message, upgrade: caught.isEntitlementError });
      } else {
        setCreateError({ message: 'The report could not be requested.', upgrade: false });
      }
    } finally {
      setCreating(false);
    }
  }

  async function download(report: Report) {
    setDownloadingId(report.id);
    setDownloadError(null);
    try {
      const blob = await api.reports.download(report.id);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `zentra-vendor-risk-register-${report.created_at.slice(0, 10)}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (caught) {
      setDownloadError(
        caught instanceof ApiError ? caught.message : 'The report could not be downloaded.',
      );
    } finally {
      setDownloadingId(null);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-silver-50">Reports</h1>
        <p className="mt-1 text-sm text-silver-400">
          Generate a dated vendor risk register covering every vendor you monitor.
        </p>
      </div>

      <Card>
        <CardHeader
          title="Generate a vendor risk register"
          description="A PDF covering every active vendor: scores, key findings, recommended actions and the full methodology."
        />
        <CardBody>
          {createError && (
            <div className="mb-4">
              <Banner
                tone={createError.upgrade ? 'warning' : 'danger'}
                title={createError.upgrade ? 'Not included in your plan' : undefined}
              >
                {createError.message}
                {createError.upgrade && (
                  <div className="mt-3">
                    <Link
                      href="/dashboard/billing"
                      className="inline-flex h-9 items-center rounded-sm bg-silver-50 px-4 text-xs font-medium text-ink-950 hover:bg-white"
                    >
                      View plans
                    </Link>
                  </div>
                )}
              </Banner>
            </div>
          )}
          <form onSubmit={generate} className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <div className="flex-1">
              <Field label="Report title" htmlFor="report-title" hint="Optional. Defaults to your company name.">
                <Input
                  id="report-title"
                  placeholder="Q3 vendor risk register"
                  value={title}
                  onChange={(event) => setTitle(event.target.value)}
                  disabled={creating}
                />
              </Field>
            </div>
            <Button type="submit" loading={creating} loadingLabel="Requesting…" className="sm:w-44">
              Generate report
            </Button>
          </form>
          <p className="mt-3 text-2xs leading-relaxed text-silver-600">
            Reports are informational assessments supporting your third-party risk process. They do
            not confer or demonstrate compliance with any certification scheme.
          </p>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Generated reports" />
        {downloadError && (
          <p role="alert" className="border-b border-ink-800 px-5 py-3 text-sm text-risk-critical">
            {downloadError}
          </p>
        )}
        {loading && <LoadingState label="Loading reports…" rows={4} />}
        {error && <ErrorState message={error.message} onRetry={reload} requestId={error.requestId} />}
        {data && data.length === 0 && (
          <EmptyState
            title="No reports yet"
            description="Generate your first vendor risk register above. It takes a few seconds."
          />
        )}
        {data && data.length > 0 && (
          <Table>
            <thead>
              <tr>
                <Th>Title</Th>
                <Th className="w-40">Created</Th>
                <Th className="w-36">Status</Th>
                <Th className="w-24">Size</Th>
                <Th className="w-36 text-right">Download</Th>
              </tr>
            </thead>
            <tbody>
              {data.map((report) => (
                <tr key={report.id} className="hover:bg-ink-850">
                  <Td className="text-silver-100">{report.title}</Td>
                  <Td className="text-xs text-silver-400">{formatDateTime(report.created_at)}</Td>
                  <Td>
                    <ReportStatus report={report} />
                  </Td>
                  <Td className="text-xs text-silver-400">{formatBytes(report.file_size)}</Td>
                  <Td className="text-right">
                    {report.status === 'completed' ? (
                      <Button
                        size="sm"
                        variant="secondary"
                        loading={downloadingId === report.id}
                        onClick={() => void download(report)}
                      >
                        Download PDF
                      </Button>
                    ) : (
                      <span className="text-xs text-silver-600">—</span>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  );
}

function ReportStatus({ report }: { report: Report }) {
  if (report.status === 'completed') {
    return <Badge className="border-risk-low/45 text-risk-low">Ready</Badge>;
  }
  if (report.status === 'failed') {
    return (
      <div>
        <Badge className="border-risk-critical/45 text-risk-critical">Failed</Badge>
        {report.error_message && (
          <p className="mt-1 text-2xs text-silver-500">{report.error_message}</p>
        )}
      </div>
    );
  }
  return (
    <Badge className="border-silver-500/40 text-silver-300">
      <span
        aria-hidden="true"
        className="mr-1 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-current"
      />
      Preparing…
    </Badge>
  );
}

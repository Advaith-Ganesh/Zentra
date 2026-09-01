'use client';

import * as React from 'react';
import Link from 'next/link';
import {
  Card,
  EmptyState,
  ErrorState,
  LoadingState,
  Select,
} from '@/components/ui';
import { FindingStatusBadge, SeverityBadge } from '@/components/risk';
import { useAsync } from '@/hooks/useSession';
import { api } from '@/lib/api';
import { relativeTime } from '@/lib/utils';
import type { Finding, Vendor } from '@/lib/types';

export default function FindingsPage() {
  const [statusFilter, setStatusFilter] = React.useState('open');

  const findingsQuery = useAsync<Finding[]>(
    () =>
      api.findings.list(
        statusFilter === 'all'
          ? {}
          : statusFilter === 'open'
            ? { status: ['open', 'in_progress'] }
            : { status: [statusFilter] },
      ),
    [statusFilter],
  );
  const vendorsQuery = useAsync<{ items: Vendor[] }>(
    () => api.vendors.list({ status: 'all', limit: 200 }),
    [],
  );

  const vendorNames = React.useMemo(() => {
    const map = new Map<string, Vendor>();
    for (const vendor of vendorsQuery.data?.items ?? []) map.set(vendor.id, vendor);
    return map;
  }, [vendorsQuery.data]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-silver-50">Findings</h1>
        <p className="mt-1 text-sm text-silver-400">
          Every tracked issue across your vendors, worst first.
        </p>
      </div>

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-ink-750 px-5 py-4">
          <h2 className="text-sm font-medium text-silver-50">
            {findingsQuery.data ? `${findingsQuery.data.length} findings` : 'Findings'}
          </h2>
          <div className="w-52">
            <label htmlFor="finding-filter" className="sr-only">
              Filter findings
            </label>
            <Select
              id="finding-filter"
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value)}
            >
              <option value="open">Open and in progress</option>
              <option value="resolved">Resolved</option>
              <option value="accepted_risk">Accepted risk</option>
              <option value="all">All</option>
            </Select>
          </div>
        </div>

        {findingsQuery.loading && <LoadingState label="Loading findings…" rows={5} />}
        {findingsQuery.error && (
          <ErrorState
            message={findingsQuery.error.message}
            onRetry={findingsQuery.reload}
            requestId={findingsQuery.error.requestId}
          />
        )}
        {findingsQuery.data?.length === 0 && (
          <EmptyState
            title={statusFilter === 'open' ? 'No open findings' : 'Nothing here'}
            description={
              statusFilter === 'open'
                ? 'Zentra has not detected any outstanding issues across your vendors.'
                : 'Try a different filter.'
            }
          />
        )}
        {findingsQuery.data && findingsQuery.data.length > 0 && (
          <ul className="divide-y divide-ink-800">
            {findingsQuery.data.map((finding) => {
              const vendor = vendorNames.get(finding.vendor_id);
              return (
                <li key={finding.id} className="px-5 py-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={finding.severity} />
                    <FindingStatusBadge status={finding.status} />
                    <h3 className="text-sm font-medium text-silver-100">{finding.title}</h3>
                  </div>
                  <p className="mt-1.5 text-xs text-silver-500">
                    {vendor ? (
                      <Link
                        href={`/dashboard/vendors/${vendor.id}`}
                        className="underline-offset-4 hover:text-silver-300 hover:underline"
                      >
                        {vendor.name} · {vendor.domain}
                      </Link>
                    ) : (
                      'Unknown vendor'
                    )}
                    {' · '}
                    Last confirmed {relativeTime(finding.last_seen_at)}
                  </p>
                  <p className="mt-2 text-sm text-silver-400">{finding.description}</p>
                  <p className="mt-2 text-sm text-silver-300">
                    <span className="text-silver-500">What to do: </span>
                    {finding.recommendation}
                  </p>
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </div>
  );
}

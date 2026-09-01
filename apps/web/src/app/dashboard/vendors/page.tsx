'use client';

import * as React from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  Input,
  LoadingState,
  Select,
  Table,
  Td,
  Th,
} from '@/components/ui';
import { RiskBadge, ScoreCell } from '@/components/risk';
import { useAsync } from '@/hooks/useSession';
import { ApiError, api } from '@/lib/api';
import { trendPresentation } from '@/lib/risk';
import { cn, relativeTime } from '@/lib/utils';
import type { VendorList } from '@/lib/types';

/** Filters live in the URL so a filtered view is shareable and back works. */
export default function VendorsPage() {
  return (
    <React.Suspense fallback={<LoadingState label="Loading vendors…" rows={6} />}>
      <VendorsView />
    </React.Suspense>
  );
}

function VendorsView() {
  const router = useRouter();
  const params = useSearchParams();

  const search = params.get('search') ?? '';
  const status = params.get('status') ?? 'active';
  const risk = params.get('risk') ?? '';
  const sort = params.get('sort') ?? 'current_score';
  const direction = params.get('direction') ?? 'desc';

  const [searchInput, setSearchInput] = React.useState(search);
  const [busyId, setBusyId] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const { data, loading, error, reload } = useAsync<VendorList>(
    () =>
      api.vendors.list({
        search: search || undefined,
        status,
        risk_level: risk ? [risk] : undefined,
        sort,
        direction,
        limit: 100,
      }),
    [search, status, risk, sort, direction],
  );

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params.toString());
    if (value) next.set(key, value);
    else next.delete(key);
    router.replace(`/dashboard/vendors?${next.toString()}`);
  }

  React.useEffect(() => {
    const timer = setTimeout(() => {
      if (searchInput !== search) setParam('search', searchInput);
    }, 300);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchInput]);

  async function runScan(vendorId: string) {
    setBusyId(vendorId);
    setActionError(null);
    try {
      await api.vendors.scan(vendorId);
      reload();
    } catch (caught) {
      setActionError(caught instanceof ApiError ? caught.message : 'The scan could not be queued.');
    } finally {
      setBusyId(null);
    }
  }

  async function archive(vendorId: string) {
    setBusyId(vendorId);
    setActionError(null);
    try {
      await api.vendors.archive(vendorId);
      reload();
    } catch (caught) {
      setActionError(caught instanceof ApiError ? caught.message : 'The vendor could not be archived.');
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-silver-50">Vendors</h1>
          <p className="mt-1 text-sm text-silver-400">
            Every third party you monitor, with its current risk position.
          </p>
        </div>
        <Link
          href="/dashboard/vendors/new"
          className="inline-flex h-10 items-center rounded-sm bg-silver-50 px-4 text-sm font-medium text-ink-950 hover:bg-white"
        >
          Add vendor
        </Link>
      </div>

      <Card>
        <div className="flex flex-wrap items-end gap-3 border-b border-ink-750 px-5 py-4">
          <div className="min-w-[200px] flex-1">
            <label htmlFor="vendor-search" className="sr-only">
              Search vendors
            </label>
            <Input
              id="vendor-search"
              type="search"
              placeholder="Search by name or domain…"
              value={searchInput}
              onChange={(event) => setSearchInput(event.target.value)}
            />
          </div>
          <div className="w-36">
            <label htmlFor="risk-filter" className="sr-only">
              Filter by risk level
            </label>
            <Select
              id="risk-filter"
              value={risk}
              onChange={(event) => setParam('risk', event.target.value)}
            >
              <option value="">All risk levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </Select>
          </div>
          <div className="w-36">
            <label htmlFor="status-filter" className="sr-only">
              Filter by status
            </label>
            <Select
              id="status-filter"
              value={status}
              onChange={(event) => setParam('status', event.target.value)}
            >
              <option value="active">Active</option>
              <option value="paused">Paused</option>
              <option value="archived">Archived</option>
              <option value="all">All</option>
            </Select>
          </div>
          <div className="w-44">
            <label htmlFor="sort-order" className="sr-only">
              Sort by
            </label>
            <Select
              id="sort-order"
              value={`${sort}:${direction}`}
              onChange={(event) => {
                const [nextSort, nextDirection] = event.target.value.split(':');
                const next = new URLSearchParams(params.toString());
                next.set('sort', nextSort!);
                next.set('direction', nextDirection!);
                router.replace(`/dashboard/vendors?${next.toString()}`);
              }}
            >
              <option value="current_score:desc">Highest risk first</option>
              <option value="current_score:asc">Lowest risk first</option>
              <option value="name:asc">Name (A–Z)</option>
              <option value="last_scanned_at:desc">Recently assessed</option>
              <option value="created_at:desc">Recently added</option>
            </Select>
          </div>
        </div>

        {actionError && (
          <p role="alert" className="border-b border-ink-800 px-5 py-3 text-sm text-risk-critical">
            {actionError}
          </p>
        )}

        {loading && <LoadingState label="Loading vendors…" rows={6} />}
        {error && <ErrorState message={error.message} onRetry={reload} requestId={error.requestId} />}

        {data && data.items.length === 0 && (
          <EmptyState
            title={search || risk ? 'No vendors match these filters' : 'No vendors yet'}
            description={
              search || risk
                ? 'Try clearing the search or the risk filter.'
                : 'Add your first vendor to start monitoring third-party risk.'
            }
            action={
              search || risk ? (
                <Button variant="secondary" size="sm" onClick={() => router.replace('/dashboard/vendors')}>
                  Clear filters
                </Button>
              ) : (
                <Link
                  href="/dashboard/vendors/new"
                  className="inline-flex h-10 items-center rounded-sm bg-silver-50 px-5 text-sm font-medium text-ink-950 hover:bg-white"
                >
                  Add vendor
                </Link>
              )
            }
          />
        )}

        {data && data.items.length > 0 && (
          <>
            <Table>
              <caption className="sr-only">
                Vendors, showing risk score, risk level, trend and last assessment date
              </caption>
              <thead>
                <tr>
                  <Th>Vendor</Th>
                  <Th className="w-24">Score</Th>
                  <Th className="w-28">Risk</Th>
                  <Th className="w-32">Trend</Th>
                  <Th className="w-28">Criticality</Th>
                  <Th className="w-36">Last assessed</Th>
                  <Th className="w-44 text-right">Actions</Th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((vendor) => {
                  const trend = trendPresentation(vendor.score_trend);
                  return (
                    <tr key={vendor.id} className="hover:bg-ink-850">
                      <Td>
                        <Link
                          href={`/dashboard/vendors/${vendor.id}`}
                          className="font-medium text-silver-100 underline-offset-4 hover:underline"
                        >
                          {vendor.name}
                        </Link>
                        <span className="block text-xs text-silver-500">{vendor.domain}</span>
                      </Td>
                      <Td>
                        <ScoreCell score={vendor.current_score} level={vendor.current_risk_level} />
                      </Td>
                      <Td>
                        <RiskBadge level={vendor.current_risk_level} />
                      </Td>
                      <Td>
                        <span className={cn('text-xs tabular-nums', trend.className)}>
                          <span aria-hidden="true">{trend.glyph}</span> {trend.label}
                        </span>
                      </Td>
                      <Td className="text-xs capitalize text-silver-400">{vendor.criticality}</Td>
                      <Td className="text-xs text-silver-400">{relativeTime(vendor.last_scanned_at)}</Td>
                      <Td className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => void runScan(vendor.id)}
                            loading={busyId === vendor.id}
                            aria-label={`Scan ${vendor.name} now`}
                          >
                            Scan now
                          </Button>
                          {vendor.status !== 'archived' && (
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => void archive(vendor.id)}
                              disabled={busyId === vendor.id}
                              aria-label={`Archive ${vendor.name}`}
                            >
                              Archive
                            </Button>
                          )}
                        </div>
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
            <p className="border-t border-ink-800 px-5 py-3 text-xs text-silver-500">
              Showing {data.items.length} of {data.total} vendor{data.total === 1 ? '' : 's'}. A
              higher score means more observed risk.
            </p>
          </>
        )}
      </Card>
    </div>
  );
}

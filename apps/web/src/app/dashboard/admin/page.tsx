'use client';

import * as React from 'react';
import { Badge, Card, CardBody, CardHeader, ErrorState, LoadingState, Table, Td, Th } from '@/components/ui';
import { useAsync, useSession } from '@/hooks/useSession';
import { request } from '@/lib/api';
import { formatDateTime } from '@/lib/utils';

interface AdminOverview {
  environment: string;
  mock_scanners: boolean;
  feature_flags: Record<string, boolean>;
  totals: { users: number; organizations: number; vendors: number; scans: number };
  scan_health_24h: Record<string, number>;
  plan_mix: Record<string, number>;
  dependencies: Record<string, string>;
}

interface ScanHealth {
  window_hours: number;
  by_status: Record<string, number>;
  failure_reasons: Record<string, number>;
  avg_duration_seconds: number | null;
  max_duration_seconds: number | null;
}

/**
 * Internal platform admin. Authorization is enforced entirely server-side by
 * the `is_platform_admin` column; this component only decides what to render.
 */
export default function AdminPage() {
  const { me, loading: sessionLoading } = useSession();
  const overview = useAsync<AdminOverview>(() => request('/api/v1/admin/overview'), []);
  const health = useAsync<ScanHealth>(() => request('/api/v1/admin/scan-health'), []);
  const webhooks = useAsync<
    { provider: string; event_type: string | null; status: string; error: string | null; created_at: string }[]
  >(() => request('/api/v1/admin/webhooks?limit=20'), []);

  if (sessionLoading) return <LoadingState rows={4} />;
  if (!me) return null;

  if (!me.user.is_platform_admin) {
    return (
      <ErrorState
        title="Not found"
        message="This area does not exist for your account."
      />
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-silver-50">Platform admin</h1>
        <p className="mt-1 text-sm text-silver-400">
          Internal operations view. Not visible to customers.
        </p>
      </div>

      {overview.loading && <LoadingState rows={4} />}
      {overview.error && (
        <ErrorState message={overview.error.message} onRetry={overview.reload} />
      )}

      {overview.data && (
        <>
          <Card>
            <CardHeader title="System" />
            <CardBody>
              <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
                <div>
                  <dt className="text-xs text-silver-500">Environment</dt>
                  <dd className="mt-1 text-silver-100">{overview.data.environment}</dd>
                </div>
                <div>
                  <dt className="text-xs text-silver-500">Scanners</dt>
                  <dd className="mt-1">
                    {overview.data.mock_scanners ? (
                      <Badge className="border-risk-medium/45 text-risk-medium">Mock providers</Badge>
                    ) : (
                      <Badge className="border-risk-low/45 text-risk-low">Live providers</Badge>
                    )}
                  </dd>
                </div>
                {Object.entries(overview.data.dependencies).map(([name, status]) => (
                  <div key={name}>
                    <dt className="text-xs capitalize text-silver-500">{name}</dt>
                    <dd className="mt-1">
                      <Badge
                        className={
                          status === 'ok'
                            ? 'border-risk-low/45 text-risk-low'
                            : 'border-risk-critical/45 text-risk-critical'
                        }
                      >
                        {status}
                      </Badge>
                    </dd>
                  </div>
                ))}
              </dl>
            </CardBody>
          </Card>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader title="Totals" />
              <CardBody>
                <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                  {Object.entries(overview.data.totals).map(([label, value]) => (
                    <div key={label}>
                      <dt className="text-xs capitalize text-silver-500">{label}</dt>
                      <dd className="mt-1 text-2xl font-semibold text-silver-50">{value}</dd>
                    </div>
                  ))}
                </dl>
              </CardBody>
            </Card>

            <Card>
              <CardHeader title="Plan mix" />
              <CardBody>
                <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                  {Object.entries(overview.data.plan_mix).map(([plan, count]) => (
                    <div key={plan}>
                      <dt className="text-xs capitalize text-silver-500">{plan}</dt>
                      <dd className="mt-1 text-2xl font-semibold text-silver-50">{count}</dd>
                    </div>
                  ))}
                </dl>
              </CardBody>
            </Card>
          </div>

          <Card>
            <CardHeader title="Feature flags" />
            <CardBody>
              <ul className="flex flex-wrap gap-2">
                {Object.entries(overview.data.feature_flags).map(([flag, enabled]) => (
                  <li key={flag}>
                    <Badge
                      className={
                        enabled
                          ? 'border-risk-low/45 text-risk-low'
                          : 'border-ink-600 text-silver-500'
                      }
                    >
                      {flag.replace(/_/g, ' ')}
                    </Badge>
                  </li>
                ))}
              </ul>
            </CardBody>
          </Card>
        </>
      )}

      {health.data && (
        <Card>
          <CardHeader title={`Scan health (last ${health.data.window_hours}h)`} />
          <CardBody className="space-y-4">
            <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              {Object.entries(health.data.by_status).map(([status, count]) => (
                <div key={status}>
                  <dt className="text-xs capitalize text-silver-500">{status}</dt>
                  <dd className="mt-1 text-xl font-semibold text-silver-50">{count}</dd>
                </div>
              ))}
            </dl>
            <dl className="grid grid-cols-2 gap-4 border-t border-ink-800 pt-4 text-sm">
              <div>
                <dt className="text-xs text-silver-500">Average duration</dt>
                <dd className="mt-1 text-silver-100">
                  {health.data.avg_duration_seconds ? `${health.data.avg_duration_seconds}s` : '—'}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-silver-500">Slowest scan</dt>
                <dd className="mt-1 text-silver-100">
                  {health.data.max_duration_seconds ? `${health.data.max_duration_seconds}s` : '—'}
                </dd>
              </div>
            </dl>
            {Object.keys(health.data.failure_reasons).length > 0 && (
              <div className="border-t border-ink-800 pt-4">
                <p className="text-xs text-silver-500">Failure reasons</p>
                <ul className="mt-2 space-y-1 text-sm text-silver-300">
                  {Object.entries(health.data.failure_reasons).map(([reason, count]) => (
                    <li key={reason}>
                      <span className="font-mono text-xs">{reason}</span> — {count}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </CardBody>
        </Card>
      )}

      {webhooks.data && webhooks.data.length > 0 && (
        <Card>
          <CardHeader title="Recent webhook events" />
          <Table>
            <thead>
              <tr>
                <Th className="w-28">Provider</Th>
                <Th>Event</Th>
                <Th className="w-28">Status</Th>
                <Th className="w-44">Received</Th>
              </tr>
            </thead>
            <tbody>
              {webhooks.data.map((event, index) => (
                <tr key={`${event.provider}-${index}`}>
                  <Td className="text-xs text-silver-400">{event.provider}</Td>
                  <Td className="font-mono text-xs text-silver-300">{event.event_type ?? '—'}</Td>
                  <Td className="text-xs text-silver-400">{event.status}</Td>
                  <Td className="text-xs text-silver-400">{formatDateTime(event.created_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
      )}
    </div>
  );
}

'use client';

import * as React from 'react';
import Link from 'next/link';
import { Badge, Button, Card, CardHeader, EmptyState, ErrorState, LoadingState } from '@/components/ui';
import { useAsync } from '@/hooks/useSession';
import { api } from '@/lib/api';
import { formatDateTime } from '@/lib/utils';
import type { Alert } from '@/lib/types';

export default function AlertsPage() {
  const [nonce, setNonce] = React.useState(0);
  const { data, loading, error, reload } = useAsync<Alert[]>(() => api.alerts.list(), [nonce]);
  const [busyId, setBusyId] = React.useState<string | null>(null);

  async function acknowledge(id: string) {
    setBusyId(id);
    try {
      await api.alerts.acknowledge(id);
      setNonce((n) => n + 1);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-silver-50">Alerts</h1>
        <p className="mt-1 text-sm text-silver-400">
          Raised when a vendor’s risk position changes materially.
        </p>
      </div>

      <Card>
        <CardHeader title="Recent alerts" />
        {loading && <LoadingState label="Loading alerts…" rows={4} />}
        {error && <ErrorState message={error.message} onRetry={reload} requestId={error.requestId} />}
        {data?.length === 0 && (
          <EmptyState
            title="No alerts"
            description="Zentra alerts you when a vendor's score worsens materially, or when a new critical finding appears."
          />
        )}
        {data && data.length > 0 && (
          <ul className="divide-y divide-ink-800">
            {data.map((alert) => (
              <li key={alert.id} className="flex flex-wrap items-start justify-between gap-4 px-5 py-4">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-sm font-medium text-silver-100">{alert.title}</h3>
                    {alert.acknowledged_at && (
                      <Badge className="border-ink-600 text-silver-500">Acknowledged</Badge>
                    )}
                    {alert.notification_status === 'suppressed' && (
                      <Badge className="border-ink-600 text-silver-500" title="Email alerts are not included in your plan.">
                        Not emailed
                      </Badge>
                    )}
                  </div>
                  <p className="mt-1.5 text-sm text-silver-400">{alert.message}</p>
                  <p className="mt-2 text-2xs text-silver-600">
                    {formatDateTime(alert.created_at)}
                    {alert.score_delta !== null && (
                      <>
                        {' · '}Score {alert.old_score} → {alert.new_score} (
                        {alert.score_delta > 0 ? '+' : ''}
                        {alert.score_delta})
                      </>
                    )}
                  </p>
                </div>
                <div className="flex shrink-0 gap-2">
                  {alert.vendor_id && (
                    <Link
                      href={`/dashboard/vendors/${alert.vendor_id}`}
                      className="inline-flex h-8 items-center rounded-sm border border-ink-600 px-3 text-xs text-silver-200 hover:border-ink-500 hover:bg-ink-850"
                    >
                      Review vendor
                    </Link>
                  )}
                  {!alert.acknowledged_at && (
                    <Button
                      size="sm"
                      variant="ghost"
                      loading={busyId === alert.id}
                      onClick={() => void acknowledge(alert.id)}
                    >
                      Acknowledge
                    </Button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

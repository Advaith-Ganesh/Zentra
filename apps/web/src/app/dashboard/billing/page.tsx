'use client';

import * as React from 'react';
import {
  Banner,
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  LoadingState,
} from '@/components/ui';
import { useAsync } from '@/hooks/useSession';
import { ApiError, api } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import type { Billing } from '@/lib/types';

export default function BillingPage() {
  const { data, loading, error, reload } = useAsync<Billing>(() => api.billing.get(), []);
  const [busy, setBusy] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  async function checkout(plan: string) {
    setBusy(plan);
    setActionError(null);
    try {
      const result = await api.billing.checkout(
        plan === 'report_pack' ? { product: 'report_pack' } : { plan },
      );
      window.location.assign(result.checkout_url);
    } catch (caught) {
      setActionError(
        caught instanceof ApiError ? caught.message : 'Checkout could not be started.',
      );
      setBusy(null);
    }
  }

  async function openPortal() {
    setBusy('portal');
    setActionError(null);
    try {
      const result = await api.billing.portal();
      window.location.assign(result.portal_url);
    } catch (caught) {
      setActionError(
        caught instanceof ApiError ? caught.message : 'The billing portal could not be opened.',
      );
      setBusy(null);
    }
  }

  if (loading) return <LoadingState label="Loading billing…" rows={5} />;
  if (error) return <ErrorState message={error.message} onRetry={reload} requestId={error.requestId} />;
  if (!data) return null;

  const entitlements = data.entitlements;
  const usagePercent = entitlements.unlimited_vendors
    ? 0
    : Math.min(
        100,
        Math.round((entitlements.vendors_used / Math.max(entitlements.vendor_limit, 1)) * 100),
      );
  const atLimit = !entitlements.unlimited_vendors && entitlements.vendors_remaining === 0;
  const nearLimit = !entitlements.unlimited_vendors && usagePercent >= 80;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-silver-50">Billing</h1>
        <p className="mt-1 text-sm text-silver-400">Your plan, usage and available upgrades.</p>
      </div>

      {actionError && <Banner tone="danger">{actionError}</Banner>}

      {!data.stripe_configured && (
        <Banner tone="info" title="Billing is not configured in this environment">
          Stripe credentials have not been supplied to this deployment, so checkout is unavailable.
          Plan entitlements are still enforced by the backend.
        </Banner>
      )}

      {atLimit && (
        <Banner tone="warning" title="You have reached your vendor limit">
          You are using all {entitlements.vendor_limit} vendors on the {entitlements.plan_name} plan.
          Upgrade to add more.
        </Banner>
      )}

      <Card>
        <CardHeader
          title={`Current plan: ${entitlements.plan_name}`}
          description={`Subscription status: ${data.status}`}
          action={
            data.stripe_configured ? (
              <Button variant="secondary" size="sm" loading={busy === 'portal'} onClick={() => void openPortal()}>
                Manage billing
              </Button>
            ) : null
          }
        />
        <CardBody className="space-y-5">
          <div>
            <div className="flex items-baseline justify-between gap-3">
              <span className="text-sm text-silver-300">Vendors used</span>
              <span className="font-mono text-sm tabular-nums text-silver-100">
                {entitlements.unlimited_vendors
                  ? `${entitlements.vendors_used} (unlimited)`
                  : `${entitlements.vendors_used} / ${entitlements.vendor_limit}`}
              </span>
            </div>
            {!entitlements.unlimited_vendors && (
              <div
                className="mt-2 h-2 w-full overflow-hidden rounded-sm bg-ink-800"
                role="meter"
                aria-valuenow={entitlements.vendors_used}
                aria-valuemin={0}
                aria-valuemax={entitlements.vendor_limit}
                aria-label="Vendor allowance used"
              >
                <div
                  className={
                    atLimit ? 'h-full bg-risk-critical' : nearLimit ? 'h-full bg-risk-medium' : 'h-full bg-silver-300'
                  }
                  style={{ width: `${usagePercent}%` }}
                />
              </div>
            )}
          </div>

          <dl className="grid grid-cols-2 gap-4 text-xs sm:grid-cols-4">
            <div>
              <dt className="text-silver-500">Rescan frequency</dt>
              <dd className="mt-1 text-silver-200">Every {entitlements.scan_interval_hours} hours</dd>
            </div>
            <div>
              <dt className="text-silver-500">Team seats</dt>
              <dd className="mt-1 text-silver-200">
                {entitlements.member_limit === -1 ? 'Unlimited' : entitlements.member_limit}
              </dd>
            </div>
            <div>
              <dt className="text-silver-500">Renews</dt>
              <dd className="mt-1 text-silver-200">
                {data.current_period_end ? formatDate(data.current_period_end) : '—'}
              </dd>
            </div>
            <div>
              <dt className="text-silver-500">Report packs</dt>
              <dd className="mt-1 text-silver-200">{entitlements.report_pack_credits}</dd>
            </div>
          </dl>

          {data.cancel_at_period_end && (
            <Banner tone="warning">
              Your subscription is set to cancel at the end of the current period. You will move to
              the Free plan on {formatDate(data.current_period_end)}.
            </Banner>
          )}

          <div>
            <p className="text-2xs font-semibold uppercase tracking-governance text-silver-500">
              Included in your plan
            </p>
            <ul className="mt-2 flex flex-wrap gap-2">
              {entitlements.features.map((feature) => (
                <li
                  key={feature}
                  className="rounded-sm border border-ink-600 px-2 py-1 text-2xs text-silver-300"
                >
                  {feature.replace(/_/g, ' ')}
                </li>
              ))}
            </ul>
          </div>
        </CardBody>
      </Card>

      <div>
        <h2 className="text-sm font-medium text-silver-50">Plans</h2>
        <div className="mt-4 grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
          {data.available_plans.map((plan) => {
            const current = plan.plan === entitlements.plan;
            return (
              <Card key={plan.plan} className={current ? 'border-silver-400/50' : undefined}>
                <CardBody className="flex h-full flex-col">
                  <div className="flex items-baseline justify-between gap-2">
                    <h3 className="text-sm font-medium text-silver-50">{plan.name}</h3>
                    {current && (
                      <span className="text-2xs uppercase tracking-governance text-silver-400">
                        Current
                      </span>
                    )}
                  </div>
                  <p className="mt-3 text-2xl font-semibold text-silver-50">{plan.price_display}</p>
                  <p className="mt-2 flex-1 text-sm text-silver-400">{plan.description}</p>
                  <ul className="mt-4 space-y-1.5">
                    {plan.features.slice(0, 5).map((feature) => (
                      <li key={feature} className="flex gap-2 text-xs text-silver-400">
                        <span aria-hidden="true" className="mt-1.5 h-1 w-1 shrink-0 bg-silver-500" />
                        {feature.replace(/_/g, ' ')}
                      </li>
                    ))}
                  </ul>
                  <Button
                    className="mt-5 w-full"
                    variant={current ? 'ghost' : 'secondary'}
                    disabled={current || !plan.purchasable || !data.stripe_configured}
                    loading={busy === plan.plan}
                    onClick={() => void checkout(plan.plan)}
                  >
                    {current
                      ? 'Current plan'
                      : !plan.purchasable || !data.stripe_configured
                        ? 'Unavailable here'
                        : `Choose ${plan.name}`}
                  </Button>
                </CardBody>
              </Card>
            );
          })}
        </div>
        <p className="mt-4 text-2xs text-silver-600">
          Prices exclude VAT. Entitlements are enforced by the backend from your Stripe
          subscription; changes take effect as soon as Stripe confirms them.
        </p>
      </div>
    </div>
  );
}

'use client';

import * as React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Wordmark } from '@/components/marketing';
import { Badge, LoadingState } from '@/components/ui';
import { useSession } from '@/hooks/useSession';
import { cn, initials } from '@/lib/utils';

const NAV = [
  { href: '/dashboard', label: 'Overview', exact: true },
  { href: '/dashboard/vendors', label: 'Vendors' },
  { href: '/dashboard/findings', label: 'Findings' },
  { href: '/dashboard/reports', label: 'Reports' },
  { href: '/dashboard/alerts', label: 'Alerts' },
  { href: '/dashboard/settings', label: 'Settings' },
  { href: '/dashboard/billing', label: 'Billing' },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { me, loading, signOut } = useSession();
  const [menuOpen, setMenuOpen] = React.useState(false);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="w-full max-w-md">
          <LoadingState label="Loading your workspace…" rows={4} />
        </div>
      </div>
    );
  }

  if (!me) return null;

  const entitlements = me.entitlements;
  const usage = entitlements.unlimited_vendors
    ? `${entitlements.vendors_used} vendors`
    : `${entitlements.vendors_used}/${entitlements.vendor_limit} vendors`;
  const nearLimit =
    !entitlements.unlimited_vendors &&
    entitlements.vendor_limit > 0 &&
    entitlements.vendors_used / entitlements.vendor_limit >= 0.8;

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-40 border-b border-ink-800 bg-ink-950/90 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-4 px-4 sm:px-6">
          <div className="flex items-center gap-3">
            <Link href="/dashboard" className="flex items-center gap-2 rounded-sm">
              <span aria-hidden="true" className="inline-block h-3.5 w-3.5 border border-silver-200" />
              <Wordmark />
              <span className="sr-only">Zentra dashboard</span>
            </Link>
            <span aria-hidden="true" className="hidden h-4 w-px bg-ink-700 sm:block" />
            <span className="hidden truncate text-sm text-silver-400 sm:block">
              {me.organization.name}
            </span>
          </div>

          <div className="flex items-center gap-3">
            <Link
              href="/dashboard/billing"
              className={cn(
                'hidden rounded-sm border px-2.5 py-1 text-2xs font-medium uppercase tracking-governance sm:inline-flex',
                nearLimit
                  ? 'border-risk-medium/45 text-risk-medium'
                  : 'border-ink-600 text-silver-400 hover:border-ink-500 hover:text-silver-200',
              )}
            >
              {entitlements.plan_name} · {usage}
            </Link>
            <div className="relative">
              <button
                type="button"
                onClick={() => setMenuOpen((open) => !open)}
                aria-expanded={menuOpen}
                aria-haspopup="menu"
                className="flex h-9 w-9 items-center justify-center rounded-sm border border-ink-600 text-xs font-medium text-silver-200 hover:border-ink-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-silver-300"
              >
                {initials(me.user.full_name ?? me.user.email)}
                <span className="sr-only">Account menu</span>
              </button>
              {menuOpen && (
                <div
                  role="menu"
                  className="absolute right-0 top-11 z-50 w-60 rounded-sm border border-ink-700 bg-ink-900 py-1 shadow-xl"
                >
                  <div className="border-b border-ink-800 px-3 py-2.5">
                    <p className="truncate text-sm text-silver-100">
                      {me.user.full_name ?? me.user.email}
                    </p>
                    <p className="truncate text-xs text-silver-500">{me.user.email}</p>
                    <Badge className="mt-2 border-ink-600 text-silver-400">{me.role}</Badge>
                  </div>
                  <Link
                    role="menuitem"
                    href="/dashboard/settings"
                    onClick={() => setMenuOpen(false)}
                    className="block px-3 py-2 text-sm text-silver-300 hover:bg-ink-850 hover:text-silver-50"
                  >
                    Settings
                  </Link>
                  {me.user.is_platform_admin && (
                    <Link
                      role="menuitem"
                      href="/dashboard/admin"
                      onClick={() => setMenuOpen(false)}
                      className="block px-3 py-2 text-sm text-silver-300 hover:bg-ink-850 hover:text-silver-50"
                    >
                      Platform admin
                    </Link>
                  )}
                  <button
                    role="menuitem"
                    type="button"
                    onClick={() => void signOut()}
                    className="block w-full px-3 py-2 text-left text-sm text-silver-300 hover:bg-ink-850 hover:text-silver-50"
                  >
                    Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        <nav aria-label="Dashboard" className="border-t border-ink-850">
          <div className="mx-auto max-w-7xl overflow-x-auto px-4 sm:px-6">
            <ul className="flex min-w-max gap-1">
              {NAV.map((item) => {
                const active = item.exact
                  ? pathname === item.href
                  : pathname.startsWith(item.href);
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      aria-current={active ? 'page' : undefined}
                      className={cn(
                        'inline-flex h-11 items-center border-b-2 px-3 text-sm transition-colors',
                        active
                          ? 'border-silver-200 text-silver-50'
                          : 'border-transparent text-silver-400 hover:text-silver-100',
                      )}
                    >
                      {item.label}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        </nav>
      </header>

      {me.organization.name.includes('(demo)') && (
        <div className="border-b border-risk-medium/30 bg-risk-medium-dim px-4 py-2 text-center sm:px-6">
          <p className="text-xs text-risk-medium">
            Demo workspace. Every scan result here is synthetic data produced by Zentra’s mock
            providers and describes no real company’s security posture.
          </p>
        </div>
      )}

      <main id="main" className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 sm:px-6">
        {children}
      </main>

      <footer className="border-t border-ink-800 px-4 py-5 sm:px-6">
        <p className="mx-auto max-w-7xl text-2xs leading-relaxed text-silver-600">
          Zentra’s risk scores are informational assessments based on signals from publicly
          available sources. They are not an audit of a vendor and are not legal, regulatory or
          certification advice.
        </p>
      </footer>
    </div>
  );
}

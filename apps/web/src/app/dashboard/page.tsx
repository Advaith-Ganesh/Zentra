"use client";

import * as React from "react";
import Link from "next/link";
import {
  Banner,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingState,
  Table,
  Td,
  Th,
} from "@/components/ui";
import { RiskBadge, ScanStatusIndicator, ScoreCell } from "@/components/risk";
import { useAsync } from "@/hooks/useSession";
import { api } from "@/lib/api";
import { relativeTime } from "@/lib/utils";
import type { Dashboard } from "@/lib/types";

export default function DashboardOverviewPage() {
  const { data, loading, error, reload } = useAsync<Dashboard>(
    () => api.dashboard(),
    [],
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-silver-50">
            Overview
          </h1>
          <p className="mt-1 text-sm text-silver-400">
            Your third-party risk position right now.
          </p>
        </div>
        <div className="flex gap-2">
          <Link
            href="/dashboard/reports"
            className="inline-flex h-10 items-center rounded-sm border border-silver-500/40 px-4 text-sm text-silver-100 hover:border-silver-400 hover:bg-ink-850"
          >
            Generate report
          </Link>
          <Link
            href="/dashboard/vendors/new"
            className="inline-flex h-10 items-center rounded-sm bg-silver-50 px-4 text-sm font-medium text-ink-950 hover:bg-white"
          >
            Add vendor
          </Link>
        </div>
      </div>

      {loading && <LoadingState label="Loading your dashboard…" rows={5} />}
      {error && (
        <ErrorState
          message={error.message}
          onRetry={reload}
          requestId={error.requestId}
        />
      )}

      {data && (
        <>
          {data.summary.total_vendors === 0 ? (
            <Card>
              <EmptyState
                title="No vendors yet"
                description="Add your first vendor to start monitoring third-party risk. Start with the supplier you would least like to have a breach."
                action={
                  <Link
                    href="/dashboard/vendors/new"
                    className="inline-flex h-10 items-center rounded-sm bg-silver-50 px-5 text-sm font-medium text-ink-950 hover:bg-white"
                  >
                    Add your first vendor
                  </Link>
                }
              />
            </Card>
          ) : (
            <>
              <SummaryTiles summary={data.summary} />

              {data.summary.vendors_needing_attention > 0 && (
                <Banner tone="warning" title="Vendors needing attention">
                  {data.summary.vendors_needing_attention === 1
                    ? "1 vendor carries"
                    : `${data.summary.vendors_needing_attention} vendors carry`}{" "}
                  high or critical risk signals. Each has a recommended next
                  step on its detail page.
                </Banner>
              )}

              {/* grid-cols-1 (minmax(0, 1fr)) and min-w-0 keep these grid items
                  from being sized by the wide tables they contain. See the
                  known-limitation note in README about the residual horizontal
                  pan this page still has on very narrow screens. */}
              <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
                <Card className="min-w-0 lg:col-span-2">
                  <CardHeader
                    title="Needs attention"
                    description="Highest-risk vendors first."
                    action={
                      <Link
                        href="/dashboard/vendors"
                        className="text-xs text-silver-400 underline-offset-4 hover:text-silver-100 hover:underline"
                      >
                        All vendors
                      </Link>
                    }
                  />
                  {data.vendors_needing_attention.length === 0 ? (
                    <EmptyState
                      title="Nothing needs attention"
                      description="No vendor currently carries high or critical risk signals across the checks that completed."
                    />
                  ) : (
                    <Table>
                      <thead>
                        <tr>
                          <Th>Vendor</Th>
                          <Th className="w-24">Score</Th>
                          <Th className="w-28">Risk</Th>
                          <Th className="w-32">Last assessed</Th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.vendors_needing_attention.map((vendor) => (
                          <tr key={vendor.id} className="hover:bg-ink-850">
                            <Td>
                              <Link
                                href={`/dashboard/vendors/${vendor.id}`}
                                className="font-medium text-silver-100 underline-offset-4 hover:underline"
                              >
                                {vendor.name}
                              </Link>
                              <span className="block text-xs text-silver-500">
                                {vendor.domain}
                              </span>
                            </Td>
                            <Td>
                              <ScoreCell
                                score={vendor.current_score}
                                level={vendor.current_risk_level}
                              />
                            </Td>
                            <Td>
                              <RiskBadge level={vendor.current_risk_level} />
                            </Td>
                            <Td className="text-xs text-silver-400">
                              {relativeTime(vendor.last_scanned_at)}
                            </Td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  )}
                </Card>

                <Card className="min-w-0">
                  <CardHeader
                    title="Recent alerts"
                    action={
                      <Link
                        href="/dashboard/alerts"
                        className="text-xs text-silver-400 underline-offset-4 hover:text-silver-100 hover:underline"
                      >
                        All
                      </Link>
                    }
                  />
                  {data.recent_alerts.length === 0 ? (
                    <EmptyState
                      title="No alerts"
                      description="Zentra will alert you here when a vendor's risk changes materially."
                    />
                  ) : (
                    <ul className="divide-y divide-ink-800">
                      {data.recent_alerts.map((alert) => (
                        <li key={alert.id} className="px-5 py-3.5">
                          <p className="text-sm text-silver-100">
                            {alert.title}
                          </p>
                          <p className="mt-1 text-xs text-silver-500">
                            {relativeTime(alert.created_at)}
                            {alert.score_delta !== null && (
                              <>
                                {" · "}
                                {alert.old_score} → {alert.new_score}
                              </>
                            )}
                          </p>
                        </li>
                      ))}
                    </ul>
                  )}
                </Card>
              </div>

              <Card>
                <CardHeader
                  title="Recent scans"
                  description="The last assessments Zentra ran."
                />
                {data.recent_scans.length === 0 ? (
                  <EmptyState
                    title="No scans yet"
                    description="Scans appear here once vendors are added."
                  />
                ) : (
                  <Table>
                    <thead>
                      <tr>
                        <Th>Started</Th>
                        <Th className="w-32">Trigger</Th>
                        <Th className="w-40">Status</Th>
                        <Th className="w-24">Score</Th>
                        <Th className="w-32">Checks</Th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.recent_scans.map((scan) => (
                        <tr key={scan.id} className="hover:bg-ink-850">
                          <Td className="text-xs text-silver-400">
                            {relativeTime(scan.queued_at)}
                          </Td>
                          <Td className="text-xs capitalize text-silver-400">
                            {scan.trigger}
                          </Td>
                          <Td>
                            <ScanStatusIndicator status={scan.status} />
                          </Td>
                          <Td>
                            <ScoreCell
                              score={scan.score}
                              level={scan.risk_level}
                            />
                          </Td>
                          <Td className="text-xs text-silver-400">
                            {scan.checks_succeeded}/{scan.checks_total}{" "}
                            conclusive
                          </Td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                )}
              </Card>
            </>
          )}
        </>
      )}
    </div>
  );
}

function SummaryTiles({ summary }: { summary: Dashboard["summary"] }) {
  const tiles = [
    {
      label: "Vendors monitored",
      value: summary.total_vendors,
      tone: "text-silver-50",
    },
    {
      label: "Critical risk",
      value: summary.critical_vendors,
      tone: "text-risk-critical",
    },
    {
      label: "High risk",
      value: summary.high_risk_vendors,
      tone: "text-risk-high",
    },
    {
      label: "Average score",
      value: summary.average_score ?? "—",
      tone: "text-silver-50",
      hint: "Lower is better",
    },
    {
      label: "Open findings",
      value: summary.open_findings,
      tone: "text-silver-50",
    },
  ];
  return (
    <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-sm border border-ink-700 bg-ink-700 sm:grid-cols-3 lg:grid-cols-5">
      {tiles.map((tile) => (
        <div key={tile.label} className="bg-ink-900 px-5 py-4">
          <dt className="text-2xs uppercase tracking-governance text-silver-500">
            {tile.label}
          </dt>
          <dd
            className={`mt-1.5 text-2xl font-semibold tabular-nums ${tile.tone}`}
          >
            {tile.value}
          </dd>
          {tile.hint && (
            <p className="mt-0.5 text-2xs text-silver-600">{tile.hint}</p>
          )}
        </div>
      ))}
    </dl>
  );
}

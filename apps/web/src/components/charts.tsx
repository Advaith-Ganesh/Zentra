'use client';

import * as React from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { formatDate } from '@/lib/utils';
import type { RiskLevel } from '@/lib/types';

interface TrendPoint {
  date: string | null;
  score: number;
  risk_level: RiskLevel;
}

/**
 * Score history. A rising line means rising risk, so the threshold guides are
 * labelled explicitly rather than left to colour alone.
 */
export function TrendChart({ history }: { history: TrendPoint[] }) {
  const data = React.useMemo(
    () =>
      history
        .filter((point) => point.date)
        .map((point) => ({
          date: point.date!,
          label: formatDate(point.date),
          score: point.score,
        })),
    [history],
  );

  if (data.length < 2) {
    return (
      <div className="flex h-48 items-center justify-center text-center">
        <p className="max-w-xs text-sm text-silver-500">
          {data.length === 0
            ? 'No completed scans yet. The trend appears once this vendor has been assessed.'
            : 'One assessment so far. The trend appears after the next scan.'}
        </p>
      </div>
    );
  }

  return (
    <div>
      <div className="h-48 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
            <defs>
              <linearGradient id="zentra-score" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#8e97a6" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#8e97a6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#232932" strokeDasharray="2 4" vertical={false} />
            <XAxis
              dataKey="label"
              stroke="#4e5666"
              tick={{ fill: '#6b7484', fontSize: 11 }}
              tickLine={false}
              axisLine={{ stroke: '#232932' }}
              minTickGap={24}
            />
            <YAxis
              domain={[0, 100]}
              ticks={[0, 25, 50, 75, 100]}
              stroke="#4e5666"
              tick={{ fill: '#6b7484', fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              width={40}
            />
            <ReferenceLine y={25} stroke="#e0b341" strokeDasharray="3 3" strokeOpacity={0.4} />
            <ReferenceLine y={50} stroke="#e8813f" strokeDasharray="3 3" strokeOpacity={0.4} />
            <ReferenceLine y={75} stroke="#e35d5d" strokeDasharray="3 3" strokeOpacity={0.4} />
            <Tooltip
              cursor={{ stroke: '#3d4552' }}
              contentStyle={{
                background: '#101318',
                border: '1px solid #232932',
                borderRadius: 2,
                fontSize: 12,
                color: '#eceef2',
              }}
              labelStyle={{ color: '#8e97a6' }}
              formatter={(value) => [`${String(value)} / 100`, 'Risk score']}
            />
            <Area
              type="monotone"
              dataKey="score"
              stroke="#d7dbe2"
              strokeWidth={1.75}
              fill="url(#zentra-score)"
              dot={{ r: 2.5, fill: '#d7dbe2', strokeWidth: 0 }}
              activeDot={{ r: 4 }}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <p className="mt-2 text-2xs text-silver-600">
        Guides mark the Medium (25), High (50) and Critical (75) thresholds. A higher
        score means more observed risk.
      </p>
      <table className="sr-only">
        <caption>Risk score history</caption>
        <thead>
          <tr>
            <th scope="col">Date</th>
            <th scope="col">Score</th>
          </tr>
        </thead>
        <tbody>
          {data.map((point) => (
            <tr key={point.date}>
              <td>{point.label}</td>
              <td>{point.score}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** A tiny inline sparkline for table rows. */
export function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) {
    return <span className="text-2xs text-silver-600">—</span>;
  }
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const range = Math.max(max - min, 1);
  const points = values
    .map((value, index) => {
      const x = (index / (values.length - 1)) * 60;
      const y = 18 - ((value - min) / range) * 16;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
  const last = values[values.length - 1]!;
  const first = values[0]!;
  return (
    <svg
      width="60"
      height="20"
      viewBox="0 0 60 20"
      role="img"
      aria-label={`Score moved from ${first} to ${last}`}
      className="overflow-visible"
    >
      <polyline
        points={points}
        fill="none"
        stroke={last > first ? '#e8813f' : last < first ? '#3fbf87' : '#6b7484'}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

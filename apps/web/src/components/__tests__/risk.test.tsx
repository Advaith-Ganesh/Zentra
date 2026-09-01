import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import {
  CheckStatusBadge,
  RiskBadge,
  ScanProgress,
  ScoreBreakdown,
  ScoreIndicator,
} from '@/components/risk';
import type { ScoreCategory } from '@/lib/types';

const categories: ScoreCategory[] = [
  {
    category: 'tls',
    display_name: 'TLS / certificate',
    description: 'Encryption in transit.',
    points: 25,
    max_points: 25,
    assessed: true,
    confidence: 1,
    status: 'severe',
    contributing_checks: [],
  },
  {
    category: 'cve',
    display_name: 'Known vulnerabilities',
    description: 'Published CVEs.',
    points: 0,
    max_points: 15,
    assessed: false,
    confidence: 0,
    status: 'unavailable',
    contributing_checks: [],
  },
];

describe('RiskBadge', () => {
  it('labels the risk level in text, not only colour', () => {
    render(<RiskBadge level="critical" />);
    expect(screen.getByText('Critical')).toBeInTheDocument();
  });

  it('announces the level to screen readers', () => {
    render(<RiskBadge level="high" />);
    expect(screen.getByText('Risk level:')).toBeInTheDocument();
  });

  it('shows "Not assessed" rather than implying safety when there is no level', () => {
    render(<RiskBadge level={null} />);
    expect(screen.getByText('Not assessed')).toBeInTheDocument();
    expect(screen.queryByText('Low')).not.toBeInTheDocument();
  });
});

describe('ScoreIndicator', () => {
  it('renders the score out of 100 with its level', () => {
    render(<ScoreIndicator score={72} level="high" />);
    expect(screen.getByText('72')).toBeInTheDocument();
    expect(screen.getByText('/ 100')).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
  });

  it('shows a dash rather than a zero when there is no score', () => {
    render(<ScoreIndicator score={null} level={null} />);
    // The em dash appears both as the score and as the "not assessed" glyph.
    expect(screen.getAllByText('—').length).toBeGreaterThan(0);
    expect(screen.queryByText('0')).not.toBeInTheDocument();
    expect(screen.getByText('Not assessed')).toBeInTheDocument();
  });

  it('describes a rising score as worse', () => {
    render(<ScoreIndicator score={60} level="high" trend={15} />);
    expect(screen.getByText(/\+15 \(worse\)/)).toBeInTheDocument();
  });
});

describe('ScoreBreakdown', () => {
  it('renders every category with its points and maximum', () => {
    render(<ScoreBreakdown categories={categories} />);
    expect(screen.getByText('TLS / certificate')).toBeInTheDocument();
    expect(screen.getByText('25 / 25')).toBeInTheDocument();
    expect(screen.getByText('0 / 15')).toBeInTheDocument();
  });

  it('marks an unassessed category explicitly', () => {
    render(<ScoreBreakdown categories={categories} />);
    expect(screen.getByText('Not assessed')).toBeInTheDocument();
  });

  it('explains that lower points are better', () => {
    render(<ScoreBreakdown categories={categories} />);
    expect(screen.getByText(/lower number is better/i)).toBeInTheDocument();
  });

  it('exposes each category as an accessible meter', () => {
    render(<ScoreBreakdown categories={categories} />);
    const meters = screen.getAllByRole('meter');
    expect(meters).toHaveLength(2);
    expect(meters[0]).toHaveAttribute('aria-valuenow', '25');
    expect(meters[0]).toHaveAttribute('aria-valuemax', '25');
  });
});

describe('CheckStatusBadge', () => {
  it('distinguishes a provider outage from a failure', () => {
    const { rerender } = render(<CheckStatusBadge status="error" />);
    expect(screen.getByText('Unavailable')).toBeInTheDocument();
    rerender(<CheckStatusBadge status="fail" />);
    expect(screen.getByText('Problem')).toBeInTheDocument();
  });

  it('labels an inconclusive check as not assessed', () => {
    render(<CheckStatusBadge status="unknown" />);
    expect(screen.getByText('Not assessed')).toBeInTheDocument();
  });
});

describe('ScanProgress', () => {
  it('names the stages instead of faking a percentage', () => {
    render(<ScanProgress status="running" />);
    expect(screen.getByText('Checking TLS and certificates')).toBeInTheDocument();
    expect(screen.getByText('Calculating risk')).toBeInTheDocument();
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
  });

  it('is announced politely to assistive technology', () => {
    render(<ScanProgress status="queued" />);
    expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite');
  });
});

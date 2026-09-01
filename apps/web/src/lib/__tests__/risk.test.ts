import { describe, expect, it } from 'vitest';
import {
  CHECK_STATUS_PRESENTATION,
  RISK_PRESENTATION,
  SEVERITY_ORDER,
  checkTypeLabel,
  riskPresentation,
  scoreToPercent,
  trendPresentation,
} from '@/lib/risk';

describe('risk presentation', () => {
  it('maps every risk level to a label, a glyph and a meaning', () => {
    for (const level of ['low', 'medium', 'high', 'critical', 'unknown'] as const) {
      const presentation = RISK_PRESENTATION[level];
      expect(presentation.label).toBeTruthy();
      expect(presentation.glyph).toBeTruthy();
      expect(presentation.meaning).toBeTruthy();
    }
  });

  it('never relies on colour alone: each level has a distinct glyph', () => {
    const glyphs = Object.values(RISK_PRESENTATION).map((p) => p.glyph);
    expect(new Set(glyphs).size).toBe(glyphs.length);
  });

  it('treats an absent risk level as "not assessed", never as low', () => {
    expect(riskPresentation(null).label).toBe('Not assessed');
    expect(riskPresentation(undefined).label).toBe('Not assessed');
    expect(riskPresentation(null).meaning).toContain('not an indication of low risk');
  });

  it('describes a provider outage as unavailable, not as a pass', () => {
    expect(CHECK_STATUS_PRESENTATION.error.label).toBe('Unavailable');
    expect(CHECK_STATUS_PRESENTATION.error.meaning).toContain('not an indication');
    expect(CHECK_STATUS_PRESENTATION.unknown.meaning).toContain('not counted as a problem');
  });

  it('orders severities worst-first', () => {
    expect(SEVERITY_ORDER.critical).toBeLessThan(SEVERITY_ORDER.high);
    expect(SEVERITY_ORDER.high).toBeLessThan(SEVERITY_ORDER.medium);
    expect(SEVERITY_ORDER.medium).toBeLessThan(SEVERITY_ORDER.low);
    expect(SEVERITY_ORDER.low).toBeLessThan(SEVERITY_ORDER.info);
  });
});

describe('trend presentation', () => {
  it('reads a rising score as worse', () => {
    const trend = trendPresentation(12);
    expect(trend.label).toContain('worse');
    expect(trend.glyph).toBe('↑');
  });

  it('reads a falling score as better', () => {
    const trend = trendPresentation(-8);
    expect(trend.label).toContain('better');
    expect(trend.glyph).toBe('↓');
  });

  it('handles no change and missing data', () => {
    expect(trendPresentation(0).label).toBe('No change');
    expect(trendPresentation(null).label).toBe('No change');
    expect(trendPresentation(undefined).label).toBe('No change');
  });
});

describe('scoreToPercent', () => {
  it('converts points to a bounded percentage', () => {
    expect(scoreToPercent(0, 25)).toBe(0);
    expect(scoreToPercent(25, 25)).toBe(100);
    expect(scoreToPercent(12.5, 25)).toBe(50);
  });

  it('never divides by zero or exceeds bounds', () => {
    expect(scoreToPercent(5, 0)).toBe(0);
    expect(scoreToPercent(50, 25)).toBe(100);
    expect(scoreToPercent(-5, 25)).toBe(0);
  });
});

describe('checkTypeLabel', () => {
  it('uses plain English for known checks', () => {
    expect(checkTypeLabel('dns_dmarc')).toBe('Email spoofing policy (DMARC)');
    expect(checkTypeLabel('tls_certificate')).toBe('TLS certificate');
  });

  it('degrades readably for an unknown check', () => {
    expect(checkTypeLabel('some_new_check')).toBe('some new check');
  });
});

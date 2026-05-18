import { describe, it, expect } from 'vitest';
import { UnifiedFindingSchema, MergedFindingSchema } from './finding.js';

const validFinding = {
  id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  tool: 'sca' as const,
  severity: 'high' as const,
  cvss: 8.1,
  cve: 'CVE-2023-44487',
  cwe: 'CWE-400',
  title: 'CVE-2023-44487 in lodash',
  asset: 'my-service',
  status: 'open' as const,
  fixVersion: '4.17.21',
  firstSeen: '2024-01-01T00:00:00Z',
  lastSeen: '2024-01-02T00:00:00Z',
  remediationSteps: ['Upgrade lodash to 4.17.21'],
  references: [],
  evidence: { raw: 'data' },
  scanId: 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
};

describe('UnifiedFindingSchema', () => {
  it('parses a valid finding', () => {
    const result = UnifiedFindingSchema.safeParse(validFinding);
    expect(result.success).toBe(true);
  });

  it('rejects an invalid severity', () => {
    const result = UnifiedFindingSchema.safeParse({ ...validFinding, severity: 'extreme' });
    expect(result.success).toBe(false);
  });

  it('allows null cvss', () => {
    const result = UnifiedFindingSchema.safeParse({ ...validFinding, cvss: null });
    expect(result.success).toBe(true);
  });

  it('rejects cvss > 10', () => {
    const result = UnifiedFindingSchema.safeParse({ ...validFinding, cvss: 10.1 });
    expect(result.success).toBe(false);
  });

  it('defaults status to open when omitted', () => {
    const { status: _, ...withoutStatus } = validFinding;
    const result = UnifiedFindingSchema.safeParse(withoutStatus);
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.status).toBe('open');
  });
});

describe('MergedFindingSchema', () => {
  it('parses a merged finding with multiple tools', () => {
    const { tool: _, ...base } = validFinding;
    const merged = { ...base, tools: ['sca', 'sonatype'], occurrenceCount: 2 };
    const result = MergedFindingSchema.safeParse(merged);
    expect(result.success).toBe(true);
  });
});

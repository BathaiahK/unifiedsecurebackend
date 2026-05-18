import { describe, it, expect, vi } from 'vitest';
import { enrichFindings } from './engine.js';
import type { UnifiedFinding } from '@usp/schema';

vi.mock('./nvd-client.js', () => ({
  enrichFromNvd: vi
    .fn()
    .mockResolvedValue({ cvss: 9.8, severity: 'critical', cwe: 'CWE-917', description: 'RCE' }),
}));

vi.mock('./osv-client.js', () => ({
  enrichFromOsv: vi.fn().mockResolvedValue({
    fixVersion: '2.17.1',
    advisoryUrls: ['https://nvd.nist.gov/CVE-2021-44228'],
    ecosystem: 'Maven',
  }),
}));

const baseFinding: UnifiedFinding = {
  id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  tool: 'sca',
  severity: 'critical',
  cvss: null,
  cve: 'CVE-2021-44228',
  cwe: null,
  title: 'Log4j RCE Vulnerability',
  asset: 'payment-service',
  status: 'open',
  fixVersion: null,
  firstSeen: '2024-01-01T00:00:00Z',
  lastSeen: '2024-01-02T00:00:00Z',
  remediationSteps: ['Check dependencies'],
  references: [],
  evidence: {},
  scanId: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
};

describe('enrichFindings', () => {
  it('fills in cvss from NVD when null', async () => {
    const [result] = await enrichFindings([baseFinding]);
    expect(result?.cvss).toBe(9.8);
  });

  it('fills in cwe from NVD when null', async () => {
    const [result] = await enrichFindings([baseFinding]);
    expect(result?.cwe).toBe('CWE-917');
  });

  it('fills in fixVersion from OSV when null', async () => {
    const [result] = await enrichFindings([baseFinding]);
    expect(result?.fixVersion).toBe('2.17.1');
  });

  it('appends advisory URL to remediation steps', async () => {
    const [result] = await enrichFindings([baseFinding]);
    expect(result?.remediationSteps.some((s) => s.includes('nvd.nist.gov'))).toBe(true);
  });

  it('does not overwrite an already-present cvss', async () => {
    const withCvss = { ...baseFinding, cvss: 5.0 };
    const [result] = await enrichFindings([withCvss]);
    expect(result?.cvss).toBe(5.0);
  });

  it('skips enrichment when cve is null', async () => {
    const noCve = { ...baseFinding, cve: null };
    const [result] = await enrichFindings([noCve]);
    expect(result?.cvss).toBeNull();
  });

  it('deduplicates remediation steps', async () => {
    const withDupe = {
      ...baseFinding,
      remediationSteps: ['Upgrade to version 2.17.1 or later'],
    };
    const [result] = await enrichFindings([withDupe]);
    const upgradeSteps = result?.remediationSteps.filter((s) => s.includes('2.17.1'));
    expect(upgradeSteps?.length).toBe(1);
  });
});

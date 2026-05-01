import { describe, it, expect } from 'vitest';
import { normalizeBlackDuckComponent } from './normalize.js';
import type { BlackDuckVulnerableComponent } from './client.js';

const rawComponent: BlackDuckVulnerableComponent = {
  componentName: 'log4j-core',
  componentVersionName: '2.14.1',
  vulnerabilityWithRemediation: {
    vulnerabilityName: 'CVE-2021-44228',
    description: 'Apache Log4j2 JNDI RCE vulnerability',
    baseScore: 10.0,
    severity: 'CRITICAL',
    remediationStatus: 'OPEN',
    cweId: 'CWE-917',
    targetRemediationDate: null,
    remediationCreatedAt: '2021-12-10T00:00:00Z',
  },
  _meta: { href: 'https://blackduck.example.com/api/components/123' },
};

describe('normalizeBlackDuckComponent', () => {
  it('maps severity correctly', () => {
    const finding = normalizeBlackDuckComponent(rawComponent, 'payment-service', 'scan-123');
    expect(finding.severity).toBe('critical');
  });

  it('extracts CVE from vulnerability name', () => {
    const finding = normalizeBlackDuckComponent(rawComponent, 'payment-service', 'scan-123');
    expect(finding.cve).toBe('CVE-2021-44228');
  });

  it('maps tool to blackduck', () => {
    const finding = normalizeBlackDuckComponent(rawComponent, 'payment-service', 'scan-123');
    expect(finding.tool).toBe('blackduck');
  });

  it('maps OPEN status correctly', () => {
    const finding = normalizeBlackDuckComponent(rawComponent, 'payment-service', 'scan-123');
    expect(finding.status).toBe('open');
  });

  it('preserves asset name', () => {
    const finding = normalizeBlackDuckComponent(rawComponent, 'my-service', 'scan-123');
    expect(finding.asset).toBe('my-service');
  });

  it('returns a valid UUID for id', () => {
    const finding = normalizeBlackDuckComponent(rawComponent, 'my-service', 'scan-123');
    expect(finding.id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('does not extract CVE from non-CVE vulnerability name', () => {
    const comp = {
      ...rawComponent,
      vulnerabilityWithRemediation: {
        ...rawComponent.vulnerabilityWithRemediation,
        vulnerabilityName: 'BDSA-2021-9999',
      },
    };
    const finding = normalizeBlackDuckComponent(comp, 'my-service', 'scan-123');
    expect(finding.cve).toBeNull();
  });
});

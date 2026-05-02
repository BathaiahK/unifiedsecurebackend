import { randomUUID } from 'crypto';
import type { UnifiedFinding } from '@usp/schema';
import type { BlackDuckVulnerableComponent } from './client.js';

const severityMap: Record<string, UnifiedFinding['severity']> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
  INFORMATIONAL: 'info',
};

const statusMap: Record<string, UnifiedFinding['status']> = {
  OPEN: 'open',
  MITIGATED: 'suppressed',
  IGNORED: 'suppressed',
  REMEDIATED: 'fixed',
  NEEDS_REVIEW: 'in_progress',
  PATCHED: 'fixed',
};

export function normalizeBlackDuckComponent(
  component: BlackDuckVulnerableComponent,
  asset: string,
  scanId: string,
): UnifiedFinding {
  const vuln = component.vulnerabilityWithRemediation;
  const now = new Date().toISOString();
  const cveName = vuln.vulnerabilityName.startsWith('CVE-') ? vuln.vulnerabilityName : null;

  return {
    id: randomUUID(),
    tool: 'blackduck',
    severity: severityMap[vuln.severity.toUpperCase()] ?? 'info',
    cvss: vuln.baseScore,
    cve: cveName,
    cwe: vuln.cweId ?? null,
    title: cveName
      ? `${cveName} in ${component.componentName}@${component.componentVersionName}`
      : `${vuln.vulnerabilityName} in ${component.componentName}@${component.componentVersionName}`,
    asset,
    status: statusMap[vuln.remediationStatus?.toUpperCase()] ?? 'open',
    fixVersion: null,
    firstSeen: vuln.remediationCreatedAt ?? now,
    lastSeen: now,
    remediationSteps: buildRemediationSteps(component),
    references: buildReferences(component),
    evidence: {
      componentName: component.componentName,
      componentVersion: component.componentVersionName,
      vulnerabilityName: vuln.vulnerabilityName,
      description: vuln.description,
      remediationStatus: vuln.remediationStatus,
      href: component._meta.href,
    },
    scanId,
  };
}

function buildRemediationSteps(component: BlackDuckVulnerableComponent): string[] {
  const steps: string[] = [];
  const { componentName, componentVersionName } = component;
  const vuln = component.vulnerabilityWithRemediation;

  steps.push(`Review ${componentName}@${componentVersionName} and upgrade to a non-vulnerable version`);

  if (vuln.vulnerabilityName.startsWith('CVE-')) {
    steps.push(`Run: npm audit fix  # or equivalent for your package manager`);
    steps.push(`Verify fix: npm audit | grep ${vuln.vulnerabilityName}`);
  }

  const targetDate = vuln.targetRemediationDate;
  if (targetDate) {
    steps.push(`Remediation target: ${new Date(targetDate).toLocaleDateString('en-GB')}`);
  }

  return steps;
}

function buildReferences(component: BlackDuckVulnerableComponent): { label: string; url: string }[] {
  const refs: { label: string; url: string }[] = [];
  const vuln = component.vulnerabilityWithRemediation;

  if (vuln.vulnerabilityName.startsWith('CVE-')) {
    refs.push({ label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${vuln.vulnerabilityName}` });
  }
  if (component._meta.href) {
    refs.push({ label: 'BlackDuck Advisory', url: component._meta.href });
  }

  return refs;
}

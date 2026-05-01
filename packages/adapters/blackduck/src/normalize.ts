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
    asset,
    status: statusMap[vuln.remediationStatus?.toUpperCase()] ?? 'open',
    fixVersion: null,
    firstSeen: vuln.remediationCreatedAt ?? now,
    lastSeen: now,
    remediationSteps: buildRemediationSteps(component),
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

  steps.push(`Investigate ${componentName}@${componentVersionName} for a patched release`);
  steps.push(`Check the BlackDuck advisory for ${component.vulnerabilityWithRemediation.vulnerabilityName}`);

  const targetDate = component.vulnerabilityWithRemediation.targetRemediationDate;
  if (targetDate) {
    steps.push(`Remediation target date: ${new Date(targetDate).toLocaleDateString('en-GB')}`);
  }

  return steps;
}

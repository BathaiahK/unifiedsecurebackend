import { randomUUID } from 'crypto';
import type { UnifiedFinding } from '@usp/schema';
import type {
  TrivyMisconfiguration,
  TrivyResult,
  TrivySecret,
  TrivyVulnerability,
  EpssEntry,
} from './types.js';

export function normalizeContainerFindings(
  results: TrivyResult[],
  asset: string,
  scanId: string,
  epssMap?: Map<string, EpssEntry>,
  kevSet?: Set<string>,
): UnifiedFinding[] {
  const findings: UnifiedFinding[] = [];

  for (const result of results) {
    // Normalize vulnerabilities
    if (result.vulnerabilities) {
      for (const vuln of result.vulnerabilities) {
        let finding = normalizeVulnerability(vuln, asset, scanId, result.target);

        // Augment with EPSS data
        if (epssMap && vuln.vulnerabilityID) {
          const epssEntry = epssMap.get(vuln.vulnerabilityID);
          if (epssEntry) {
            finding.evidence = {
              ...finding.evidence,
              epss: epssEntry.epss,
              epssPercentile: epssEntry.percentile,
            };
          }
        }

        // Check KEV catalog
        if (kevSet && vuln.vulnerabilityID && kevSet.has(vuln.vulnerabilityID)) {
          finding.evidence = { ...finding.evidence, inKev: true };
          finding.title = `[KEV] ${finding.title}`;
          if (finding.severity !== 'critical') {
            finding.severity = 'critical';
          }
        }

        findings.push(finding);
      }
    }

    // Normalize misconfigurations
    if (result.misconfigurations) {
      for (const misc of result.misconfigurations) {
        findings.push(normalizeMisconfiguration(misc, asset, scanId));
      }
    }

    // Normalize secrets
    if (result.secrets) {
      for (const secret of result.secrets) {
        findings.push(normalizeSecret(secret, asset, scanId, result.target));
      }
    }
  }

  return findings;
}

function normalizeVulnerability(
  vuln: TrivyVulnerability,
  asset: string,
  scanId: string,
  target: string,
): UnifiedFinding {
  const severity = (vuln.severity || 'UNKNOWN').toLowerCase();
  const cvss = vuln.cvss?.nvd?.v3Score || vuln.cvss?.redhat?.v3Score || null;
  const cwe = vuln.cweIDs?.[0] || null;

  const severityMap: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    unknown: 'info',
    '': 'info',
  };

  return {
    id: randomUUID(),
    tool: 'container',
    severity: severityMap[severity] || 'info',
    cvss,
    cve: vuln.vulnerabilityID?.startsWith('CVE-') ? vuln.vulnerabilityID : null,
    cwe,
    title: `${vuln.vulnerabilityID} in ${vuln.pkgName}@${vuln.installedVersion}`,
    asset,
    status: 'open',
    fixVersion: vuln.fixedVersion || null,
    firstSeen: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    remediationSteps: buildRemediationSteps(vuln),
    references: buildReferences(vuln),
    evidence: {
      vulnerabilityID: vuln.vulnerabilityID,
      pkgName: vuln.pkgName,
      installedVersion: vuln.installedVersion,
      fixedVersion: vuln.fixedVersion,
      target,
      class: 'lang-pkgs',
      type: vuln.type,
      description: vuln.description,
      primaryURL: vuln.primaryURL,
      dataSource: vuln.dataSource,
      cvss: vuln.cvss,
      cweIDs: vuln.cweIDs,
    },
    scanId,
  };
}

function normalizeMisconfiguration(
  misc: TrivyMisconfiguration,
  asset: string,
  scanId: string,
): UnifiedFinding {
  const severity = (misc.severity || 'UNKNOWN').toLowerCase();

  const severityMap: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    unknown: 'info',
    '': 'info',
  };

  return {
    id: randomUUID(),
    tool: 'container',
    severity: severityMap[severity] || 'info',
    cvss: null,
    cve: null,
    cwe: null,
    title: `Config: ${misc.title}`,
    asset,
    status: 'open',
    fixVersion: null,
    firstSeen: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    remediationSteps: [
      misc.resolution || `Fix Dockerfile to address ${misc.id}: ${misc.title}`,
      'Rebuild and redeploy the container image',
    ],
    references: misc.references ? misc.references.map((url) => ({ label: 'Reference', url })) : [],
    evidence: {
      id: misc.id,
      type: misc.type,
      message: misc.message,
      resolution: misc.resolution,
      references: misc.references,
      startLine: misc.causeMetadata?.startLine,
      endLine: misc.causeMetadata?.endLine,
    },
    scanId,
  };
}

function normalizeSecret(
  secret: TrivySecret,
  asset: string,
  scanId: string,
  target: string,
): UnifiedFinding {
  // Mask the secret value for safety
  const maskedMatch = secret.match
    ? `${secret.match.slice(0, Math.min(4, secret.match.length))}${'*'.repeat(Math.max(4, secret.match.length - 4))}`
    : '***';

  return {
    id: randomUUID(),
    tool: 'container',
    severity: 'critical',
    cvss: null,
    cve: null,
    cwe: null,
    title: `Secret detected: ${secret.ruleID || secret.title || 'Sensitive data'} in ${target}`,
    asset,
    status: 'open',
    fixVersion: null,
    firstSeen: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    remediationSteps: [
      'Remove secret from Dockerfile and image layers',
      'Rotate the exposed credentials immediately',
      'Use Docker BuildKit secrets or environment injection at runtime instead',
      'Consider using a secrets management service (HashiCorp Vault, AWS Secrets Manager, etc.)',
    ],
    references: [],
    evidence: {
      ruleID: secret.ruleID,
      category: secret.category,
      title: secret.title,
      description: secret.description,
      match: maskedMatch,
      layer: secret.layer,
    },
    scanId,
  };
}

function buildRemediationSteps(vuln: TrivyVulnerability): string[] {
  const steps: string[] = [];

  if (vuln.fixedVersion) {
    steps.push(`Upgrade ${vuln.pkgName} from ${vuln.installedVersion} to ${vuln.fixedVersion}`);
  }

  if (vuln.primaryURL) {
    steps.push(`Review vulnerability details: ${vuln.primaryURL}`);
  }

  steps.push('Rebuild container image with updated package');
  steps.push('Test updated container in non-production environment first');
  steps.push('Deploy updated image to production');

  return steps;
}

function buildReferences(vuln: TrivyVulnerability): Array<{ label: string; url: string }> {
  const refs: Array<{ label: string; url: string }> = [];

  if (vuln.vulnerabilityID?.startsWith('CVE-')) {
    refs.push({
      label: 'NVD',
      url: `https://nvd.nist.gov/vuln/detail/${vuln.vulnerabilityID}`,
    });
  }

  if (vuln.primaryURL) {
    refs.push({
      label: 'Advisory',
      url: vuln.primaryURL,
    });
  }

  if (vuln.dataSource) {
    refs.push({
      label: vuln.dataSource.Name || 'Source',
      url: vuln.dataSource.URL || '#',
    });
  }

  return refs;
}

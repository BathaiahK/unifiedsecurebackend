import { randomUUID } from 'crypto';
import type { UnifiedFinding } from '@usp/schema';
import type { VulnMatch } from '@usp/vuln-db';

function severityFromCvss(cvss: number | null): UnifiedFinding['severity'] {
  if (cvss === null) return 'medium';
  if (cvss >= 9.0) return 'critical';
  if (cvss >= 7.0) return 'high';
  if (cvss >= 4.0) return 'medium';
  if (cvss > 0) return 'low';
  return 'info';
}

export function normalizeMatch(
  match: VulnMatch,
  asset: string,
  scanId: string,
): UnifiedFinding {
  const { advisory } = match;
  const now = new Date().toISOString();

  const remediationSteps: string[] = [];
  if (advisory.fixVersion) {
    remediationSteps.push(
      `Upgrade ${match.packageName} from ${match.version} to ${advisory.fixVersion}`,
    );
    if (match.ecosystem === 'npm') {
      remediationSteps.push(`Run: npm install ${match.packageName}@${advisory.fixVersion}`);
    } else if (match.ecosystem === 'PyPI') {
      remediationSteps.push(`Run: pip install ${match.packageName}==${advisory.fixVersion}`);
    } else if (match.ecosystem === 'Maven') {
      remediationSteps.push(`Update pom.xml to version ${advisory.fixVersion}`);
    } else if (match.ecosystem === 'Go') {
      remediationSteps.push(`Run: go get ${match.packageName}@v${advisory.fixVersion}`);
    }
  }
  for (const ref of advisory.references) {
    remediationSteps.push(`See advisory: ${ref}`);
  }

  const references: UnifiedFinding['references'] = advisory.references.map((url, i) => ({
    label: i === 0 ? 'Advisory' : 'Reference',
    url,
  }));

  return {
    id: randomUUID(),
    tool: 'sca',
    severity: severityFromCvss(advisory.cvss),
    cvss: advisory.cvss,
    cve: advisory.cve,
    cwe: advisory.cwes[0] ?? null,
    title: advisory.summary || `${advisory.id} affects ${match.packageName}@${match.version}`,
    asset,
    status: 'open',
    fixVersion: advisory.fixVersion,
    firstSeen: now,
    lastSeen: now,
    remediationSteps,
    references,
    evidence: {
      advisoryId: advisory.id,
      packageName: match.packageName,
      version: match.version,
      ecosystem: match.ecosystem,
      purl: match.purl,
      fixVersion: advisory.fixVersion,
      cvssVector: advisory.cvssVector,
      cwes: advisory.cwes,
      ranges: advisory.ranges,
    },
    scanId,
  };
}

import { randomUUID } from 'node:crypto';
import type { UnifiedFinding } from '@usp/schema';
import type { SonatypeComponent, OSSIndexVulnerability } from './client.js';

// ── Severity mapping (CVSS v3 score → UnifiedFinding severity) ─────────────────

function cvssToSeverity(score: number | null): UnifiedFinding['severity'] {
  if (score === null) return 'info';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'info';
}

// ── Component name/version from purl ─────────────────────────────────────────

function componentNameVersion(purl: string): { componentName: string; version: string } {
  // e.g. pkg:npm/lodash@4.17.20  or  pkg:maven/org.apache.struts/struts2-core@2.5.26
  const withoutPrefix = purl.replace(/^pkg:[^/]+\//, '');
  const atIdx = withoutPrefix.lastIndexOf('@');
  const rawName = atIdx === -1 ? withoutPrefix : withoutPrefix.slice(0, atIdx);
  const version = atIdx === -1 ? 'unknown' : withoutPrefix.slice(atIdx + 1);
  // For maven coords like "org.apache.struts/struts2-core" use the artifact id
  const slashIdx = rawName.indexOf('/');
  const componentName = slashIdx === -1 ? rawName : rawName.slice(slashIdx + 1);
  return { componentName, version };
}

// ── Remediation step builder ──────────────────────────────────────────────────

function buildRemediationSteps(
  component: SonatypeComponent,
  vuln: OSSIndexVulnerability,
): string[] {
  const steps: string[] = [];
  const { componentName, version } = componentNameVersion(component.coordinates);
  const { goldenVersion, ecosystem, isReachable, detectionType } = component;

  if (goldenVersion) {
    steps.push(
      `Upgrade ${componentName} from ${version} to ${goldenVersion} (Sonatype Golden Version — resolves all policy violations).`,
    );

    // Ecosystem-appropriate upgrade command
    if (ecosystem === 'npm') {
      steps.push(`Run: npm install ${componentName}@${goldenVersion}`);
    } else if (ecosystem === 'maven') {
      steps.push(
        `Update pom.xml or build.gradle: set ${componentName} version to ${goldenVersion}`,
      );
    } else if (ecosystem === 'pypi') {
      steps.push(`Run: pip install "${componentName}>=${goldenVersion}"`);
    } else if (ecosystem === 'deb') {
      steps.push(`Run: apt-get install --only-upgrade ${componentName}`);
    } else if (ecosystem === 'apk') {
      steps.push(`Run: apk upgrade ${componentName}`);
    } else {
      steps.push(`Update ${componentName} to ${goldenVersion} using your package manager.`);
    }
  } else {
    steps.push(`No golden version available — review ${componentName}@${version} manually.`);
    steps.push(`Check upstream advisories and consider an alternative dependency.`);
  }

  // Reachability context (JVM / static analysis only)
  if (isReachable === true) {
    steps.push(
      `Reachability analysis confirms the vulnerable code path IS called in this project — treat as actively exploitable.`,
    );
  } else if (isReachable === false) {
    steps.push(
      `Reachability analysis confirms the vulnerable code path is NOT called — risk is reduced but the dependency should still be upgraded.`,
    );
  }

  // Binary/container specific advice
  if (detectionType === 'binary') {
    steps.push(
      `This component was detected via binary analysis (not a lock-file entry). Locate the JAR/binary, identify how it is bundled, and replace it with the patched version.`,
    );
  } else if (detectionType === 'snippet') {
    steps.push(
      `This vulnerability was detected via code snippet matching — remove or update the copy-pasted source fragment.`,
    );
  }

  // Link to advisory
  if (vuln.reference) {
    steps.push(`See advisory: ${vuln.reference}`);
  }

  return steps;
}

// ── Reference list builder ─────────────────────────────────────────────────────

function buildReferences(
  vuln: OSSIndexVulnerability,
  component: SonatypeComponent,
): { label: string; url: string }[] {
  const refs: { label: string; url: string }[] = [];

  if (vuln.cve) {
    refs.push({ label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${vuln.cve}` });
  }

  refs.push({ label: 'OSS Index', url: vuln.reference });

  const firstExternal = vuln.externalReferences[0];
  if (firstExternal) {
    refs.push({ label: 'External Advisory', url: firstExternal });
  }

  refs.push({ label: 'Component page', url: component.reference });

  return refs;
}

// ── Main normalizer ────────────────────────────────────────────────────────────

/**
 * Convert a single (component, vulnerability) pair into a UnifiedFinding.
 * One component with N vulnerabilities produces N findings.
 */
export function normalizeComponent(
  component: SonatypeComponent,
  asset: string,
  scanId: string,
  vuln: OSSIndexVulnerability,
): UnifiedFinding {
  const now = new Date().toISOString();
  const { componentName, version } = componentNameVersion(component.coordinates);

  const title = vuln.cve
    ? `${vuln.cve} in ${componentName}@${version}`
    : `${vuln.displayName} in ${componentName}@${version}`;

  return {
    id: randomUUID(),
    tool: 'sonatype',
    severity: cvssToSeverity(vuln.cvssScore),
    cvss: vuln.cvssScore,
    cve: vuln.cve,
    cwe: vuln.cwe,
    title,
    asset,
    status: 'open',
    fixVersion: component.goldenVersion,
    firstSeen: now,
    lastSeen: now,
    remediationSteps: buildRemediationSteps(component, vuln),
    references: buildReferences(vuln, component),
    evidence: {
      coordinates: component.coordinates,
      ecosystem: component.ecosystem,
      detectionType: component.detectionType,
      licenseId: component.licenseId,
      licenseRisk: component.licenseRisk,
      goldenVersion: component.goldenVersion,
      isReachable: component.isReachable,
      qualityRisk: component.qualityRisk,
      supplyChainThreat: component.supplyChainThreat,
      vulnerabilityId: vuln.id,
      description: vuln.description,
      cvssVector: vuln.cvssVector,
      reference: component.reference,
    },
    scanId,
  };
}

/**
 * Produce a finding for a quality-risk component (abandoned / stale / low quality).
 * Returns null if the component has no quality risk data.
 */
export function normalizeQualityRisk(
  component: SonatypeComponent,
  asset: string,
  scanId: string,
): UnifiedFinding | null {
  if (!component.qualityRisk) return null;

  const now = new Date().toISOString();
  const { componentName, version } = componentNameVersion(component.coordinates);
  const qr = component.qualityRisk;

  const riskLabel = qr.isAbandoned ? 'abandoned' : `stale (${qr.daysStale ?? '?'} days)`;
  const title = `Quality risk: ${componentName}@${version} is ${riskLabel}`;

  const remediationSteps: string[] = [
    `Replace ${componentName}@${version} with an actively maintained alternative.`,
  ];
  if (qr.lastPublished) {
    remediationSteps.push(
      `Last published: ${new Date(qr.lastPublished).toLocaleDateString('en-GB')}. No new releases since then.`,
    );
  }
  if (qr.issueCount > 0) {
    remediationSteps.push(
      `${qr.issueCount} open issues with no recent maintainer activity — security vulnerabilities may go unpatched.`,
    );
  }
  if (component.licenseRisk === 'HIGH') {
    remediationSteps.push(
      `Licence ${component.licenseId ?? 'UNKNOWN'} is high-risk (copyleft) — obtain legal clearance or replace.`,
    );
  }

  return {
    id: randomUUID(),
    tool: 'sonatype',
    severity: 'info',
    cvss: null,
    cve: null,
    cwe: null,
    title,
    asset,
    status: 'open',
    fixVersion: null,
    firstSeen: now,
    lastSeen: now,
    remediationSteps,
    references: [{ label: 'OSS Index', url: component.reference }],
    evidence: {
      coordinates: component.coordinates,
      ecosystem: component.ecosystem,
      detectionType: component.detectionType,
      licenseId: component.licenseId,
      licenseRisk: component.licenseRisk,
      qualityRisk: qr,
    },
    scanId,
  };
}

/**
 * Produce a finding for a supply chain threat (typosquatting, malicious code, etc.).
 * Returns null if the component has no supply chain threat data.
 */
export function normalizeSupplyChainThreat(
  component: SonatypeComponent,
  asset: string,
  scanId: string,
): UnifiedFinding | null {
  if (!component.supplyChainThreat) return null;

  const now = new Date().toISOString();
  const { componentName, version } = componentNameVersion(component.coordinates);
  const threat = component.supplyChainThreat;

  const title = `Supply chain threat: ${componentName}@${version} — ${threat.type}`;
  const severity: UnifiedFinding['severity'] = threat.confidence === 'HIGH' ? 'high' : 'medium';

  const remediationSteps: string[] = [
    `${threat.description}`,
    `Remove or replace ${componentName}@${version} from the dependency tree.`,
    `Audit your lock file for any version ranges that could resolve to a compromised release.`,
    `Use pnpm/yarn/npm with lockfile integrity checks enabled.`,
  ];

  if (threat.type === 'typosquatting' || threat.type === 'dependency-confusion') {
    remediationSteps.push(
      `Verify the package origin on the registry — confirm the publisher matches the expected maintainer.`,
    );
  }

  if (threat.type === 'malicious-code' || threat.type === 'compromised') {
    remediationSteps.push(
      `Run a binary integrity check on the installed artifact (e.g. npm pack verification or Sigstore cosign).`,
    );
  }

  return {
    id: randomUUID(),
    tool: 'sonatype',
    severity,
    cvss: null,
    cve: null,
    cwe: null,
    title,
    asset,
    status: 'open',
    fixVersion: null,
    firstSeen: now,
    lastSeen: now,
    remediationSteps,
    references: [{ label: 'OSS Index', url: component.reference }],
    evidence: {
      coordinates: component.coordinates,
      ecosystem: component.ecosystem,
      detectionType: component.detectionType,
      licenseId: component.licenseId,
      licenseRisk: component.licenseRisk,
      supplyChainThreat: threat,
    },
    scanId,
  };
}

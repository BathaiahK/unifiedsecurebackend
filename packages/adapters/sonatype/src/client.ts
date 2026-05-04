// ── Sonatype OSS Index client ─────────────────────────────────────────────────
//
// OSS Index (https://ossindex.sonatype.org) is the free, public Sonatype API.
// It accepts PackageURL (purl) coordinates and returns vulnerability data from
// NVD, Sonatype's own research team, and community sources.
//
// Free-tier limits: 128 components per request, 64 requests/minute unauthenticated.
// Authenticated with username+token: 64 requests/minute with higher quotas.
//
// Real Nexus IQ (commercial) uses a different REST API but returns data in
// a compatible shape. This client models the free OSS Index API which any
// project can use without a Sonatype licence.
// ─────────────────────────────────────────────────────────────────────────────

export type SonatypeScanMode = 'dependency' | 'binary' | 'container';
export type DetectionType = 'dependency' | 'transitive' | 'binary' | 'snippet';
export type LicenseRisk = 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

// ── OSS Index wire types ──────────────────────────────────────────────────────

export interface OSSIndexVulnerability {
  /** CVE identifier (e.g. "CVE-2021-44228") or Sonatype-prefixed ID (e.g. "sonatype-2023-1234") */
  id: string;
  displayName: string;
  title: string;
  description: string;
  cvssScore: number | null;
  cvssVector: string | null;
  cwe: string | null;
  /** Canonical CVE identifier — null when Sonatype publishes ahead of NVD */
  cve: string | null;
  /** URL to the advisory page */
  reference: string;
  externalReferences: string[];
}

export interface OSSIndexComponent {
  /** PackageURL, e.g. "pkg:npm/lodash@4.17.20" */
  coordinates: string;
  description: string;
  /** URL to the OSS Index component page */
  reference: string;
  vulnerabilities: OSSIndexVulnerability[];
}

// ── Enriched types (not on OSS Index wire — added by our adapter) ──────────────

export interface QualityRisk {
  isAbandoned: boolean;
  lastPublished: string | null;
  daysStale: number | null;
  issueCount: number;
}

export interface SupplyChainThreat {
  type: 'typosquatting' | 'dependency-confusion' | 'malicious-code' | 'compromised';
  description: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface SonatypeComponent extends OSSIndexComponent {
  detectionType: DetectionType;
  licenseId: string | null;
  licenseRisk: LicenseRisk;
  /** Safest upgrade that resolves ALL policy violations without breaking changes */
  goldenVersion: string | null;
  /** Whether the vulnerable code path is actually called — JVM only, null = unknown */
  isReachable: boolean | null;
  qualityRisk: QualityRisk | null;
  supplyChainThreat: SupplyChainThreat | null;
  /** Ecosystem extracted from purl prefix, e.g. "npm", "maven", "pypi", "go" */
  ecosystem: string;
}

export interface ApplicationReport {
  scanMode: SonatypeScanMode;
  totalComponents: number;
  vulnerableComponents: number;
  policyViolations: number;
  licenseViolations: Array<{
    component: string;
    version: string;
    licenseId: string;
    risk: 'HIGH' | 'MEDIUM';
    reason: string;
  }>;
  qualityRisks: Array<{
    component: string;
    version: string;
    risk: 'abandoned' | 'stale' | 'no-tests' | 'high-issues';
    detail: string;
  }>;
  supplyChainThreats: Array<{
    component: string;
    version: string;
    threat: SupplyChainThreat;
  }>;
  goldenVersionsAvailable: number;
  topComponents: Array<{
    name: string;
    version: string;
    ecosystem: string;
    licenseId: string;
    licenseRisk: LicenseRisk;
    vulnerabilityCount: number;
    goldenVersion: string | null;
  }>;
}

// ── OSS Index HTTP client ─────────────────────────────────────────────────────

const OSS_INDEX_URL = 'https://ossindex.sonatype.org/api/v3/component-report';
const BATCH_SIZE = 128; // free-tier maximum per request

export interface OSSIndexConfig {
  username?: string;
  token?: string;
}

export class OSSIndexClient {
  private readonly authHeader: string | null;

  constructor(config: OSSIndexConfig) {
    if (config.username && config.token) {
      const encoded = Buffer.from(`${config.username}:${config.token}`).toString('base64');
      this.authHeader = `Basic ${encoded}`;
    } else {
      this.authHeader = null;
    }
  }

  /**
   * Evaluate a list of PackageURL coordinates against OSS Index.
   * Automatically batches into groups of BATCH_SIZE to respect the free-tier limit.
   */
  async evaluateComponents(purls: string[]): Promise<OSSIndexComponent[]> {
    if (purls.length === 0) return [];

    const results: OSSIndexComponent[] = [];

    for (let offset = 0; offset < purls.length; offset += BATCH_SIZE) {
      const batch = purls.slice(offset, offset + BATCH_SIZE);
      const batchResults = await this.fetchBatch(batch);
      results.push(...batchResults);
    }

    return results;
  }

  private async fetchBatch(purls: string[]): Promise<OSSIndexComponent[]> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };

    if (this.authHeader !== null) {
      headers['Authorization'] = this.authHeader;
    }

    const res = await fetch(OSS_INDEX_URL, {
      method: 'POST',
      headers,
      body: JSON.stringify({ coordinates: purls }),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`OSS Index API error ${res.status}: ${text}`);
    }

    // OSS Index returns an array of component reports directly
    return res.json() as Promise<OSSIndexComponent[]>;
  }
}

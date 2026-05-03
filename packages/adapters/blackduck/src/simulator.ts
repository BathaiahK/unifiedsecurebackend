import type {
  BlackDuckVulnerabilityPage,
  BlackDuckVulnerableComponent,
  BlackDuckBOMPage,
  BlackDuckBOMComponent,
  BOMSummary,
  ScanMode,
} from './client.js';

/**
 * Simulates the BlackDuck HTTP API without a real server.
 *
 * Scan modes mirror what BlackDuck actually runs:
 *  - package-manager  fastest — reads lock files, declared deps only
 *  - standard         + signature scanning (hash-based, finds undeclared deps)
 *  - full             + snippet + binary scanning, BDSA-only advisories
 *
 * BDSA (Black Duck Security Advisories) findings appear 2-3 weeks before NVD.
 * Detection type records HOW each vulnerability was found.
 * BOM includes all components (clean + vulnerable) with license risk.
 */
export class BlackDuckSimulator {
  private readonly scans = new Map<
    string,
    { startedAt: number; projectName: string; scanMode: ScanMode }
  >();

  async getProjectVersion(
    projectName: string,
  ): Promise<{ id: string; versionId: string } | null> {
    return { id: toHex(projectName + '-proj'), versionId: toHex(projectName + '-ver') };
  }

  async triggerScan(
    projectName: string,
    _versionName: string,
    scanMode: ScanMode = 'standard',
  ): Promise<{ location: string }> {
    const scanUrl = `sim://scans/${toHex(projectName + Date.now())}`;
    this.scans.set(scanUrl, { startedAt: Date.now(), projectName, scanMode });
    return { location: scanUrl };
  }

  async getScanStatus(
    scanUrl: string,
  ): Promise<{ status: string; percentComplete: number }> {
    const scan = this.scans.get(scanUrl);
    if (!scan) return { status: 'FAILED', percentComplete: 0 };

    const elapsed = Date.now() - scan.startedAt;
    // Full scan takes ~20s, standard ~15s, package-manager ~10s
    const duration =
      scan.scanMode === 'full' ? 20_000 :
      scan.scanMode === 'standard' ? 15_000 : 10_000;

    if (elapsed < duration * 0.2) return { status: 'RUNNING', percentComplete: 10 };
    if (elapsed < duration * 0.4) return { status: 'RUNNING', percentComplete: 35 };
    if (elapsed < duration * 0.6) return { status: 'RUNNING', percentComplete: 60 };
    if (elapsed < duration * 0.8) return { status: 'RUNNING', percentComplete: 80 };
    if (elapsed < duration)       return { status: 'RUNNING', percentComplete: 95 };
    return { status: 'COMPLETE', percentComplete: 100 };
  }

  async getVulnerabilities(
    _projectId: string,
    _versionId: string,
    scanMode: ScanMode = 'standard',
  ): Promise<BlackDuckVulnerabilityPage> {
    const items: BlackDuckVulnerableComponent[] = [
      ...PKG_MANAGER_VULNS,
      ...(scanMode !== 'package-manager' ? SIGNATURE_VULNS : []),
      ...(scanMode === 'full' ? SNIPPET_BINARY_VULNS : []),
      ...(scanMode === 'full' ? BDSA_ONLY_VULNS : []),
    ];
    return { totalCount: items.length, items };
  }

  async getComponentBOM(
    _projectId: string,
    _versionId: string,
    scanMode: ScanMode = 'standard',
  ): Promise<BlackDuckBOMPage> {
    const items: BlackDuckBOMComponent[] = [
      ...BASE_BOM_COMPONENTS,
      ...(scanMode !== 'package-manager' ? SIGNATURE_BOM_COMPONENTS : []),
      ...(scanMode === 'full' ? FULL_SCAN_BOM_COMPONENTS : []),
    ];
    return { totalCount: items.length, items };
  }

  buildBOMSummary(
    scanMode: ScanMode,
    bomPage: BlackDuckBOMPage,
    vulnPage: BlackDuckVulnerabilityPage,
  ): BOMSummary {
    const bdsaCount = vulnPage.items.filter((v) => v.advisorySource === 'bdsa').length;

    const licenseViolations: BOMSummary['licenseViolations'] = [];
    let high = 0, medium = 0, low = 0;

    const topComponents: BOMSummary['topComponents'] = bomPage.items.map((c) => {
      const lic = c.licenses[0];
      const spdx = lic?.spdxId ?? 'UNKNOWN';
      const risk = licenseRiskOf(spdx);

      if (risk === 'HIGH')   { high++;   licenseViolations.push({ component: c.componentName, version: c.componentVersionName, license: spdx, risk: 'HIGH' }); }
      if (risk === 'MEDIUM') { medium++; licenseViolations.push({ component: c.componentName, version: c.componentVersionName, license: spdx, risk: 'MEDIUM' }); }
      if (risk === 'LOW')    low++;

      return { name: c.componentName, version: c.componentVersionName, license: spdx, licenseRisk: risk };
    });

    return {
      scanMode,
      totalComponents: bomPage.totalCount,
      vulnerableComponents: vulnPage.totalCount,
      bdsaCount,
      licenseRisk: { high, medium, low },
      licenseViolations,
      topComponents,
    };
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function licenseRiskOf(spdx: string): 'HIGH' | 'MEDIUM' | 'LOW' {
  if (/^GPL/i.test(spdx) || /^AGPL/i.test(spdx))  return 'HIGH';
  if (/^LGPL/i.test(spdx) || /^EUPL/i.test(spdx)) return 'MEDIUM';
  return 'LOW';
}

function toHex(seed: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0') + '-' +
    (h ^ 0xdeadbeef).toString(16).padStart(4, '0') + '-4' +
    (h ^ 0xcafe).toString(16).padStart(3, '0') + '-a' +
    (h ^ 0xbabe).toString(16).padStart(3, '0') + '-' +
    (h ^ 0x12345678).toString(16).padStart(12, '0');
}

// ── Vulnerability datasets ────────────────────────────────────────────────────

// Package-manager mode: declared dependencies found via lock file parsing
const PKG_MANAGER_VULNS: BlackDuckVulnerableComponent[] = [
  {
    componentName: 'log4j-core', componentVersionName: '2.14.1',
    detectionType: 'package-manager', advisorySource: 'nvd',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2021-44228', severity: 'CRITICAL', baseScore: 10.0,
      description: 'Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP endpoints (Log4Shell).',
      remediationStatus: 'OPEN', cweId: 'CWE-917',
      targetRemediationDate: null, remediationCreatedAt: '2021-12-10T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2021-44228' },
  },
  {
    componentName: 'runc', componentVersionName: '1.1.5',
    detectionType: 'package-manager', advisorySource: 'nvd',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2024-21626', severity: 'HIGH', baseScore: 8.6,
      description: 'runc through 1.1.11 allows a container escape via a /proc/self/fd leak.',
      remediationStatus: 'OPEN', cweId: 'CWE-22',
      targetRemediationDate: null, remediationCreatedAt: '2024-01-31T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2024-21626' },
  },
  {
    componentName: 'nghttp2', componentVersionName: '1.52.0',
    detectionType: 'package-manager', advisorySource: 'nvd',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2023-44487', severity: 'HIGH', baseScore: 7.5,
      description: 'HTTP/2 Rapid Reset Attack allows denial of service via stream cancellation.',
      remediationStatus: 'NEEDS_REVIEW', cweId: 'CWE-400',
      targetRemediationDate: new Date(Date.now() + 14 * 86400_000).toISOString(),
      remediationCreatedAt: '2023-10-10T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2023-44487' },
  },
  {
    componentName: 'openssl', componentVersionName: '3.0.7',
    detectionType: 'package-manager', advisorySource: 'nvd',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2023-0286', severity: 'HIGH', baseScore: 7.4,
      description: 'Type confusion in X.400 address processing in X.509 GeneralName.',
      remediationStatus: 'OPEN', cweId: 'CWE-843',
      targetRemediationDate: null, remediationCreatedAt: '2023-02-08T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2023-0286' },
  },
  {
    componentName: 'tough-cookie', componentVersionName: '2.5.0',
    detectionType: 'package-manager', advisorySource: 'nvd',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2023-26136', severity: 'MEDIUM', baseScore: 5.3,
      description: 'Prototype pollution in tough-cookie when using CookieJar with rejectPublicSuffixes=false.',
      remediationStatus: 'OPEN', cweId: 'CWE-1321',
      targetRemediationDate: null, remediationCreatedAt: '2023-07-01T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2023-26136' },
  },
  {
    componentName: 'semver', componentVersionName: '5.7.1',
    detectionType: 'package-manager', advisorySource: 'nvd',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2022-25883', severity: 'MEDIUM', baseScore: 5.3,
      description: 'ReDoS via the function new Range in semver before 6.3.1.',
      remediationStatus: 'OPEN', cweId: 'CWE-1333',
      targetRemediationDate: null, remediationCreatedAt: '2023-06-21T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2022-25883' },
  },
  {
    componentName: 'axios', componentVersionName: '0.21.1',
    detectionType: 'package-manager', advisorySource: 'nvd',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2021-3749', severity: 'HIGH', baseScore: 7.5,
      description: 'Inefficient regular expression in axios trim function allows ReDoS.',
      remediationStatus: 'REMEDIATED', cweId: 'CWE-400',
      targetRemediationDate: null, remediationCreatedAt: '2021-08-31T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2021-3749' },
  },
  {
    componentName: 'lodash', componentVersionName: '4.17.15',
    detectionType: 'package-manager', advisorySource: 'nvd',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2021-23337', severity: 'HIGH', baseScore: 7.2,
      description: 'Lodash template function vulnerable to command injection.',
      remediationStatus: 'OPEN', cweId: 'CWE-77',
      targetRemediationDate: null, remediationCreatedAt: '2021-02-15T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2021-23337' },
  },
];

// Signature mode: undeclared/vendored deps found by matching file hashes against KB
const SIGNATURE_VULNS: BlackDuckVulnerableComponent[] = [
  {
    componentName: 'zlib', componentVersionName: '1.2.11',
    detectionType: 'signature', advisorySource: 'nvd',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2022-37434', severity: 'HIGH', baseScore: 9.8,
      description: 'zlib heap-based buffer overflow via a large gzip header in inflate and inflateBack (found via signature match — not in lock file).',
      remediationStatus: 'OPEN', cweId: 'CWE-787',
      targetRemediationDate: null, remediationCreatedAt: '2022-08-05T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2022-37434' },
  },
  {
    componentName: 'libexpat', componentVersionName: '2.4.1',
    detectionType: 'signature', advisorySource: 'nvd',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2022-25235', severity: 'HIGH', baseScore: 9.8,
      description: 'Expat XML parser stack overflow via a large number of colons in namespace-separator munging (vendored C library, found via KB hash match).',
      remediationStatus: 'OPEN', cweId: 'CWE-787',
      targetRemediationDate: null, remediationCreatedAt: '2022-02-16T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2022-25235' },
  },
  {
    // BDSA advisory — published 19 days before NVD assigned a CVE
    componentName: 'curl', componentVersionName: '7.88.0',
    detectionType: 'signature', advisorySource: 'bdsa',
    bdsaId: 'BDSA-2023-2038',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'BDSA-2023-2038', severity: 'HIGH', baseScore: 8.1,
      description: 'curl HSTS bypass via IDN host name — BDSA published 19 days before CVE-2023-46219 appeared in NVD. Signature-detected vendored binary.',
      remediationStatus: 'OPEN', cweId: 'CWE-311',
      targetRemediationDate: null, remediationCreatedAt: '2023-10-02T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/bdsa/BDSA-2023-2038' },
  },
];

// Full mode: snippet + binary analysis finds fragments and modified binaries
const SNIPPET_BINARY_VULNS: BlackDuckVulnerableComponent[] = [
  {
    // Snippet match: a copy-pasted function from vulnerable libpng landed in a custom renderer
    componentName: 'libpng (snippet)', componentVersionName: '1.6.37',
    detectionType: 'snippet', advisorySource: 'nvd',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2019-7317', severity: 'MEDIUM', baseScore: 5.3,
      description: 'libpng use-after-free in png_image_free — snippet of vulnerable code copy-pasted into src/renderer/image-utils.c (codeprint match, sliding-window algorithm).',
      remediationStatus: 'OPEN', cweId: 'CWE-416',
      targetRemediationDate: null, remediationCreatedAt: '2019-02-04T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2019-7317' },
  },
  {
    // Binary match: bundled native module with a modified but recognisable sqlite build
    componentName: 'sqlite3 (binary)', componentVersionName: '3.39.2',
    detectionType: 'binary', advisorySource: 'nvd',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2022-35737', severity: 'HIGH', baseScore: 7.5,
      description: 'SQLite 1.0.12 through 3.39.x NULL pointer deref in ARRAY_LENGTH — binary analysis matched a stripped native add-on (no source, no lock file entry).',
      remediationStatus: 'OPEN', cweId: 'CWE-476',
      targetRemediationDate: null, remediationCreatedAt: '2022-08-03T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2022-35737' },
  },
];

// BDSA-only findings: advisories published weeks before NVD (full scan only)
const BDSA_ONLY_VULNS: BlackDuckVulnerableComponent[] = [
  {
    componentName: 'openssl', componentVersionName: '3.1.3',
    detectionType: 'package-manager', advisorySource: 'bdsa',
    bdsaId: 'BDSA-2024-3891',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'BDSA-2024-3891', severity: 'HIGH', baseScore: 7.8,
      description: 'OpenSSL PKCS#12 decoding excessive iterations — BDSA-2024-3891 published 23 days before NVD assigned CVE-2024-12797. Affects 3.1.x builds with legacy provider.',
      remediationStatus: 'OPEN', cweId: 'CWE-400',
      targetRemediationDate: null, remediationCreatedAt: '2024-11-12T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/bdsa/BDSA-2024-3891' },
  },
  {
    componentName: 'go-stdlib', componentVersionName: '1.21.0',
    detectionType: 'signature', advisorySource: 'bdsa',
    bdsaId: 'BDSA-2024-0421',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'BDSA-2024-0421', severity: 'MEDIUM', baseScore: 6.5,
      description: 'Go net/http request smuggling via malformed chunked encoding — BDSA-2024-0421 published 18 days before CVE-2024-24790 in NVD. Signature-matched vendored Go runtime.',
      remediationStatus: 'NEEDS_REVIEW', cweId: 'CWE-444',
      targetRemediationDate: new Date(Date.now() + 21 * 86400_000).toISOString(),
      remediationCreatedAt: '2024-02-03T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/bdsa/BDSA-2024-0421' },
  },
];

// ── BOM datasets (all components, not just vulnerable) ────────────────────────

const BASE_BOM_COMPONENTS: BlackDuckBOMComponent[] = [
  { componentName: 'log4j-core',    componentVersionName: '2.14.1', licenses: [{ spdxId: 'Apache-2.0', licenseDisplay: 'Apache License 2.0', licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'REVIEWED' },
  { componentName: 'runc',          componentVersionName: '1.1.5',  licenses: [{ spdxId: 'Apache-2.0', licenseDisplay: 'Apache License 2.0', licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'REVIEWED' },
  { componentName: 'nghttp2',       componentVersionName: '1.52.0', licenses: [{ spdxId: 'MIT',        licenseDisplay: 'MIT License',         licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
  { componentName: 'openssl',       componentVersionName: '3.0.7',  licenses: [{ spdxId: 'Apache-2.0', licenseDisplay: 'Apache License 2.0', licenseType: 'OPEN_SOURCE' }], usages: ['STATICALLY_LINKED'], reviewStatus: 'REVIEWED' },
  { componentName: 'tough-cookie',  componentVersionName: '2.5.0',  licenses: [{ spdxId: 'BSD-3-Clause', licenseDisplay: 'BSD 3-Clause',     licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
  { componentName: 'semver',        componentVersionName: '5.7.1',  licenses: [{ spdxId: 'ISC',         licenseDisplay: 'ISC License',        licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'REVIEWED' },
  { componentName: 'axios',         componentVersionName: '0.21.1', licenses: [{ spdxId: 'MIT',         licenseDisplay: 'MIT License',        licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'REVIEWED' },
  { componentName: 'lodash',        componentVersionName: '4.17.15',licenses: [{ spdxId: 'MIT',         licenseDisplay: 'MIT License',        licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'REVIEWED' },
  { componentName: 'express',       componentVersionName: '4.18.2', licenses: [{ spdxId: 'MIT',         licenseDisplay: 'MIT License',        licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'REVIEWED' },
  { componentName: 'react',         componentVersionName: '18.2.0', licenses: [{ spdxId: 'MIT',         licenseDisplay: 'MIT License',        licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'REVIEWED' },
  { componentName: 'webpack',       componentVersionName: '5.88.0', licenses: [{ spdxId: 'MIT',         licenseDisplay: 'MIT License',        licenseType: 'OPEN_SOURCE' }], usages: ['DEV_TOOL'],           reviewStatus: 'REVIEWED' },
  { componentName: 'babel-core',    componentVersionName: '7.22.0', licenses: [{ spdxId: 'MIT',         licenseDisplay: 'MIT License',        licenseType: 'OPEN_SOURCE' }], usages: ['DEV_TOOL'],           reviewStatus: 'REVIEWED' },
  { componentName: 'moment',        componentVersionName: '2.29.4', licenses: [{ spdxId: 'MIT',         licenseDisplay: 'MIT License',        licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
  { componentName: 'uuid',          componentVersionName: '9.0.0',  licenses: [{ spdxId: 'MIT',         licenseDisplay: 'MIT License',        licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'REVIEWED' },
  { componentName: 'ffmpeg',        componentVersionName: '6.0',    licenses: [{ spdxId: 'LGPL-2.1-or-later', licenseDisplay: 'GNU LGPL 2.1+', licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
  { componentName: 'gstreamer',     componentVersionName: '1.22.0', licenses: [{ spdxId: 'LGPL-2.0-or-later', licenseDisplay: 'GNU LGPL 2.0+', licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
  { componentName: 'wkhtmltopdf',   componentVersionName: '0.12.6', licenses: [{ spdxId: 'LGPL-3.0-only',     licenseDisplay: 'GNU LGPL 3.0',   licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
  { componentName: 'mysql-client',  componentVersionName: '8.0.33', licenses: [{ spdxId: 'GPL-2.0-only',      licenseDisplay: 'GNU GPL 2.0',    licenseType: 'OPEN_SOURCE' }], usages: ['STATICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
];

const SIGNATURE_BOM_COMPONENTS: BlackDuckBOMComponent[] = [
  { componentName: 'zlib',          componentVersionName: '1.2.11', licenses: [{ spdxId: 'Zlib', licenseDisplay: 'zlib License', licenseType: 'OPEN_SOURCE' }], usages: ['STATICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
  { componentName: 'libexpat',      componentVersionName: '2.4.1',  licenses: [{ spdxId: 'MIT', licenseDisplay: 'MIT License',   licenseType: 'OPEN_SOURCE' }], usages: ['STATICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
  { componentName: 'curl',          componentVersionName: '7.88.0', licenses: [{ spdxId: 'curl', licenseDisplay: 'curl License', licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
  { componentName: 'libjpeg-turbo', componentVersionName: '2.1.5',  licenses: [{ spdxId: 'BSD-3-Clause', licenseDisplay: 'BSD 3-Clause', licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'REVIEWED' },
  { componentName: 'libpng',        componentVersionName: '1.6.40', licenses: [{ spdxId: 'libpng', licenseDisplay: 'libpng License', licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'REVIEWED' },
];

const FULL_SCAN_BOM_COMPONENTS: BlackDuckBOMComponent[] = [
  { componentName: 'libpng (snippet)', componentVersionName: '1.6.37', licenses: [{ spdxId: 'libpng', licenseDisplay: 'libpng License', licenseType: 'OPEN_SOURCE' }], usages: ['SOURCE_CODE'], reviewStatus: 'UNREVIEWED' },
  { componentName: 'sqlite3 (binary)', componentVersionName: '3.39.2', licenses: [{ spdxId: 'blessing', licenseDisplay: 'Public Domain / blessing', licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
  { componentName: 'openssl',          componentVersionName: '3.1.3',  licenses: [{ spdxId: 'Apache-2.0', licenseDisplay: 'Apache License 2.0', licenseType: 'OPEN_SOURCE' }], usages: ['STATICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
  { componentName: 'go-stdlib',        componentVersionName: '1.21.0', licenses: [{ spdxId: 'BSD-3-Clause', licenseDisplay: 'BSD 3-Clause', licenseType: 'OPEN_SOURCE' }], usages: ['STATICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
  { componentName: 'ffmpeg-gpl',       componentVersionName: '5.1.3',  licenses: [{ spdxId: 'GPL-2.0-or-later', licenseDisplay: 'GNU GPL 2.0+', licenseType: 'OPEN_SOURCE' }], usages: ['DYNAMICALLY_LINKED'], reviewStatus: 'UNREVIEWED' },
];

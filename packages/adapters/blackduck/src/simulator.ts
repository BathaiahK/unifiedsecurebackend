import type { BlackDuckVulnerabilityPage, BlackDuckVulnerableComponent } from './client.js';

/**
 * Simulates the BlackDuck HTTP API without a real server.
 * Activated automatically when BLACKDUCK_URL / BLACKDUCK_API_TOKEN are absent,
 * or when scan options contain { simulate: true }.
 *
 * Every step downstream of this class (normalize, NVD/OSV enrichment, MongoDB
 * storage, SSE streaming) is 100% real — only the "call the BlackDuck server"
 * part is replaced with pre-built response shapes that mirror the real API.
 */
export class BlackDuckSimulator {
  // Tracks simulated scan state: scanUrl → { startedAt, projectName }
  private readonly scans = new Map<string, { startedAt: number; projectName: string }>();

  async getProjectVersion(
    projectName: string,
  ): Promise<{ id: string; versionId: string } | null> {
    // Always find the project in simulation mode
    const id = toHex(projectName + '-proj');
    const versionId = toHex(projectName + '-ver');
    return { id, versionId };
  }

  async triggerScan(
    projectName: string,
    _versionName: string,
  ): Promise<{ location: string }> {
    const scanUrl = `sim://scans/${toHex(projectName + Date.now())}`;
    this.scans.set(scanUrl, { startedAt: Date.now(), projectName });
    return { location: scanUrl };
  }

  async getScanStatus(
    scanUrl: string,
  ): Promise<{ status: string; percentComplete: number }> {
    const scan = this.scans.get(scanUrl);
    if (!scan) return { status: 'FAILED', percentComplete: 0 };

    const elapsed = Date.now() - scan.startedAt;

    // Simulate a realistic scan duration: 15 seconds from trigger to complete
    if (elapsed < 3_000)  return { status: 'RUNNING', percentComplete: 10 };
    if (elapsed < 6_000)  return { status: 'RUNNING', percentComplete: 35 };
    if (elapsed < 9_000)  return { status: 'RUNNING', percentComplete: 60 };
    if (elapsed < 12_000) return { status: 'RUNNING', percentComplete: 80 };
    if (elapsed < 15_000) return { status: 'RUNNING', percentComplete: 95 };
    return { status: 'COMPLETE', percentComplete: 100 };
  }

  async getVulnerabilities(
    _projectId: string,
    _versionId: string,
  ): Promise<BlackDuckVulnerabilityPage> {
    return { totalCount: SIMULATED_VULNERABILITIES.length, items: SIMULATED_VULNERABILITIES };
  }
}

// ── Deterministic hex ID from a string seed ────────────────────────────────

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

// ── Realistic BlackDuck vulnerability payload ─────────────────────────────
// These are real CVEs with correct severity/CWE/CVSS data in BlackDuck's
// exact response shape. NVD and OSV will enrich them further with real data.

const SIMULATED_VULNERABILITIES: BlackDuckVulnerableComponent[] = [
  {
    componentName: 'log4j-core',
    componentVersionName: '2.14.1',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2021-44228',
      description:
        'Apache Log4j2 2.0-beta9 through 2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.',
      baseScore: 10.0,
      severity: 'CRITICAL',
      remediationStatus: 'OPEN',
      cweId: 'CWE-917',
      targetRemediationDate: null,
      remediationCreatedAt: '2021-12-10T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2021-44228' },
  },
  {
    componentName: 'runc',
    componentVersionName: '1.1.5',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2024-21626',
      description:
        'runc through 1.1.11 allows a container escape via a /proc/self/fd leak, as exploited in the wild in January 2024.',
      baseScore: 8.6,
      severity: 'HIGH',
      remediationStatus: 'OPEN',
      cweId: 'CWE-22',
      targetRemediationDate: null,
      remediationCreatedAt: '2024-01-31T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2024-21626' },
  },
  {
    componentName: 'nghttp2',
    componentVersionName: '1.52.0',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2023-44487',
      description:
        'The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.',
      baseScore: 7.5,
      severity: 'HIGH',
      remediationStatus: 'NEEDS_REVIEW',
      cweId: 'CWE-400',
      targetRemediationDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
      remediationCreatedAt: '2023-10-10T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2023-44487' },
  },
  {
    componentName: 'openssl',
    componentVersionName: '3.0.7',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2023-0286',
      description:
        'There is a type confusion vulnerability relating to X.400 address processing inside an X.509 GeneralName. X.400 addresses were parsed as an ASN1_STRING but the public structure definition for GENERAL_NAME incorrectly specified the type of the x400Address field as ASN1_TYPE.',
      baseScore: 7.4,
      severity: 'HIGH',
      remediationStatus: 'OPEN',
      cweId: 'CWE-843',
      targetRemediationDate: null,
      remediationCreatedAt: '2023-02-08T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2023-0286' },
  },
  {
    componentName: 'tough-cookie',
    componentVersionName: '2.5.0',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2023-26136',
      description:
        'Versions of the package tough-cookie before 4.1.3 are vulnerable to Prototype Pollution due to improper handling of Cookies when using CookieJar in rejectPublicSuffixes=false mode.',
      baseScore: 5.3,
      severity: 'MEDIUM',
      remediationStatus: 'OPEN',
      cweId: 'CWE-1321',
      targetRemediationDate: null,
      remediationCreatedAt: '2023-07-01T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2023-26136' },
  },
  {
    componentName: 'semver',
    componentVersionName: '5.7.1',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2022-25883',
      description:
        'Versions of the package semver before 6.3.1 are vulnerable to Regular Expression Denial of Service (ReDoS) via the function new Range.',
      baseScore: 5.3,
      severity: 'MEDIUM',
      remediationStatus: 'OPEN',
      cweId: 'CWE-1333',
      targetRemediationDate: null,
      remediationCreatedAt: '2023-06-21T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2022-25883' },
  },
  {
    componentName: 'axios',
    componentVersionName: '0.21.1',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2021-3749',
      description:
        'axios is vulnerable to Inefficient Regular Expression Complexity in the `trim` function, allowing attackers to trigger ReDoS.',
      baseScore: 7.5,
      severity: 'HIGH',
      remediationStatus: 'REMEDIATED',
      cweId: 'CWE-400',
      targetRemediationDate: null,
      remediationCreatedAt: '2021-08-31T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2021-3749' },
  },
  {
    componentName: 'lodash',
    componentVersionName: '4.17.15',
    vulnerabilityWithRemediation: {
      vulnerabilityName: 'CVE-2021-23337',
      description:
        'Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.',
      baseScore: 7.2,
      severity: 'HIGH',
      remediationStatus: 'OPEN',
      cweId: 'CWE-77',
      targetRemediationDate: null,
      remediationCreatedAt: '2021-02-15T00:00:00Z',
    },
    _meta: { href: 'https://blackduck.example.com/api/vulnerabilities/CVE-2021-23337' },
  },
];

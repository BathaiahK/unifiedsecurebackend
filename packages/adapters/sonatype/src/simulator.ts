// ── Sonatype Simulator ────────────────────────────────────────────────────────
//
// Mirrors what real Sonatype OSS Index / Nexus IQ returns across three scan
// modes. Each mode is a strict superset of the previous:
//
//   dependency  lock file parsing only  (10 npm components)
//   binary      + compiled artifact analysis (+ 3 maven/npm binaries)
//   container   + OS package layer scan (+ 3 deb/apk packages)
//
// The dataset intentionally covers every Sonatype feature:
//   - CVE vulnerabilities with CVSS scoring
//   - Golden version (safest upgrade)
//   - Reachability analysis (JVM only)
//   - Quality risk (abandoned / stale packages)
//   - Supply chain threats (malicious code injection)
//   - License compliance (GPL copyleft contamination)
//   - Mixed ecosystems: npm, maven, deb, apk
// ─────────────────────────────────────────────────────────────────────────────

import type {
  SonatypeScanMode,
  SonatypeComponent,
  OSSIndexVulnerability,
  ApplicationReport,
  LicenseRisk,
} from './client.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Extract "pkg:npm/lodash@4.17.20" → { name: "lodash", version: "4.17.20", ecosystem: "npm" } */
function parsePurl(purl: string): { name: string; version: string; ecosystem: string } {
  // e.g. pkg:npm/lodash@4.17.20  or  pkg:maven/org.apache.struts/struts2-core@2.5.26
  const withoutPrefix = purl.replace(/^pkg:/, '');
  const slashIdx = withoutPrefix.indexOf('/');
  const ecosystem = withoutPrefix.slice(0, slashIdx);
  const rest = withoutPrefix.slice(slashIdx + 1);
  const atIdx = rest.lastIndexOf('@');
  const name = atIdx === -1 ? rest : rest.slice(0, atIdx);
  const version = atIdx === -1 ? 'unknown' : rest.slice(atIdx + 1);
  return { name, version, ecosystem };
}

function licenseRiskOf(licenseId: string | null): LicenseRisk {
  if (!licenseId) return 'UNKNOWN';
  if (/^GPL/i.test(licenseId) || /^AGPL/i.test(licenseId)) return 'HIGH';
  if (/^LGPL/i.test(licenseId)) return 'MEDIUM';
  return 'LOW';
}

// ── Vulnerability helpers ─────────────────────────────────────────────────────

function mkVuln(
  id: string,
  displayName: string,
  title: string,
  description: string,
  cvssScore: number | null,
  cvssVector: string | null,
  cwe: string | null,
  reference: string,
  externalReferences: string[] = [],
): OSSIndexVulnerability {
  return {
    id,
    displayName,
    title,
    description,
    cvssScore,
    cvssVector,
    cwe,
    cve: id.startsWith('CVE-') ? id : null,
    reference,
    externalReferences,
  };
}

// ── Dependency-mode findings (lock-file scanning) ────────────────────────────

const DEPENDENCY_COMPONENTS: SonatypeComponent[] = [
  {
    coordinates: 'pkg:npm/lodash@4.17.20',
    description: 'Lodash modular utilities — a modern JavaScript utility library delivering modularity, performance, & extras.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/lodash@4.17.20',
    detectionType: 'dependency',
    licenseId: 'MIT',
    licenseRisk: 'LOW',
    goldenVersion: '4.17.21',
    isReachable: true,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [
      mkVuln(
        'CVE-2021-23337',
        'CVE-2021-23337',
        'Lodash Command Injection via template',
        'Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function due to use of Function with string concatenation.',
        7.2,
        'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
        'CWE-77',
        'https://ossindex.sonatype.org/vulnerability/CVE-2021-23337',
        ['https://nvd.nist.gov/vuln/detail/CVE-2021-23337', 'https://github.com/lodash/lodash/blob/master/CHANGELOG.md'],
      ),
    ],
  },

  {
    coordinates: 'pkg:npm/axios@0.21.1',
    description: 'Promise based HTTP client for the browser and node.js.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/axios@0.21.1',
    detectionType: 'dependency',
    licenseId: 'MIT',
    licenseRisk: 'LOW',
    goldenVersion: '0.21.4',
    isReachable: true,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [
      mkVuln(
        'CVE-2021-3749',
        'CVE-2021-3749',
        'Axios ReDoS via trim function',
        'axios is vulnerable to Inefficient Regular Expression Complexity in the trim function, allowing a ReDoS attack when processing large whitespace-padded strings.',
        7.5,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
        'CWE-400',
        'https://ossindex.sonatype.org/vulnerability/CVE-2021-3749',
        ['https://nvd.nist.gov/vuln/detail/CVE-2021-3749'],
      ),
    ],
  },

  {
    coordinates: 'pkg:npm/moment@2.29.3',
    description: 'Parse, validate, manipulate, and display dates.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/moment@2.29.3',
    detectionType: 'dependency',
    licenseId: 'MIT',
    licenseRisk: 'LOW',
    goldenVersion: '2.29.4',
    isReachable: false,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [
      mkVuln(
        'CVE-2022-24785',
        'CVE-2022-24785',
        'Moment.js Path Traversal',
        'Moment.js is vulnerable to Path Traversal when parsing the locale string provided in a moment.locale() call. A locale with a crafted name containing ../../ segments can overwrite arbitrary files. Note: reachability analysis indicates this code path is NOT called in this project.',
        7.5,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
        'CWE-22',
        'https://ossindex.sonatype.org/vulnerability/CVE-2022-24785',
        ['https://nvd.nist.gov/vuln/detail/CVE-2022-24785'],
      ),
    ],
  },

  {
    coordinates: 'pkg:npm/express@4.17.1',
    description: 'Fast, unopinionated, minimalist web framework for Node.js.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/express@4.17.1',
    detectionType: 'dependency',
    licenseId: 'MIT',
    licenseRisk: 'LOW',
    goldenVersion: '4.18.2',
    isReachable: true,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [
      mkVuln(
        'CVE-2022-24999',
        'CVE-2022-24999',
        'Express qs prototype pollution',
        'qs before 6.10.3 allows prototype pollution, which can cause DoS, property injection, or security bypass depending on application logic.',
        5.3,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
        'CWE-1321',
        'https://ossindex.sonatype.org/vulnerability/CVE-2022-24999',
        ['https://nvd.nist.gov/vuln/detail/CVE-2022-24999'],
      ),
    ],
  },

  {
    coordinates: 'pkg:npm/node-fetch@2.6.1',
    description: 'A light-weight module that brings window.fetch to Node.js.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/node-fetch@2.6.1',
    detectionType: 'dependency',
    licenseId: 'MIT',
    licenseRisk: 'LOW',
    goldenVersion: '2.6.7',
    isReachable: true,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [
      mkVuln(
        'CVE-2022-0235',
        'CVE-2022-0235',
        'node-fetch exposure of sensitive information via URL redirect',
        'node-fetch is vulnerable to Exposure of Sensitive Information to an Unauthorized Actor: when following a redirect, it forwards any credentials set in the Authorization header to the 3rd-party redirect destination.',
        8.8,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N',
        'CWE-601',
        'https://ossindex.sonatype.org/vulnerability/CVE-2022-0235',
        ['https://nvd.nist.gov/vuln/detail/CVE-2022-0235'],
      ),
    ],
  },

  {
    coordinates: 'pkg:npm/semver@5.7.1',
    description: 'The semantic versioner for npm.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/semver@5.7.1',
    detectionType: 'dependency',
    licenseId: 'ISC',
    licenseRisk: 'LOW',
    goldenVersion: '5.7.2',
    isReachable: null,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [
      mkVuln(
        'CVE-2022-25883',
        'CVE-2022-25883',
        'semver ReDoS via new Range',
        'Versions of the package semver before 6.3.1 are vulnerable to Regular Expression Denial of Service (ReDoS) via the function new Range, when untrusted user data is provided as a range.',
        5.3,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
        'CWE-1333',
        'https://ossindex.sonatype.org/vulnerability/CVE-2022-25883',
        ['https://nvd.nist.gov/vuln/detail/CVE-2022-25883'],
      ),
    ],
  },

  {
    coordinates: 'pkg:npm/tough-cookie@2.5.0',
    description: 'RFC6265 Cookies and CookieJar for Node.js.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/tough-cookie@2.5.0',
    detectionType: 'dependency',
    licenseId: 'BSD-3-Clause',
    licenseRisk: 'LOW',
    goldenVersion: '4.1.3',
    isReachable: null,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [
      mkVuln(
        'CVE-2023-26136',
        'CVE-2023-26136',
        'tough-cookie prototype pollution',
        'Versions of the package tough-cookie before 4.1.3 are vulnerable to Prototype Pollution due to improper handling of Cookies when using CookieJar in rejectPublicSuffixes=false mode.',
        5.3,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
        'CWE-1321',
        'https://ossindex.sonatype.org/vulnerability/CVE-2023-26136',
        ['https://nvd.nist.gov/vuln/detail/CVE-2023-26136'],
      ),
    ],
  },

  {
    coordinates: 'pkg:npm/qs@6.5.2',
    description: 'A querystring parser and stringifier with some added security.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/qs@6.5.2',
    detectionType: 'dependency',
    licenseId: 'BSD-3-Clause',
    licenseRisk: 'LOW',
    goldenVersion: '6.11.0',
    isReachable: true,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [
      mkVuln(
        'CVE-2022-24999',
        'CVE-2022-24999',
        'qs prototype pollution',
        'qs before 6.10.3 is vulnerable to Prototype Pollution leading to denial of service, property injection or remote code execution depending on how the output is used.',
        7.5,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H',
        'CWE-1321',
        'https://ossindex.sonatype.org/vulnerability/CVE-2022-24999-qs',
        ['https://nvd.nist.gov/vuln/detail/CVE-2022-24999'],
      ),
    ],
  },

  {
    // Quality risk only — no CVE. Abandoned package with a copyleft licence.
    coordinates: 'pkg:npm/mysql2@2.3.3',
    description: 'fast mysql driver. Implements core protocol, prepared statements, ssl and compression in native JS.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/mysql2@2.3.3',
    detectionType: 'dependency',
    licenseId: 'GPL-2.0-only',
    licenseRisk: 'HIGH',
    goldenVersion: null,
    isReachable: null,
    qualityRisk: {
      isAbandoned: true,
      lastPublished: '2021-11-30T00:00:00Z',
      daysStale: 847,
      issueCount: 143,
    },
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [],
  },

  {
    // Supply chain threat only — no CVE. Historical backdoor injection in a related version.
    coordinates: 'pkg:npm/event-stream@3.3.4',
    description: 'construct pipes of streams of events.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/event-stream@3.3.4',
    detectionType: 'dependency',
    licenseId: 'MIT',
    licenseRisk: 'LOW',
    goldenVersion: null,
    isReachable: null,
    qualityRisk: null,
    supplyChainThreat: {
      type: 'malicious-code',
      description:
        'Historical backdoor injection in event-stream v3.3.6 — dependency confusion risk on similar version ranges. The package was compromised via a maintainer handoff attack in 2018; consumers pinning ~3.3.x may inadvertently pull the backdoored version if lock files are regenerated.',
      confidence: 'HIGH',
    },
    ecosystem: 'npm',
    vulnerabilities: [],
  },
];

// ── Binary-mode findings (compiled artifact analysis) ────────────────────────

const BINARY_COMPONENTS: SonatypeComponent[] = [
  {
    coordinates: 'pkg:maven/org.apache.struts/struts2-core@2.5.26',
    description: 'Apache Struts 2 — a popular MVC framework for creating enterprise-ready Java web applications.',
    reference: 'https://ossindex.sonatype.org/component/pkg:maven/org.apache.struts/struts2-core@2.5.26',
    detectionType: 'binary',
    licenseId: 'Apache-2.0',
    licenseRisk: 'LOW',
    goldenVersion: '2.5.33',
    isReachable: true,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'maven',
    vulnerabilities: [
      mkVuln(
        'CVE-2023-50164',
        'CVE-2023-50164',
        'Apache Struts 2 path traversal / RCE',
        'An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to uploading a malicious file which can be used to perform Remote Code Execution. Detected via binary JAR hash matching — struts2-core-2.5.26.jar in lib/.',
        9.8,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'CWE-22',
        'https://ossindex.sonatype.org/vulnerability/CVE-2023-50164',
        ['https://nvd.nist.gov/vuln/detail/CVE-2023-50164', 'https://lists.apache.org/thread/yh09b3fkf6vz5d6jdgrlvmg60lfwtqhj'],
      ),
    ],
  },

  {
    coordinates: 'pkg:maven/commons-text/commons-text@1.9',
    description: 'Apache Commons Text — a library focused on algorithms working on strings.',
    reference: 'https://ossindex.sonatype.org/component/pkg:maven/commons-text/commons-text@1.9',
    detectionType: 'binary',
    licenseId: 'Apache-2.0',
    licenseRisk: 'LOW',
    goldenVersion: '1.10.0',
    isReachable: true,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'maven',
    vulnerabilities: [
      mkVuln(
        'CVE-2022-42889',
        'CVE-2022-42889',
        'Text4Shell — Apache Commons Text RCE via StringSubstitutor',
        'Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The StringSubstitutor API evaluates interpolators including "script", "dns", "url", enabling RCE (Text4Shell). Detected via binary analysis of commons-text-1.9.jar.',
        9.8,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'CWE-94',
        'https://ossindex.sonatype.org/vulnerability/CVE-2022-42889',
        ['https://nvd.nist.gov/vuln/detail/CVE-2022-42889', 'https://seclists.org/oss-sec/2022/q4/22'],
      ),
    ],
  },

  {
    coordinates: 'pkg:npm/minimist@1.2.5',
    description: 'parse argument options — minimalist argument option parser.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/minimist@1.2.5',
    detectionType: 'binary',
    licenseId: 'MIT',
    licenseRisk: 'LOW',
    goldenVersion: '1.2.6',
    isReachable: null,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [
      mkVuln(
        'sonatype-2022-6438',
        'sonatype-2022-6438',
        'minimist prototype pollution (Sonatype research)',
        'minimist prior to 1.2.6 is vulnerable to prototype pollution when parsing crafted argument strings. Sonatype researchers published this advisory ahead of NVD assignment. Found in bundled CLI binary.',
        5.6,
        'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L',
        'CWE-1321',
        'https://ossindex.sonatype.org/vulnerability/sonatype-2022-6438',
        ['https://github.com/substack/minimist/issues/164'],
      ),
    ],
  },
];

// ── Container-mode findings (OS package layer scan) ──────────────────────────

const CONTAINER_COMPONENTS: SonatypeComponent[] = [
  {
    coordinates: 'pkg:deb/debian/libc6@2.31',
    description: 'GNU C Library: Shared libraries — contains the standard C library and the standard math library.',
    reference: 'https://ossindex.sonatype.org/component/pkg:deb/debian/libc6@2.31',
    detectionType: 'binary',
    licenseId: 'LGPL-2.1-only',
    licenseRisk: 'MEDIUM',
    goldenVersion: '2.33',
    isReachable: null,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'deb',
    vulnerabilities: [
      mkVuln(
        'CVE-2021-33574',
        'CVE-2021-33574',
        'glibc mq_notify use-after-free',
        'The mq_notify function in the GNU C Library (glibc) 2.32 and 2.33 has a use-after-free. It may use the notification thread attributes object (passed through its struct sigevent parameter) after it has been freed by the caller, leading to a denial of service or potential privilege escalation. Detected in Debian Bullseye base layer.',
        9.8,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'CWE-416',
        'https://ossindex.sonatype.org/vulnerability/CVE-2021-33574',
        ['https://nvd.nist.gov/vuln/detail/CVE-2021-33574'],
      ),
    ],
  },

  {
    coordinates: 'pkg:deb/debian/openssl@1.1.1n',
    description: 'Secure Sockets Layer toolkit — runtime library.',
    reference: 'https://ossindex.sonatype.org/component/pkg:deb/debian/openssl@1.1.1n',
    detectionType: 'binary',
    licenseId: 'OpenSSL',
    licenseRisk: 'LOW',
    goldenVersion: '1.1.1o',
    isReachable: null,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'deb',
    vulnerabilities: [
      mkVuln(
        'CVE-2022-0778',
        'CVE-2022-0778',
        'OpenSSL infinite loop in BN_mod_sqrt()',
        'The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys. This allows an attacker to craft a certificate that hangs the parser, causing DoS. Detected in container OS layer.',
        7.5,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
        'CWE-835',
        'https://ossindex.sonatype.org/vulnerability/CVE-2022-0778',
        ['https://nvd.nist.gov/vuln/detail/CVE-2022-0778', 'https://www.openssl.org/news/secadv/20220315.txt'],
      ),
    ],
  },

  {
    coordinates: 'pkg:apk/alpine/busybox@1.34.1',
    description: 'Size optimized toolbox of many common UNIX utilities (Alpine layer).',
    reference: 'https://ossindex.sonatype.org/component/pkg:apk/alpine/busybox@1.34.1',
    detectionType: 'binary',
    licenseId: 'GPL-2.0-only',
    licenseRisk: 'HIGH',
    goldenVersion: '1.35.0',
    isReachable: null,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'apk',
    vulnerabilities: [
      mkVuln(
        'CVE-2022-28391',
        'CVE-2022-28391',
        'BusyBox netstat information disclosure',
        "BusyBox through 1.35.0 allows remote attackers to execute arbitrary code if netd, the ntpd, or the ftpd is running without a -w argument, or there is a POSIX shell. This is due to mishandling of the CLIENTIP environment variable in the shell's SETPRIV action.",
        6.1,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        'CWE-78',
        'https://ossindex.sonatype.org/vulnerability/CVE-2022-28391',
        ['https://nvd.nist.gov/vuln/detail/CVE-2022-28391'],
      ),
    ],
  },
];

// ── Clean (non-vulnerable) components for the application report BOM ─────────

const CLEAN_COMPONENTS: SonatypeComponent[] = [
  {
    coordinates: 'pkg:npm/react@18.2.0',
    description: 'React is a JavaScript library for building user interfaces.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/react@18.2.0',
    detectionType: 'dependency',
    licenseId: 'MIT',
    licenseRisk: 'LOW',
    goldenVersion: null,
    isReachable: null,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [],
  },
  {
    coordinates: 'pkg:npm/webpack@5.88.0',
    description: 'A bundler for javascript and friends.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/webpack@5.88.0',
    detectionType: 'dependency',
    licenseId: 'MIT',
    licenseRisk: 'LOW',
    goldenVersion: null,
    isReachable: null,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [],
  },
  {
    coordinates: 'pkg:npm/typescript@5.0.4',
    description: 'TypeScript extends JavaScript by adding types to the language.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/typescript@5.0.4',
    detectionType: 'dependency',
    licenseId: 'Apache-2.0',
    licenseRisk: 'LOW',
    goldenVersion: null,
    isReachable: null,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [],
  },
  {
    coordinates: 'pkg:npm/prisma@5.0.0',
    description: 'Prisma is a next-generation ORM.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/prisma@5.0.0',
    detectionType: 'dependency',
    licenseId: 'Apache-2.0',
    licenseRisk: 'LOW',
    goldenVersion: null,
    isReachable: null,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [],
  },
  {
    coordinates: 'pkg:npm/fastify@4.23.0',
    description: 'Fast and low overhead web framework, for Node.js.',
    reference: 'https://ossindex.sonatype.org/component/pkg:npm/fastify@4.23.0',
    detectionType: 'dependency',
    licenseId: 'MIT',
    licenseRisk: 'LOW',
    goldenVersion: null,
    isReachable: null,
    qualityRisk: null,
    supplyChainThreat: null,
    ecosystem: 'npm',
    vulnerabilities: [],
  },
];

// ── Simulator class ───────────────────────────────────────────────────────────

export class SonatypeSimulator {
  /**
   * Returns simulated SonatypeComponent[] for the given scan mode.
   * Each mode is a strict superset of the previous.
   *
   * @param _purls   Ignored in simulation — we return our hardcoded dataset.
   * @param scanMode Controls how many components (and detectionTypes) are returned.
   */
  evaluateComponents(
    _purls: string[],
    scanMode: SonatypeScanMode,
  ): Promise<SonatypeComponent[]> {
    const components: SonatypeComponent[] = [...DEPENDENCY_COMPONENTS];

    if (scanMode === 'binary' || scanMode === 'container') {
      components.push(...BINARY_COMPONENTS);
    }

    if (scanMode === 'container') {
      components.push(...CONTAINER_COMPONENTS);
    }

    return Promise.resolve(components);
  }

  /**
   * Build a high-level ApplicationReport summarising the scan.
   * Counts are derived directly from the component list so they are always
   * consistent with what normalize() produces.
   */
  buildApplicationReport(
    scanMode: SonatypeScanMode,
    components: SonatypeComponent[],
  ): ApplicationReport {
    const allComponents = [...components, ...CLEAN_COMPONENTS];
    const totalComponents = allComponents.length;

    const vulnerableComponents = components.filter(
      (c) => c.vulnerabilities.length > 0,
    ).length;

    // Every vulnerability is a policy violation in this context
    const policyViolations = components.reduce(
      (sum, c) => sum + c.vulnerabilities.length,
      0,
    );

    // License violations: GPL = HIGH risk, LGPL = MEDIUM risk
    const licenseViolations: ApplicationReport['licenseViolations'] = [];
    for (const c of allComponents) {
      if (!c.licenseId) continue;
      const risk = licenseRiskOf(c.licenseId);
      if (risk !== 'HIGH' && risk !== 'MEDIUM') continue;

      const { name, version } = parsePurl(c.coordinates);
      const reason =
        risk === 'HIGH'
          ? `${c.licenseId} is a copyleft licence that may require disclosure of proprietary source code.`
          : `${c.licenseId} is a weak copyleft licence — dynamic linking may trigger disclosure obligations.`;

      licenseViolations.push({ component: name, version, licenseId: c.licenseId, risk, reason });
    }

    // Quality risks
    const qualityRisks: ApplicationReport['qualityRisks'] = [];
    for (const c of components) {
      if (!c.qualityRisk) continue;
      const { name, version } = parsePurl(c.coordinates);
      const qr = c.qualityRisk;

      if (qr.isAbandoned) {
        qualityRisks.push({
          component: name,
          version,
          risk: 'abandoned',
          detail: `No releases in ${qr.daysStale ?? '?'} days (last: ${qr.lastPublished ?? 'unknown'}). ${qr.issueCount} open issues with no maintainer activity.`,
        });
      } else if (qr.daysStale !== null && qr.daysStale > 180) {
        qualityRisks.push({
          component: name,
          version,
          risk: 'stale',
          detail: `${qr.daysStale} days since last release. ${qr.issueCount} open issues.`,
        });
      }
    }

    // Supply chain threats
    const supplyChainThreats: ApplicationReport['supplyChainThreats'] = [];
    for (const c of components) {
      if (!c.supplyChainThreat) continue;
      const { name, version } = parsePurl(c.coordinates);
      supplyChainThreats.push({ component: name, version, threat: c.supplyChainThreat });
    }

    // Golden versions available
    const goldenVersionsAvailable = components.filter(
      (c) => c.goldenVersion !== null && c.vulnerabilities.length > 0,
    ).length;

    // Top components (all, including clean)
    const topComponents: ApplicationReport['topComponents'] = allComponents.map((c) => {
      const { name, version } = parsePurl(c.coordinates);
      return {
        name,
        version,
        ecosystem: c.ecosystem,
        licenseId: c.licenseId ?? 'UNKNOWN',
        licenseRisk: c.licenseRisk,
        vulnerabilityCount: c.vulnerabilities.length,
        goldenVersion: c.goldenVersion,
      };
    });

    return {
      scanMode,
      totalComponents,
      vulnerableComponents,
      policyViolations,
      licenseViolations,
      qualityRisks,
      supplyChainThreats,
      goldenVersionsAvailable,
      topComponents,
    };
  }
}

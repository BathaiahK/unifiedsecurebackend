import { PrismaClient } from '@prisma/client';
import { randomUUID } from 'node:crypto';

const prisma = new PrismaClient();

const now       = new Date();
const daysAgo   = (d: number) => new Date(now.getTime() - d * 86_400_000);
const monthsAgo = (m: number) => new Date(now.getFullYear(), now.getMonth() - m, 1);

const SCAN = {
  bdPayment:  randomUUID(),
  sysPayment: randomUUID(),
  crunchApi:  randomUUID(),
  dastApi:    randomUUID(),
  snAuth:     randomUUID(),
  snPayment:  randomUUID(),
};

async function main() {
  console.log('🌱 Seeding database…');

  // ── Wipe (raw MongoDB delete avoids replica-set requirement) ──────────────
  await prisma.$runCommandRaw({ delete: 'Finding',        deletes: [{ q: {}, limit: 0 }] });
  await prisma.$runCommandRaw({ delete: 'Scan',           deletes: [{ q: {}, limit: 0 }] });
  await prisma.$runCommandRaw({ delete: 'ReportDownload', deletes: [{ q: {}, limit: 0 }] });
  console.log('  Cleared existing data');

  // ── Scans (individual creates — no transaction needed) ────────────────────
  const scans = [
    { id: SCAN.bdPayment,  tool: 'blackduck',  asset: 'payment-service', status: 'complete', startedAt: daysAgo(0), completedAt: new Date(now.getTime() - 45 * 60_000), critical: 2, high: 3, medium: 2, passedGate: false },
    { id: SCAN.sysPayment, tool: 'sysdig',     asset: 'payment-service', status: 'complete', startedAt: daysAgo(0), completedAt: new Date(now.getTime() - 20 * 60_000), critical: 1, high: 0, medium: 0, passedGate: false },
    { id: SCAN.crunchApi,  tool: '42crunch',   asset: 'api-gateway',     status: 'complete', startedAt: daysAgo(0), completedAt: new Date(now.getTime() - 10 * 60_000), critical: 0, high: 2, medium: 1, passedGate: true  },
    { id: SCAN.dastApi,    tool: 'dast',       asset: 'api-gateway',     status: 'complete', startedAt: daysAgo(1), completedAt: new Date(daysAgo(1).getTime() + 12 * 60_000), critical: 0, high: 1, medium: 0, passedGate: false },
    { id: SCAN.snAuth,     tool: 'sonatype',   asset: 'auth-service',    status: 'complete', startedAt: daysAgo(1), completedAt: new Date(daysAgo(1).getTime() + 8  * 60_000), critical: 1, high: 1, medium: 1, passedGate: false },
    { id: SCAN.snPayment,  tool: 'sonatype',   asset: 'payment-service', status: 'running',  startedAt: new Date(now.getTime() - 3 * 60_000), completedAt: null, critical: null, high: null, medium: null, passedGate: null },
  ];
  for (const s of scans) await prisma.scan.create({ data: s });
  console.log(`  Created ${scans.length} scans`);

  // ── Findings ──────────────────────────────────────────────────────────────
  const findings = [
    {
      id: randomUUID(), tool: 'sysdig', severity: 'critical', cvss: 8.6,
      cve: 'CVE-2024-21626', cwe: 'CWE-22',
      title: 'runc container escape via /proc/self/fd',
      asset: 'payment-service', status: 'open', fixVersion: 'runc 1.1.12',
      firstSeen: daysAgo(5), lastSeen: daysAgo(0), scanId: SCAN.sysPayment,
      remediationSteps: [
        'Update runc to version 1.1.12 or later',
        'Run: apt-get update && apt-get install runc=1.1.12',
        'Restart all containers after upgrading the runtime',
        'Run: runc --version  # should show 1.1.12+',
      ],
      references: [
        { label: 'NVD', url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21626' },
        { label: 'GitHub Advisory', url: 'https://github.com/advisories/GHSA-xr7r-f8xq-vfvv' },
      ],
      evidence: { image: 'runc:1.1.5', type: 'container-escape' },
    },
    {
      id: randomUUID(), tool: 'dast', severity: 'high', cvss: 7.2,
      cve: null, cwe: 'CWE-79',
      title: 'Reflected XSS on /api/search',
      asset: 'api-gateway', status: 'open', fixVersion: null,
      firstSeen: daysAgo(3), lastSeen: daysAgo(1), scanId: SCAN.dastApi,
      remediationSteps: [
        'Sanitize the "q" query parameter before reflecting it in responses',
        "Apply Content-Security-Policy header: default-src 'self'",
        'Use DOMPurify for any client-side rendering of user input',
        'Run: npm install dompurify',
      ],
      references: [{ label: 'OWASP XSS', url: 'https://owasp.org/www-community/attacks/xss/' }],
      evidence: { endpoint: '/api/search', parameter: 'q', confidence: 'High' },
    },
    {
      id: randomUUID(), tool: '42crunch', severity: 'high', cvss: 7.5,
      cve: null, cwe: 'CWE-285',
      title: 'No auth on DELETE /users/{id}',
      asset: 'api-gateway', status: 'open', fixVersion: null,
      firstSeen: daysAgo(4), lastSeen: daysAgo(0), scanId: SCAN.crunchApi,
      remediationSteps: [
        'Add Bearer token authorization to DELETE /users/{id} in OpenAPI spec',
        'Enforce object-level authorization — verify caller owns the resource',
        'Add securityScheme to the operation in openapi.yaml',
        'Run: npx @42crunch/api-security-audit --min-score 75',
      ],
      references: [{ label: 'OWASP API A1', url: 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/' }],
      evidence: { endpoint: 'DELETE /users/{id}', issue: 'Missing authorization', owaspApi: 'A1' },
    },
    {
      id: randomUUID(), tool: 'blackduck', severity: 'critical', cvss: 7.5,
      cve: 'CVE-2023-44487', cwe: 'CWE-400',
      title: 'HTTP/2 Rapid Reset Attack in nghttp2',
      asset: 'api-gateway', status: 'in_progress', fixVersion: 'nghttp2 1.57.0',
      firstSeen: daysAgo(6), lastSeen: daysAgo(0), scanId: SCAN.bdPayment,
      remediationSteps: [
        'Upgrade nghttp2 to 1.57.0 or later',
        'Run: apt-get install libnghttp2-14=1.57.0',
        'Apply rate limiting to HTTP/2 RESET_STREAM frames',
      ],
      references: [
        { label: 'NVD', url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-44487' },
        { label: 'GitHub Advisory', url: 'https://github.com/advisories/GHSA-qppj-fm56-jmg0' },
      ],
      evidence: { component: 'nghttp2:1.52.0', ecosystem: 'deb' },
    },
    {
      id: randomUUID(), tool: 'sonatype', severity: 'critical', cvss: 9.8,
      cve: null, cwe: null,
      title: 'Malicious package: event-stream@3.3.6',
      asset: 'payment-service', status: 'open', fixVersion: 'event-stream@3.3.4',
      firstSeen: daysAgo(2), lastSeen: daysAgo(1), scanId: SCAN.snAuth,
      remediationSteps: [
        'Remove event-stream@3.3.6 immediately — it contains malicious code',
        'Run: npm uninstall event-stream',
        'Run: npm install event-stream@3.3.4',
        'Audit all transitive dependencies pulling in event-stream',
      ],
      references: [
        { label: 'NPM Advisory', url: 'https://www.npmjs.com/advisories/737' },
        { label: 'Sonatype OSS Index', url: 'https://ossindex.sonatype.org/' },
      ],
      evidence: { component: 'event-stream:3.3.6', ecosystem: 'npm', type: 'malicious-package' },
    },
    {
      id: randomUUID(), tool: 'blackduck', severity: 'high', cvss: 7.8,
      cve: 'CVE-2021-44228', cwe: 'CWE-917',
      title: 'Log4Shell RCE in log4j-core',
      asset: 'payment-service', status: 'fixed', fixVersion: '2.17.1',
      firstSeen: monthsAgo(3), lastSeen: monthsAgo(1), scanId: SCAN.bdPayment,
      remediationSteps: [
        'Upgrade log4j-core from 2.14.1 to 2.17.1',
        'Run: mvn versions:use-latest-releases -Dincludes=org.apache.logging.log4j',
      ],
      references: [{ label: 'NVD', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' }],
      evidence: { component: 'log4j-core:2.14.1', ecosystem: 'Maven' },
    },
    {
      id: randomUUID(), tool: 'sonatype', severity: 'medium', cvss: 5.3,
      cve: 'CVE-2023-26136', cwe: 'CWE-79',
      title: 'Prototype pollution in tough-cookie',
      asset: 'auth-service', status: 'open', fixVersion: '4.1.3',
      firstSeen: monthsAgo(2), lastSeen: daysAgo(1), scanId: SCAN.snAuth,
      remediationSteps: [
        'Upgrade tough-cookie from 2.5.0 to 4.1.3',
        'Run: npm install tough-cookie@4.1.3',
      ],
      references: [{ label: 'NVD', url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-26136' }],
      evidence: { component: 'tough-cookie:2.5.0', ecosystem: 'npm' },
    },
    {
      id: randomUUID(), tool: '42crunch', severity: 'medium', cvss: 5.0,
      cve: null, cwe: 'CWE-209',
      title: 'Stack trace exposed in 500 response',
      asset: 'api-gateway', status: 'open', fixVersion: null,
      firstSeen: monthsAgo(1), lastSeen: daysAgo(0), scanId: SCAN.crunchApi,
      remediationSteps: [
        'Strip stack traces from production error responses',
        'Return generic 500 message instead of internal details',
        'Run: NODE_ENV=production node server.js',
      ],
      references: [],
      evidence: { endpoint: 'POST /api/payments', issue: 'Information disclosure', owaspApi: 'A2' },
    },
  ];
  for (const f of findings) await prisma.finding.create({ data: f });
  console.log(`  Created ${findings.length} findings`);

  // ── Report download history ────────────────────────────────────────────────
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const prev   = months[(now.getMonth() - 1 + 12) % 12];
  const twoBack = months[(now.getMonth() - 2 + 12) % 12];
  const yr = now.getFullYear();

  const downloads = [
    { id: randomUUID(), name: `Executive Summary — ${prev} ${yr}`,        format: 'PDF', size: '128 KB', createdAt: daysAgo(2)  },
    { id: randomUUID(), name: `Full Vulnerability Report — ${prev} ${yr}`, format: 'CSV', size: '64 KB',  createdAt: daysAgo(3)  },
    { id: randomUUID(), name: `OWASP Compliance Report — ${twoBack} ${yr}`,format: 'PDF', size: '96 KB',  createdAt: daysAgo(35) },
    { id: randomUUID(), name: `Executive Summary — ${twoBack} ${yr}`,      format: 'PDF', size: '112 KB', createdAt: daysAgo(36) },
  ];
  for (const d of downloads) await prisma.reportDownload.create({ data: d });
  console.log(`  Created ${downloads.length} report download records`);

  console.log('✅ Seed complete');
}

main()
  .catch((e) => { console.error(e); process.exit(1); })
  .finally(() => prisma.$disconnect());

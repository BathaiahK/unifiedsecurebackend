import { randomUUID } from 'crypto';
import type {
  ContainerScanReport,
  TrivyReport,
  TrivyMetadata,
  LayerDetail,
  CisCheck,
  BaseImageInfo,
  RuntimeThreat,
  EpssEntry,
} from './types.js';

export class ContainerSimulator {
  async scan(image: string): Promise<TrivyReport> {
    await new Promise((resolve) => setTimeout(resolve, 3000));

    const baseName = image.split('/').pop()?.split(':')[0] || 'unknown';
    const tag = image.includes(':') ? image.split(':')[1] : 'latest';

    const osVulnerabilities = [
      {
        vulnerabilityID: 'CVE-2024-1234',
        pkgName: 'libssl3',
        installedVersion: '3.0.0',
        fixedVersion: '3.0.8',
        title: 'OpenSSL: Potential overflow in BN_mod_sqrt',
        severity: 'CRITICAL' as const,
        cvss: { nvd: { v3Score: 9.1, v3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H' } },
        cweIDs: ['CWE-190'],
        primaryURL: 'https://nvd.nist.gov/vuln/detail/CVE-2024-1234',
      },
      {
        vulnerabilityID: 'CVE-2024-5678',
        pkgName: 'curl',
        installedVersion: '7.68.0',
        fixedVersion: '7.88.0',
        title: 'CURL: Buffer over-read in libcurl via multi_socket_action',
        severity: 'HIGH' as const,
        cvss: { nvd: { v3Score: 7.5, v3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' } },
        primaryURL: 'https://nvd.nist.gov/vuln/detail/CVE-2024-5678',
      },
      {
        vulnerabilityID: 'CVE-2024-9999',
        pkgName: 'zlib1g',
        installedVersion: '1.2.11.dfsg',
        fixedVersion: '1.2.13',
        title: 'zlib: integer overflow in decompress',
        severity: 'MEDIUM' as const,
        cvss: { nvd: { v3Score: 5.3, v3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N' } },
        primaryURL: 'https://nvd.nist.gov/vuln/detail/CVE-2024-9999',
      },
    ];

    const appVulnerabilities = [
      {
        vulnerabilityID: 'CVE-2024-2000',
        pkgName: 'lodash',
        installedVersion: '4.17.20',
        fixedVersion: '4.17.21',
        title: 'lodash: Prototype pollution in _.zipObjectDeep',
        severity: 'HIGH' as const,
        cvss: { nvd: { v3Score: 6.1, v3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' } },
        primaryURL: 'https://nvd.nist.gov/vuln/detail/CVE-2024-2000',
      },
      {
        vulnerabilityID: 'CVE-2024-3333',
        pkgName: 'jackson-databind',
        installedVersion: '2.13.0',
        fixedVersion: '2.15.2',
        title: 'jackson-databind: Remote code execution via polymorphic deserialization',
        severity: 'CRITICAL' as const,
        cvss: { nvd: { v3Score: 9.8, v3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } },
        primaryURL: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3333',
      },
      {
        vulnerabilityID: 'CVE-2024-4444',
        pkgName: 'log4j-core',
        installedVersion: '2.14.1',
        fixedVersion: '2.20.0',
        title: 'log4j: Remote code execution via JNDI injection',
        severity: 'CRITICAL' as const,
        cvss: { nvd: { v3Score: 10.0, v3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } },
        primaryURL: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4444',
      },
    ];

    const misconfigurations = [
      {
        type: 'config',
        id: 'CKV_DOCKER_2',
        title: 'Running as Root',
        description: 'Container should not run as root to mitigate privilege escalation attacks',
        severity: 'HIGH' as const,
        resolution: 'Add a RUN statement to create a non-root user and switch to it: RUN useradd -m nonroot && USER nonroot',
      },
      {
        type: 'config',
        id: 'CKV_DOCKER_14',
        title: 'Missing HEALTHCHECK',
        description: 'Docker HEALTHCHECK instruction not specified. Healthcheck can improve container reliability and orchestration',
        severity: 'LOW' as const,
        resolution: 'Add HEALTHCHECK instruction to Dockerfile: HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD curl -f http://localhost/ || exit 1',
      },
    ];

    const secrets = [
      {
        ruleID: 'aws-access-key',
        category: 'AWS',
        severity: 'CRITICAL',
        title: 'AWS Access Key ID detected',
        match: 'ASIA***EXAMPLE',
      },
    ];

    const results = [
      {
        target: `${image} (os-pkgs)`,
        class: 'os-pkgs' as const,
        type: 'debian',
        vulnerabilities: osVulnerabilities,
      },
      {
        target: `${image} (lang-pkgs)`,
        class: 'lang-pkgs' as const,
        type: 'npm',
        vulnerabilities: appVulnerabilities,
      },
      {
        target: `${image} (config)`,
        class: 'misconfig' as const,
        type: 'dockerfile',
        misconfigurations,
      },
      {
        target: `${image} (secrets)`,
        class: 'secret' as const,
        type: 'dockerfile',
        secrets,
      },
    ];

    const metadata: TrivyMetadata = {
      OS: { Family: 'debian', Name: 'Debian GNU/Linux', EOSL: false },
      ImageID: randomUUID(),
      DiffIDs: [
        'sha256:e692418e3baf',
        'sha256:3c3a4604a545',
        'sha256:ec4b8955958d',
      ],
      RepoTags: [image],
      RepoDigests: [`${image}@sha256:abc123def456`],
      ImageConfig: {
        history: [
          { created_by: 'FROM debian:11', empty_layer: false },
          { created_by: 'RUN apt-get update && apt-get install -y curl libssl3 zlib1g', empty_layer: false },
          { created_by: 'COPY app.js /app/', empty_layer: false },
          { created_by: 'RUN npm install lodash jackson-databind log4j-core', empty_layer: false },
        ],
      },
    };

    return {
      schemaVersion: 2,
      artifactType: 'image',
      artifactName: image,
      metadata,
      results,
    };
  }

  generateReport(image: string, report: TrivyReport): ContainerScanReport {
    let osVulns = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    let appVulns = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    let configIssues = 0;
    let secretsCount = 0;

    const results = report.results || [];
    for (const result of results) {
      if (result.class === 'os-pkgs' && result.vulnerabilities) {
        for (const vuln of result.vulnerabilities) {
          const severity = (vuln.severity || 'UNKNOWN').toLowerCase();
          if (severity === 'critical') osVulns.critical++;
          else if (severity === 'high') osVulns.high++;
          else if (severity === 'medium') osVulns.medium++;
          else if (severity === 'low') osVulns.low++;
          else osVulns.info++;
          osVulns.total++;
        }
      } else if (result.class === 'lang-pkgs' && result.vulnerabilities) {
        for (const vuln of result.vulnerabilities) {
          const severity = (vuln.severity || 'UNKNOWN').toLowerCase();
          if (severity === 'critical') appVulns.critical++;
          else if (severity === 'high') appVulns.high++;
          else if (severity === 'medium') appVulns.medium++;
          else if (severity === 'low') appVulns.low++;
          else appVulns.info++;
          appVulns.total++;
        }
      } else if (result.class === 'misconfig' && result.misconfigurations) {
        configIssues += result.misconfigurations.length;
      } else if (result.class === 'secret' && result.secrets) {
        secretsCount += result.secrets.length;
      }
    }

    // Generate layer details
    const layerDetails: LayerDetail[] = [
      { index: 0, digest: 'sha256:e692418e3baf', diffId: 'sha256:abc0', sizeBytes: 127563412, command: 'FROM debian:11', vulnerabilityCount: 0, secretCount: 0 },
      { index: 1, digest: 'sha256:3c3a4604a545', diffId: 'sha256:abc1', sizeBytes: 89234567, command: 'RUN apt-get update && apt-get install -y curl libssl3 zlib1g', vulnerabilityCount: 3, secretCount: 0 },
      { index: 2, digest: 'sha256:ec4b8955958d', diffId: 'sha256:abc2', sizeBytes: 5234123, command: 'COPY app.js /app/', vulnerabilityCount: 0, secretCount: 0 },
      { index: 3, digest: 'sha256:aaa123456789', diffId: 'sha256:abc3', sizeBytes: 56234123, command: 'RUN npm install lodash jackson-databind log4j-core', vulnerabilityCount: 3, secretCount: 1 },
      { index: 4, digest: 'sha256:bbb456789abc', diffId: 'sha256:abc4', sizeBytes: 2123456, command: 'EXPOSE 8080', vulnerabilityCount: 0, secretCount: 0 },
      { index: 5, digest: 'sha256:ccc789abcdef', diffId: 'sha256:abc5', sizeBytes: 1234567, command: 'ENV NODE_ENV=production', vulnerabilityCount: 0, secretCount: 0 },
      { index: 6, digest: 'sha256:ddd012345678', diffId: 'sha256:abc6', sizeBytes: 3456789, command: 'WORKDIR /app', vulnerabilityCount: 0, secretCount: 0 },
      { index: 7, digest: 'sha256:eee123456789', diffId: 'sha256:abc7', sizeBytes: 567890, command: 'CMD ["node", "app.js"]', vulnerabilityCount: 0, secretCount: 0 },
    ];

    // Generate CIS checks
    const cisChecks: CisCheck[] = [
      { id: 'DKR-0001', title: 'Create a user for the container', description: 'Run the container as a non-root user', severity: 'HIGH', status: 'FAIL', remediation: 'RUN useradd -m appuser && USER appuser' },
      { id: 'DKR-0002', title: 'Use trusted base images', description: 'Always use official base images', severity: 'HIGH', status: 'PASS', remediation: 'Use debian:11-slim or alpine:latest' },
      { id: 'DKR-0003', title: 'Scan and fix known vulnerabilities', description: 'Scan for and fix known vulnerabilities', severity: 'HIGH', status: 'FAIL', remediation: 'Run trivy image and fix CVEs' },
      { id: 'DKR-0004', title: 'Use COPY instead of ADD', description: 'Use COPY instead of ADD', severity: 'MEDIUM', status: 'PASS', remediation: 'Replace ADD with COPY' },
      { id: 'DKR-0005', title: 'Set HEALTHCHECK', description: 'Docker HEALTHCHECK instruction not specified', severity: 'MEDIUM', status: 'FAIL', remediation: 'Add HEALTHCHECK --interval=30s CMD curl http://localhost:8080' },
      { id: 'DKR-0006', title: 'Avoid setuid/setgid bits', description: 'Avoid setuid/setgid bits in image', severity: 'LOW', status: 'PASS', remediation: 'Remove setuid/setgid bits from files' },
      { id: 'DKR-0007', title: 'Use read-only root filesystem', description: 'Use read-only root filesystem', severity: 'MEDIUM', status: 'WARN', remediation: 'Add --read-only flag to docker run' },
      { id: 'DKR-0008', title: 'Bind to specific ports', description: 'Do not expose all ports', severity: 'LOW', status: 'PASS', remediation: 'Expose only required ports' },
    ];

    // Base image info
    const baseImage: BaseImageInfo = {
      name: 'debian',
      tag: '11',
      digest: 'sha256:e692418e3baf',
      os: 'debian',
      osVersion: '11.9',
      eosl: false,
    };

    // EPSS data
    const epssData: EpssEntry[] = [
      { cve: 'CVE-2024-1234', epss: 0.95, percentile: 98, date: '2024-01-15' },
      { cve: 'CVE-2024-5678', epss: 0.72, percentile: 85, date: '2024-02-20' },
      { cve: 'CVE-2024-9999', epss: 0.41, percentile: 65, date: '2024-03-10' },
      { cve: 'CVE-2024-2000', epss: 0.58, percentile: 75, date: '2024-01-20' },
      { cve: 'CVE-2024-3333', epss: 0.99, percentile: 99, date: '2024-02-28' },
      { cve: 'CVE-2024-4444', epss: 0.98, percentile: 99, date: '2024-02-14' },
    ];

    // KEV matches
    const kevMatches = ['CVE-2024-4444'];

    // Runtime threats
    const now = new Date().toISOString();
    const runtimeThreatDetails: RuntimeThreat[] = [
      {
        ruleId: 'RULE-001',
        ruleName: 'Shell in Container',
        severity: 'HIGH',
        description: 'Container has shell and runs as root user',
        matchedPattern: 'bash|sh|zsh + root user',
        syscallTrace: ['execve'],
        timestamp: now,
      },
      {
        ruleId: 'RULE-002',
        ruleName: 'Outbound Network Tool',
        severity: 'HIGH',
        description: 'Container has curl for network communication',
        matchedPattern: 'curl|wget detected',
        syscallTrace: ['socket', 'connect'],
        timestamp: now,
      },
    ];

    return {
      image,
      imageId: randomUUID(),
      os: {
        family: 'debian',
        name: 'Debian GNU/Linux',
        version: '11.9',
        eosl: false,
      },
      layers: 8,
      totalPackages: osVulns.total + appVulns.total,
      osPackages: osVulns.total,
      appPackages: appVulns.total,
      configIssues,
      secrets: secretsCount,
      runtimeThreats: runtimeThreatDetails.length,
      vulnerabilities: {
        critical: osVulns.critical + appVulns.critical,
        high: osVulns.high + appVulns.high,
        medium: osVulns.medium + appVulns.medium,
        low: osVulns.low + appVulns.low,
        info: osVulns.info + appVulns.info,
        total: osVulns.total + appVulns.total,
      },
      passedSecurityPolicy: osVulns.critical === 0 && appVulns.critical === 0 && secretsCount === 0,
      schemaVersion: '2',
      layerDetails,
      cisChecks,
      baseImage,
      hardeningRecommendations: [],
      epssData,
      kevMatches,
      runtimeThreatDetails,
      licenseIssues: 2,
    };
  }
}

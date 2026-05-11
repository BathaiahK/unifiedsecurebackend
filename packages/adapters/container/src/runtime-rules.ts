import type { TrivyReport, RuntimeThreat } from './types.js';

export interface ImageContext {
  image: string;
  osFamily: string;
  hasRootUser: boolean;
  hasWritableRootfs: boolean;
  hasPrivileged: boolean;
  hasNetworkHost: boolean;
  installedPackages: string[];
  hasShell: boolean;
  hasCurl: boolean;
  hasNetcat: boolean;
  hasOpenssl: boolean;
  hasSudo: boolean;
  secretsFound: number;
  criticalVulns: number;
}

export function buildImageContext(image: string, trivyReport: TrivyReport): ImageContext {
  const osFamily = ((trivyReport.metadata as any)?.OS?.Family || 'linux').toLowerCase();
  const installedPackages: string[] = [];
  let secretsFound = 0;
  let criticalVulns = 0;

  // Collect packages and count issues
  if (trivyReport.results) {
    for (const result of trivyReport.results) {
      if ((result.class === 'os-pkgs' || result.class === 'lang-pkgs') && result.vulnerabilities) {
        for (const vuln of result.vulnerabilities) {
          installedPackages.push(vuln.pkgName.toLowerCase());
          if (vuln.severity === 'CRITICAL') criticalVulns++;
        }
      }
      if (result.class === 'secret' && result.secrets) {
        secretsFound += result.secrets.length;
      }
    }
  }

  const pkgSet = new Set(installedPackages);

  return {
    image,
    osFamily,
    hasRootUser: false,
    hasWritableRootfs: true,
    hasPrivileged: false,
    hasNetworkHost: false,
    installedPackages: Array.from(pkgSet),
    hasShell: pkgSet.has('bash') || pkgSet.has('sh') || pkgSet.has('zsh'),
    hasCurl: pkgSet.has('curl') || pkgSet.has('wget'),
    hasNetcat: pkgSet.has('netcat') || pkgSet.has('nc') || pkgSet.has('ncat'),
    hasOpenssl: pkgSet.has('openssl'),
    hasSudo: pkgSet.has('sudo'),
    secretsFound,
    criticalVulns,
  };
}

export function evaluateRules(context: ImageContext): RuntimeThreat[] {
  const threats: RuntimeThreat[] = [];
  const now = new Date().toISOString();

  // RULE-001: Shell in Container
  if (context.hasShell && context.hasRootUser) {
    threats.push({
      ruleId: 'RULE-001',
      ruleName: 'Shell in Container',
      severity: 'HIGH',
      description: 'Container has shell and runs as root user',
      matchedPattern: 'bash|sh|zsh + root user',
      syscallTrace: ['execve'],
      timestamp: now,
    });
  }

  // RULE-002: Outbound Network Tool
  if (context.hasCurl || context.hasNetcat) {
    threats.push({
      ruleId: 'RULE-002',
      ruleName: 'Outbound Network Tool',
      severity: 'HIGH',
      description: 'Container has curl or netcat for network communication',
      matchedPattern: 'curl|wget|netcat detected',
      syscallTrace: ['socket', 'connect', 'send'],
      timestamp: now,
    });
  }

  // RULE-003: Sensitive File Read
  if (context.hasRootUser && context.osFamily !== 'windows') {
    threats.push({
      ruleId: 'RULE-003',
      ruleName: 'Sensitive File Read',
      severity: 'MEDIUM',
      description: 'Root user can read sensitive files (/etc/shadow, /etc/passwd)',
      matchedPattern: 'root user + linux',
      syscallTrace: ['open', 'read'],
      timestamp: now,
    });
  }

  // RULE-004: Privilege Escalation via sudo
  if (context.hasSudo) {
    threats.push({
      ruleId: 'RULE-004',
      ruleName: 'Privilege Escalation via sudo',
      severity: 'CRITICAL',
      description: 'sudo binary present — risk of privilege escalation',
      matchedPattern: 'sudo package installed',
      syscallTrace: ['execve'],
      timestamp: now,
    });
  }

  // RULE-005: Writable Rootfs + Critical CVE
  if (context.hasWritableRootfs && context.criticalVulns > 0) {
    threats.push({
      ruleId: 'RULE-005',
      ruleName: 'Writable Rootfs + Critical CVE',
      severity: 'HIGH',
      description: `${context.criticalVulns} critical vulnerabilities in writable filesystem`,
      matchedPattern: `critical_vuln_count=${context.criticalVulns}`,
      syscallTrace: ['write', 'unlink'],
      timestamp: now,
    });
  }

  // RULE-006: Secret Exposure at Runtime
  if (context.secretsFound > 0) {
    threats.push({
      ruleId: 'RULE-006',
      ruleName: 'Secret Exposure at Runtime',
      severity: 'CRITICAL',
      description: `${context.secretsFound} secrets detected in image`,
      matchedPattern: `secret_count=${context.secretsFound}`,
      syscallTrace: ['open', 'read'],
      timestamp: now,
    });
  }

  // RULE-007: Network Host Mode Risk
  if (context.hasNetworkHost) {
    threats.push({
      ruleId: 'RULE-007',
      ruleName: 'Network Host Mode Risk',
      severity: 'HIGH',
      description: 'Container running in host network mode — unrestricted network access',
      matchedPattern: 'network_mode=host',
      syscallTrace: ['socket', 'bind', 'listen'],
      timestamp: now,
    });
  }

  // RULE-008: Crypto Mining Indicator
  const miningBinaries = ['xmrig', 'minerd', 'cgminer', 'bfgminer', 'cpuminer'];
  if (miningBinaries.some(bin => context.installedPackages.some(pkg => pkg.includes(bin)))) {
    threats.push({
      ruleId: 'RULE-008',
      ruleName: 'Crypto Mining Indicator',
      severity: 'MEDIUM',
      description: 'Crypto mining binary detected in image',
      matchedPattern: 'xmrig|minerd|cgminer pattern',
      syscallTrace: ['clone', 'futex'],
      timestamp: now,
    });
  }

  return threats;
}

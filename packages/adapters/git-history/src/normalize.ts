import { randomUUID } from 'node:crypto';
import type { UnifiedFinding } from '@usp/schema';
import type { RawSecret } from './scanner.js';
import type { SecretCategory } from './patterns.js';

function severityToCvss(severity: 'critical' | 'high' | 'medium'): number {
  switch (severity) {
    case 'critical':
      return 9.1;
    case 'high':
      return 7.5;
    case 'medium':
      return 5.3;
  }
}

function getRemediationSteps(category: SecretCategory): string[] {
  switch (category) {
    case 'cloud-credential':
      return [
        'Immediately revoke this credential in the cloud provider console (AWS IAM, GCP Console, Azure Portal)',
        'Rotate all resources that used this key',
        'Use `git filter-repo --path <file> --invert-paths` to purge the key from git history',
        'Force-push: `git push --force-with-lease`',
        'Add credential patterns to `.gitignore` and `.pre-commit-config.yaml` with gitleaks/detect-secrets',
      ];

    case 'private-key':
      return [
        'Immediately revoke and regenerate this private key',
        'Any data encrypted/signed with this key should be considered potentially exposed',
        'Treat the associated public certificate/SSH key as compromised',
        'Remove the key from git history using `git filter-repo --path <file>`',
        'Use SSH agent forwarding, key passphrases, or hardware keys (YubiKey) instead of committing keys',
      ];

    case 'database-credential':
      return [
        'Rotate the database password immediately in the database management console',
        'Check database audit logs for unauthorized queries since the commit date',
        'Terminate any open connections that used this credential',
        'Remove from git history using `git filter-repo`',
        'Use a secrets manager (HashiCorp Vault, AWS Secrets Manager) to inject credentials at runtime',
      ];

    case 'source-control-token':
      return [
        'Immediately revoke this token in Settings > Developer settings > Personal access tokens',
        'Check audit logs in GitHub/GitLab/Bitbucket for unauthorized API calls',
        'Rotate any dependent access (CI/CD, deploy keys, API clients)',
        'Remove from git history using `git filter-repo`',
        'Use environment variables or a dedicated secrets manager instead of hardcoding tokens',
      ];

    case 'payment-credential':
      return [
        'Immediately roll/revoke the API key in the payment processor dashboard (Stripe, PayPal, etc.)',
        'Review transaction logs and API usage for unauthorized charges or data access',
        'Check if the key had sensitive scopes (charges, refunds, customer data)',
        'Remove from git history using `git filter-repo`',
        'Use environment variables; never commit payment processor keys to source control',
      ];

    case 'communication-token':
      return [
        'Immediately revoke this token in Slack/Discord settings',
        'Check message history and file access logs for unauthorized activity',
        'Review bot/webhook permissions to determine blast radius',
        'Remove from git history using `git filter-repo`',
        'Use OAuth scopes with minimal permissions (only what is needed)',
      ];

    case 'email-credential':
      return [
        'Immediately rotate the API key in the email service dashboard',
        'Review email sending logs for unauthorized messages',
        'Check if the key had permission to send from multiple addresses',
        'Remove from git history using `git filter-repo`',
        'Use environment variables and API keys with minimal scope (send-only)',
      ];

    case 'auth-token':
      return [
        'Immediately revoke or rotate this authentication token',
        'Check service logs for unauthorized API calls using this token',
        'Determine the token scope and what data it had access to',
        'Remove from git history using `git filter-repo`',
        'Use short-lived tokens (JWT with expiration, OAuth tokens) instead of long-lived secrets',
      ];

    case 'registry-credential':
      return [
        'Immediately revoke or regenerate this registry credential (npm, Docker, PyPI, etc.)',
        'Check registry audit logs for unauthorized package publishes or downloads',
        'If a package was published with this key, consider yanking/deprecating it',
        'Remove from git history using `git filter-repo`',
        'Use separate credentials per service; use scoped tokens with minimal permissions',
      ];

    case 'entropy-string':
      return [
        'Verify whether this is actually a secret or a test/placeholder value',
        'If it is a real secret, immediately revoke it in the appropriate service',
        'Use a secrets manager to inject secrets at runtime instead of hardcoding',
        'Remove from git history using `git filter-repo`',
        'Implement pre-commit hooks (gitleaks, detect-secrets) to prevent future commits',
      ];
  }
}

function getCweForCategory(category: SecretCategory): string {
  // All hardcoded credentials fall under CWE-798
  return 'CWE-798';
}

export function normalizeRawSecret(raw: RawSecret, asset: string, scanId: string): UnifiedFinding {
  const cvss = severityToCvss(raw.severity);
  const cwe = getCweForCategory(raw.secretCategory);
  const remediationSteps = getRemediationSteps(raw.secretCategory);

  const references: UnifiedFinding['references'] = [
    {
      label: 'CWE-798: Use of Hard-coded Credentials',
      url: 'https://cwe.mitre.org/data/definitions/798.html',
    },
    {
      label: 'OWASP: Secrets Management',
      url: 'https://owasp.org/www-project-secrets-management/',
    },
  ];

  if (raw.secretCategory === 'cloud-credential') {
    references.push({
      label: 'NIST SP 800-63B: Authentication and Lifecycle Management',
      url: 'https://pages.nist.gov/800-63-3/sp800-63b.html',
    });
  } else if (raw.secretCategory === 'private-key') {
    references.push({
      label: 'RFC 4251: The Secure Shell (SSH) Protocol Architecture',
      url: 'https://tools.ietf.org/html/rfc4251',
    });
  }

  const now = new Date().toISOString();

  return {
    id: randomUUID(),
    tool: 'git-history',
    severity: raw.severity,
    cvss,
    cve: null,
    cwe,
    title: `Hardcoded ${raw.patternName} found in git history`,
    asset,
    status: 'open',
    fixVersion: null,
    firstSeen: now,
    lastSeen: now,
    remediationSteps,
    references,
    evidence: {
      commitHash: raw.commitHash,
      commitDate: raw.commitDate,
      authorName: raw.authorName,
      authorEmail: raw.authorEmail,
      filePath: raw.filePath,
      lineNumber: raw.lineNumber,
      redactedSecret: raw.matchedValue,
      secretCategory: raw.secretCategory,
      patternId: raw.patternId,
      patternName: raw.patternName,
      contextLines: raw.contextLines,
      dedupeKey: raw.dedupeKey,
    },
    scanId,
  };
}

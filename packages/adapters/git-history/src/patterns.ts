export type SecretCategory =
  | 'cloud-credential'
  | 'source-control-token'
  | 'communication-token'
  | 'payment-credential'
  | 'email-credential'
  | 'private-key'
  | 'database-credential'
  | 'auth-token'
  | 'registry-credential'
  | 'entropy-string';

export interface SecretPattern {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium';
  regex: RegExp;
  keywords: string[];
  entropyThreshold?: number;
  secretCategory: SecretCategory;
}

function shannonEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function calculateEntropy(value: string): number {
  return shannonEntropy(value);
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  // ──────────────────────────────────────────────────────────────────
  // Cloud Credentials (critical)
  // ──────────────────────────────────────────────────────────────────

  {
    id: 'aws_access_key',
    name: 'AWS Access Key ID',
    severity: 'critical',
    regex: /((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})/,
    keywords: ['akia', 'aws_access_key', 'aws_key_id', 'aws_access_key_id'],
    secretCategory: 'cloud-credential',
  },

  {
    id: 'aws_secret_key',
    name: 'AWS Secret Access Key',
    severity: 'critical',
    regex:
      /(aws_secret_access_key\s*=\s*|AWS_SECRET_ACCESS_KEY\s*=\s*|aws_secret\s*=\s*)(['"]?)([A-Za-z0-9/+=]{40})/,
    keywords: ['aws_secret', 'aws_secret_access_key'],
    entropyThreshold: 4.5,
    secretCategory: 'cloud-credential',
  },

  {
    id: 'aws_session_token',
    name: 'AWS Session Token',
    severity: 'critical',
    regex: /(aws_session_token\s*=\s*|AWS_SESSION_TOKEN\s*=\s*|FwoGZXIvYXdzE[A-Za-z0-9/+=]{200,})/,
    keywords: ['aws_session_token', 'session_token', 'x-amz-security-token'],
    secretCategory: 'cloud-credential',
  },

  {
    id: 'google_api_key',
    name: 'Google API Key',
    severity: 'critical',
    regex: /(AIza[A-Za-z0-9\-_]{35})/,
    keywords: ['aiza', 'google_api_key', 'googleapikey'],
    secretCategory: 'cloud-credential',
  },

  {
    id: 'google_service_account',
    name: 'Google Service Account JSON',
    severity: 'critical',
    regex: /("type"\s*:\s*"service_account"[\s\S]{0,500}?"private_key")/,
    keywords: ['service_account', 'private_key', 'google'],
    secretCategory: 'cloud-credential',
  },

  {
    id: 'google_oauth_secret',
    name: 'Google OAuth Client Secret',
    severity: 'critical',
    regex: /(GOCSPX-[A-Za-z0-9_-]{28})/,
    keywords: ['gocspx', 'client_secret'],
    secretCategory: 'cloud-credential',
  },

  {
    id: 'azure_connection_string',
    name: 'Azure Connection String',
    severity: 'critical',
    regex: /(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+;)/,
    keywords: ['defaultendpointsprotocol', 'accountkey', 'azure'],
    secretCategory: 'cloud-credential',
  },

  {
    id: 'azure_sas_token',
    name: 'Azure SAS Token',
    severity: 'critical',
    regex: /(sv=20\d\d-\d\d-\d\d&[^&]*sig=[A-Za-z0-9%+/=]+)/,
    keywords: ['sv=20', 'sig=', 'azure'],
    secretCategory: 'cloud-credential',
  },

  // ──────────────────────────────────────────────────────────────────
  // Private Keys (critical)
  // ──────────────────────────────────────────────────────────────────

  {
    id: 'rsa_private_key',
    name: 'RSA Private Key',
    severity: 'critical',
    regex: /(-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----)/,
    keywords: ['begin rsa private key'],
    secretCategory: 'private-key',
  },

  {
    id: 'openssh_private_key',
    name: 'OpenSSH Private Key',
    severity: 'critical',
    regex: /(-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----)/,
    keywords: ['begin openssh private key'],
    secretCategory: 'private-key',
  },

  {
    id: 'pgp_private_key',
    name: 'PGP Private Key',
    severity: 'critical',
    regex: /(-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----)/,
    keywords: ['begin pgp private key'],
    secretCategory: 'private-key',
  },

  {
    id: 'ec_private_key',
    name: 'EC Private Key',
    severity: 'critical',
    regex: /(-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----)/,
    keywords: ['begin ec private key'],
    secretCategory: 'private-key',
  },

  {
    id: 'pkcs8_private_key',
    name: 'PKCS8 Private Key',
    severity: 'critical',
    regex: /(-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----)/,
    keywords: ['begin private key'],
    secretCategory: 'private-key',
  },

  // ──────────────────────────────────────────────────────────────────
  // Database Credentials (critical)
  // ──────────────────────────────────────────────────────────────────

  {
    id: 'mongodb_connection_string',
    name: 'MongoDB Connection String',
    severity: 'critical',
    regex: /(mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s"']+)/,
    keywords: ['mongodb://', 'mongodb+srv://'],
    secretCategory: 'database-credential',
  },

  {
    id: 'postgresql_connection_string',
    name: 'PostgreSQL Connection String',
    severity: 'critical',
    regex: /(postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\s"']+)/,
    keywords: ['postgres://', 'postgresql://'],
    secretCategory: 'database-credential',
  },

  {
    id: 'mysql_connection_string',
    name: 'MySQL Connection String',
    severity: 'critical',
    regex: /(mysql:\/\/[^:]+:[^@]+@[^\s"']+)/,
    keywords: ['mysql://'],
    secretCategory: 'database-credential',
  },

  {
    id: 'redis_connection_string',
    name: 'Redis Connection String',
    severity: 'critical',
    regex: /(redis(?:s)?:\/\/(?:[^:]+:[^@]+@)?[^\s"']+)/,
    keywords: ['redis://', 'rediss://'],
    secretCategory: 'database-credential',
  },

  // ──────────────────────────────────────────────────────────────────
  // Source Control Tokens (high/critical)
  // ──────────────────────────────────────────────────────────────────

  {
    id: 'github_pat',
    name: 'GitHub Personal Access Token',
    severity: 'critical',
    regex: /(ghp_[A-Za-z0-9]{36})/,
    keywords: ['ghp_', 'github_token', 'github_pat'],
    secretCategory: 'source-control-token',
  },

  {
    id: 'github_oauth_token',
    name: 'GitHub OAuth Token',
    severity: 'critical',
    regex: /(gho_[A-Za-z0-9]{36})/,
    keywords: ['gho_'],
    secretCategory: 'source-control-token',
  },

  {
    id: 'github_app_token',
    name: 'GitHub App Token',
    severity: 'critical',
    regex: /((?:ghu|ghs)_[A-Za-z0-9]{36})/,
    keywords: ['ghu_', 'ghs_'],
    secretCategory: 'source-control-token',
  },

  {
    id: 'github_fine_grained_pat',
    name: 'GitHub Fine-Grained PAT',
    severity: 'critical',
    regex: /(github_pat_[A-Za-z0-9_]{82})/,
    keywords: ['github_pat_'],
    secretCategory: 'source-control-token',
  },

  {
    id: 'gitlab_pat',
    name: 'GitLab Personal Access Token',
    severity: 'high',
    regex: /(glpat-[A-Za-z0-9\-_]{20})/,
    keywords: ['glpat-', 'gitlab_token'],
    secretCategory: 'source-control-token',
  },

  // ──────────────────────────────────────────────────────────────────
  // Communication Tokens (critical/high)
  // ──────────────────────────────────────────────────────────────────

  {
    id: 'slack_bot_token',
    name: 'Slack Bot Token',
    severity: 'critical',
    regex: /(xoxb-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{24})/,
    keywords: ['xoxb-', 'slack_bot_token'],
    secretCategory: 'communication-token',
  },

  {
    id: 'slack_app_token',
    name: 'Slack App Token',
    severity: 'critical',
    regex: /(xapp-\d-[A-Z0-9]{11}-[0-9]{11}-[a-z0-9]{64})/,
    keywords: ['xapp-'],
    secretCategory: 'communication-token',
  },

  {
    id: 'slack_webhook',
    name: 'Slack Webhook URL',
    severity: 'high',
    regex: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24})/,
    keywords: ['hooks.slack.com'],
    secretCategory: 'communication-token',
  },

  {
    id: 'discord_webhook',
    name: 'Discord Webhook URL',
    severity: 'high',
    regex: /(https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9\-_\.]{68})/,
    keywords: ['discord.com/api/webhooks'],
    secretCategory: 'communication-token',
  },

  {
    id: 'discord_bot_token',
    name: 'Discord Bot Token',
    severity: 'critical',
    regex: /((?:[MN][A-Za-z0-9]{23})\.(?:[A-Za-z0-9-_]{6})\.(?:[A-Za-z0-9-_]{27,}))/,
    keywords: ['discord_token', 'bot_token'],
    secretCategory: 'communication-token',
  },

  // ──────────────────────────────────────────────────────────────────
  // Payment Credentials (critical)
  // ──────────────────────────────────────────────────────────────────

  {
    id: 'stripe_live_key',
    name: 'Stripe Live API Key',
    severity: 'critical',
    regex: /(sk_live_[A-Za-z0-9]{24,})/,
    keywords: ['sk_live_', 'stripe'],
    secretCategory: 'payment-credential',
  },

  {
    id: 'stripe_restricted_key',
    name: 'Stripe Restricted API Key',
    severity: 'critical',
    regex: /(rk_live_[A-Za-z0-9]{24,})/,
    keywords: ['rk_live_'],
    secretCategory: 'payment-credential',
  },

  // ──────────────────────────────────────────────────────────────────
  // Email Service Credentials (high)
  // ──────────────────────────────────────────────────────────────────

  {
    id: 'sendgrid_api_key',
    name: 'SendGrid API Key',
    severity: 'high',
    regex: /(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})/,
    keywords: ['sg.', 'sendgrid'],
    secretCategory: 'email-credential',
  },

  {
    id: 'mailgun_api_key',
    name: 'Mailgun API Key',
    severity: 'high',
    regex: /(key-[A-Za-z0-9]{32})/,
    keywords: ['mailgun', 'mg.'],
    secretCategory: 'email-credential',
  },

  {
    id: 'mailchimp_api_key',
    name: 'Mailchimp API Key',
    severity: 'high',
    regex: /([a-zA-Z0-9]{32}-us\d+)/,
    keywords: ['mailchimp'],
    secretCategory: 'email-credential',
  },

  // ──────────────────────────────────────────────────────────────────
  // Auth Tokens (high)
  // ──────────────────────────────────────────────────────────────────

  {
    id: 'jwt_token',
    name: 'JWT Token',
    severity: 'high',
    regex: /(ey[A-Za-z0-9\-_]+\.ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)/,
    keywords: ['eyj', 'jwt', 'bearer'],
    secretCategory: 'auth-token',
  },

  {
    id: 'npm_token',
    name: 'NPM Token',
    severity: 'high',
    regex: /(npm_[A-Za-z0-9]{36})/,
    keywords: ['npm_', '_authtoken'],
    secretCategory: 'registry-credential',
  },

  {
    id: 'twilio_api_key',
    name: 'Twilio API Key',
    severity: 'high',
    regex: /(SK[0-9a-fA-F]{32})/,
    keywords: ['twilio', 'accountsid'],
    secretCategory: 'auth-token',
  },

  // ──────────────────────────────────────────────────────────────────
  // High Entropy Strings (high)
  // ──────────────────────────────────────────────────────────────────

  {
    id: 'high_entropy_string',
    name: 'High Entropy String',
    severity: 'high',
    regex:
      /((?:password|secret|key|token|credential|api_key|apikey|access_key|private_key|auth)\s*[=:]\s*['"]?)([A-Za-z0-9+/=_\-]{20,})(['"]?)/i,
    keywords: ['password', 'secret', 'key', 'token', 'api_key', 'credential'],
    entropyThreshold: 4.5,
    secretCategory: 'entropy-string',
  },
];

export const SKIP_PATHS: readonly RegExp[] = [
  /node_modules\//,
  /\.git\//,
  /vendor\//,
  /\.next\//,
  /dist\//,
  /build\//,
  /coverage\//,
  /\.cache\//,
  /tmp\//,
  /\.lock$/,
  /\.sum$/,
  /\.resolved$/,
  /\.(jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot|pdf|zip|tar|gz|bin|exe|dmg|iso|mov|mp4|webm|wav|mp3)$/i,
  /\.(test|spec)\.(ts|tsx|js|jsx)$/,
  /__tests__\//,
  /\/test\//,
  /\/tests\//,
  /\/fixtures\//,
  /\/mock\//,
  /CHANGELOG/i,
  /LICENSE/i,
  /\.md$/,
];

export const KNOWN_FALSE_POSITIVES = new Set([
  'examplepassword',
  'changethis',
  'yourtoken',
  'placeholder',
  'dummy',
  'test',
  'example',
  'xxxx',
  '1234567890',
  'abc123',
  'password123',
]);

export function shouldSkipPath(filePath: string): boolean {
  return SKIP_PATHS.some((pattern) => pattern.test(filePath));
}

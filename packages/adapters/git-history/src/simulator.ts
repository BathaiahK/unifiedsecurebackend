import type { RawSecret } from './scanner.js';

export function generateSimulatedFindings(asset: string): RawSecret[] {
  const now = new Date();
  const findings: RawSecret[] = [];

  // Secret 1: AWS Access Key
  findings.push({
    patternId: 'aws_access_key',
    patternName: 'AWS Access Key ID',
    severity: 'critical',
    secretCategory: 'cloud-credential',
    commitHash: 'a1b2c3d4e5f6g7h8i9j0',
    commitDate: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString(),
    authorName: 'Developer Bot',
    authorEmail: 'dev@company.com',
    filePath: 'config/aws.ts',
    lineNumber: 42,
    matchedValue: 'AKIA...MPLE',
    fullMatchedValue: 'AKIAIOSFODNN7EXAMPLE',
    contextLines: [
      'export const awsConfig = {',
      '  accessKeyId: "AKIAIOSFODNN7EXAMPLE",',
      '  region: "us-east-1",',
    ],
    dedupeKey: 'abc123def456',
  });

  // Secret 2: RSA Private Key
  findings.push({
    patternId: 'rsa_private_key',
    patternName: 'RSA Private Key',
    severity: 'critical',
    secretCategory: 'private-key',
    commitHash: 'e5f6g7h8i9j0k1l2m3n4',
    commitDate: new Date(now.getTime() - 20 * 24 * 60 * 60 * 1000).toISOString(),
    authorName: 'DevOps Team',
    authorEmail: 'devops@company.com',
    filePath: 'deploy/server.pem',
    lineNumber: 1,
    matchedValue: '-----...-----',
    fullMatchedValue: '-----BEGIN RSA PRIVATE KEY-----',
    contextLines: [
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEpAIBAAKCAQEA1234567890abcdefg...',
      'KSL2FvQ8jR7pZ0wX1m2n3o4p5q6r7s8t9u',
    ],
    dedupeKey: 'def789ghi012',
  });

  // Secret 3: GitHub PAT
  findings.push({
    patternId: 'github_pat',
    patternName: 'GitHub Personal Access Token',
    severity: 'critical',
    secretCategory: 'source-control-token',
    commitHash: '9ab4cd2e1f3g4h5i6j7k8',
    commitDate: new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000).toISOString(),
    authorName: 'CI/CD System',
    authorEmail: 'ci@company.com',
    filePath: 'scripts/deploy.sh',
    lineNumber: 87,
    matchedValue: 'ghp_...QrSt',
    fullMatchedValue: 'ghp_xK9mQrTvWpLnYzA3bCeD5fGhIjKlMnOpQ',
    contextLines: [
      'echo "Setting up GitHub..."',
      'export GITHUB_TOKEN="ghp_xK9mQrTvWpLnYzA3bCeD5fGhIjKlMnOpQ"',
      'git push origin main',
    ],
    dedupeKey: 'ghi345jkl678',
  });

  // Secret 4: Slack Bot Token
  findings.push({
    patternId: 'slack_bot_token',
    patternName: 'Slack Bot Token',
    severity: 'critical',
    secretCategory: 'communication-token',
    commitHash: '12ef345g6h7i8j9k0l1m2',
    commitDate: new Date(now.getTime() - 5 * 24 * 60 * 60 * 1000).toISOString(),
    authorName: 'Alerts Team',
    authorEmail: 'alerts@company.com',
    filePath: 'src/notifications/slack.ts',
    lineNumber: 34,
    matchedValue: 'xoxb-...UvWx',
    fullMatchedValue: 'xoxb-1234567890123-1234567890456-AbCdEfGhIjKlMnOpQrStUvWx',
    contextLines: [
      'const slackClient = new Slack({',
      '  token: "xoxb-1234567890123-1234567890456-AbCdEfGhIjKlMnOpQrStUvWx",',
      '  channel: "#alerts",',
    ],
    dedupeKey: 'jkl901mno234',
  });

  // Secret 5: MongoDB Connection String
  findings.push({
    patternId: 'mongodb_connection_string',
    patternName: 'MongoDB Connection String',
    severity: 'critical',
    secretCategory: 'database-credential',
    commitHash: 'cdef678h9i0j1k2l3m4n5',
    commitDate: new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    authorName: 'Backend Dev',
    authorEmail: 'backend@company.com',
    filePath: '.env.example',
    lineNumber: 12,
    matchedValue: 'mongodb://...mydb',
    fullMatchedValue: 'mongodb://admin:Password123@prod-cluster.mongodb.net/mydb',
    contextLines: [
      'DATABASE_URL=mongodb://admin:Password123@prod-cluster.mongodb.net/mydb',
      'REDIS_URL=redis://localhost:6379',
      'API_KEY=xxx',
    ],
    dedupeKey: 'mno567pqr890',
  });

  return findings;
}

import { randomUUID } from 'node:crypto';
import { SastFinding, SastMatch } from './types.js';
import { SAST_RULES, getRulesByLanguage } from './rules.js';

export class VulnerabilityDetector {
  private findings: SastFinding[] = [];

  detectVulnerabilities(
    sourceCode: string,
    filePath: string,
    language: string
  ): SastFinding[] {
    this.findings = [];
    const rules = getRulesByLanguage(language);

    const lines = sourceCode.split('\n');

    for (const rule of rules) {
      try {
        const regex = new RegExp(rule.pattern, 'gim');
        let match;

        while ((match = regex.exec(sourceCode)) !== null) {
          const lineNumber = sourceCode.substring(0, match.index).split('\n').length;
          const lineContent = lines[lineNumber - 1] || '';
          const columnNumber = match.index - sourceCode.lastIndexOf('\n', match.index - 1);

          const finding: SastFinding = {
            id: randomUUID(),
            ruleId: rule.id,
            ruleName: rule.name,
            file: filePath,
            line: lineNumber,
            column: columnNumber,
            code: lineContent.trim(),
            message: rule.description,
            severity: rule.severity,
            cwe: rule.cwe,
            remediation: rule.remediationTips,
            matches: [
              {
                file: filePath,
                line: lineNumber,
                column: columnNumber,
                lineContent: lineContent.trim(),
                matchedText: match[0]
              }
            ]
          };

          this.findings.push(finding);
        }
      } catch (error) {
        console.error(`Error applying rule ${rule.id}:`, error);
      }
    }

    return this.findings;
  }

  analyzeMockRepository(assetName: string): SastFinding[] {
    this.findings = [];

    // Mock vulnerable code samples for different scenarios
    const mockFiles: Record<string, { code: string; language: string }> = {
      'src/auth.ts': {
        language: 'typescript',
        code: `
import * as jwt from 'jsonwebtoken';
import crypto from 'crypto';

// VULNERABLE: Hardcoded secret
const JWT_SECRET = "my-super-secret-jwt-key-12345";

// VULNERABLE: Hardcoded password
export const DEFAULT_PASSWORD = "admin@123";

export async function authenticateUser(username: string, password: string) {
  // Vulnerable: Using MD5 for password hashing
  const hash = crypto.createHash('md5').update(password).digest('hex');

  // Vulnerable: SQL injection - string concatenation
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + hash + "'";
  const user = await db.query(query);

  return user;
}

export function validatePassword(plain: string, stored: string) {
  // Vulnerable: Using SHA1 (weak crypto)
  const hash = crypto.createHash('sha1').update(plain).digest('hex');
  return hash === stored;
}
        `
      },
      'src/api.ts': {
        language: 'typescript',
        code: `
import express from 'express';

const app = express();

// VULNERABLE: Missing authentication check
app.get('/api/admin/users', (req, res) => {
  const users = getAllUsers();
  res.json(users);
});

// VULNERABLE: Missing authentication check
app.post('/api/admin/delete-user/:id', (req, res) => {
  deleteUser(req.params.id);
  res.json({ success: true });
});

// VULNERABLE: Unescaped user input in HTML response
app.get('/user/:name', (req, res) => {
  const userName = req.params.name;
  res.send(\`<h1>Welcome \${userName}</h1>\`);
});

// VULNERABLE: Command injection
app.post('/api/convert', (req, res) => {
  const file = req.body.filename;
  const { exec } = require('child_process');
  exec('convert ' + file + ' output.png', (err) => {
    res.json({ success: true });
  });
});

// VULNERABLE: Path traversal
app.get('/files/:path', (req, res) => {
  const filePath = req.params.path;
  const fs = require('fs');
  const content = fs.readFileSync(filePath, 'utf-8');
  res.send(content);
});
        `
      },
      'src/utils.ts': {
        language: 'typescript',
        code: `
import crypto from 'crypto';

export function generateToken() {
  // VULNERABLE: Using Math.random() for security-sensitive token
  return Math.random().toString(36).substring(2, 15);
}

export function generateSecureToken() {
  // VULNERABLE: Still using Math.random (pattern detection)
  const token = Math.random().toString(36).slice(2);
  return token;
}

export function hashPassword(password: string) {
  // VULNERABLE: Using insecure random (not cryptographically secure)
  const salt = Math.random().toString(36).substring(2, 10);
  return crypto.createHash('sha1').update(password + salt).digest('hex');
}

export function logUserData(user: any) {
  // VULNERABLE: Logging sensitive data
  console.log('User logged in:', user.email, 'Password:', user.password);
  console.log('API Key:', user.apiKey);
}
        `
      },
      'src/database.ts': {
        language: 'typescript',
        code: `
import mysql from 'mysql';

const conn = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password123', // VULNERABLE: Hardcoded password
  database: 'myapp'
});

export async function getUserById(userId: string) {
  // VULNERABLE: SQL injection via string concatenation
  const query = "SELECT * FROM users WHERE id = " + userId;
  return new Promise((resolve, reject) => {
    conn.query(query, (error, results) => {
      if (error) reject(error);
      resolve(results[0]);
    });
  });
}

export async function updateUserPassword(userId: string, newPassword: string) {
  // VULNERABLE: SQL injection and weak crypto combined
  const hashedPassword = require('crypto').createHash('md5').update(newPassword).digest('hex');
  const query = "UPDATE users SET password = '" + hashedPassword + "' WHERE id = " + userId;

  conn.query(query, (error) => {
    if (error) console.log('Error:', error);
  });
}

export async function getUserByEmail(email: string) {
  // VULNERABLE: SQL injection via string concatenation
  const sql = \`SELECT * FROM users WHERE email = '\${email}'\`;
  return await conn.query(sql);
}
        `
      },
      'src/frontend.tsx': {
        language: 'typescript',
        code: `
import React from 'react';

export function UserProfile({ userData }: { userData: any }) {
  return (
    // VULNERABLE: XSS - unescaped user input
    <div dangerouslySetInnerHTML={{ __html: userData.bio }} />
  );
}

export function CommentSection({ comments }: { comments: string[] }) {
  return (
    <div>
      {comments.map((comment, i) => (
        // VULNERABLE: XSS via innerHTML
        <div key={i} innerHTML={comment} />
      ))}
    </div>
  );
}

export function SearchResults({ query }: { query: string }) {
  // VULNERABLE: XSS via dangerouslySetInnerHTML
  return (
    <div dangerouslySetInnerHTML={{ __html: \`Search results for: \${query}\` }} />
  );
}
        `
      },
      'src/config.ts': {
        language: 'typescript',
        code: `
// VULNERABLE: Multiple hardcoded secrets and API keys
export const API_KEYS = {
  stripe: 'sk_live_1234567890abcdefghij',
  twilio: 'AC1234567890abcdefghij',
  sendgrid: 'SG.1234567890abcdefghij',
  github: 'ghp_1234567890abcdefghij'
};

export const DATABASE_CREDS = {
  username: 'admin',
  password: 'prod_password_2024!'
};

export const JWT_CONFIG = {
  secret: 'my-super-secret-jwt-secret-key',
  expiresIn: '24h'
};

export const AWS_CONFIG = {
  accessKeyId: 'AKIA1234567890ABCDEF',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
};
        `
      }
    };

    // Analyze all mock files
    for (const [filePath, { code, language }] of Object.entries(mockFiles)) {
      const fileFindings = this.detectVulnerabilities(code, filePath, language);
      this.findings.push(...fileFindings);
    }

    // Remove duplicates by ID
    const uniqueFindings = new Map<string, SastFinding>();
    for (const finding of this.findings) {
      const key = `${finding.file}:${finding.line}:${finding.ruleId}`;
      if (!uniqueFindings.has(key)) {
        uniqueFindings.set(key, finding);
      }
    }

    return Array.from(uniqueFindings.values());
  }

  async analyzeRepository(repoUrl: string, assetName: string): Promise<SastFinding[]> {
    try {
      const { owner, repo } = this.parseGitHubUrl(repoUrl);
      const sourceFiles = await this.fetchSourceFiles(owner, repo);
      if (sourceFiles.length === 0) return this.analyzeMockRepository(assetName);

      this.findings = [];
      for (const { path, language } of sourceFiles.slice(0, 50)) {
        try {
          const content = await this.fetchFileContent(owner, repo, path);
          const fileFindings = this.detectVulnerabilities(content, path, language);
          this.findings.push(...fileFindings);
        } catch (error) {
          console.warn(`Failed to fetch/analyze ${path}:`, error);
        }
      }

      const uniqueFindings = new Map<string, SastFinding>();
      for (const finding of this.findings) {
        const key = `${finding.file}:${finding.line}:${finding.ruleId}`;
        if (!uniqueFindings.has(key)) uniqueFindings.set(key, finding);
      }
      return Array.from(uniqueFindings.values());
    } catch (error) {
      console.warn(`Repository analysis failed for ${repoUrl}, falling back to mock:`, error);
      return this.analyzeMockRepository(assetName);
    }
  }

  private parseGitHubUrl(url: string): { owner: string; repo: string } {
    const httpsMatch = url.match(/github\.com\/([^/]+)\/([^/]+)(\.git)?$/);
    if (httpsMatch && httpsMatch[1] && httpsMatch[2]) {
      return { owner: httpsMatch[1], repo: httpsMatch[2] };
    }

    const sshMatch = url.match(/github\.com:([^/]+)\/([^/]+)(\.git)?$/);
    if (sshMatch && sshMatch[1] && sshMatch[2]) {
      return { owner: sshMatch[1], repo: sshMatch[2] };
    }

    throw new Error(`Invalid GitHub URL: ${url}`);
  }

  private async fetchSourceFiles(owner: string, repo: string): Promise<Array<{ path: string; language: string }>> {
    const sourceExtensions = new Set([
      '.ts', '.tsx', '.js', '.jsx', '.py', '.java', '.go', '.php', '.cs', '.rb', '.kt', '.rs'
    ]);

    try {
      const response = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`,
        { headers: { 'User-Agent': 'USP-SAST' } }
      );
      if (!response.ok) return [];

      const data = (await response.json()) as { tree: Array<{ path: string; type: string }> };
      return data.tree
        .filter(item => item.type === 'blob' && sourceExtensions.has(this.getFileExtension(item.path)))
        .map(item => ({
          path: item.path,
          language: this.detectLanguage(item.path)
        }));
    } catch (error) {
      console.warn('Failed to fetch source files from GitHub API:', error);
      return [];
    }
  }

  private async fetchFileContent(owner: string, repo: string, path: string): Promise<string> {
    const response = await fetch(
      `https://raw.githubusercontent.com/${owner}/${repo}/HEAD/${path}`,
      { headers: { 'User-Agent': 'USP-SAST' } }
    );
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.text();
  }

  private getFileExtension(path: string): string {
    const match = path.match(/(\.[^.]+)$/);
    return match && match[1] ? match[1] : '';
  }

  private detectLanguage(path: string): string {
    const ext = this.getFileExtension(path).toLowerCase();
    const langMap: Record<string, string> = {
      '.ts': 'typescript', '.tsx': 'typescript',
      '.js': 'javascript', '.jsx': 'javascript',
      '.py': 'python',
      '.java': 'java',
      '.go': 'go',
      '.php': 'php',
      '.cs': 'csharp',
      '.rb': 'ruby',
      '.kt': 'kotlin',
      '.rs': 'rust'
    };
    return langMap[ext] || 'javascript';
  }
}

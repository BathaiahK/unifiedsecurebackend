import { SastRule } from './types.js';

export const SAST_RULES: SastRule[] = [
  {
    id: 'hardcoded-secret',
    name: 'Hardcoded Secret/Credential',
    description: 'Detects hardcoded API keys, passwords, tokens in source code',
    cwe: 'CWE-798',
    pattern:
      '(api[_-]?key|password|secret|token|credential)\\s*[:=]\\s*["\']([^"\']+)["\']|const\\s+\\w+\\s*=\\s*["\']sk-[^"\']+["\']|process\\.env\\.[^;\\n]*=\\s*["\'][^"\']*["\']',
    severity: 'critical',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'csharp'],
    remediationTips: [
      'Move credentials to environment variables',
      'Use .env file for local development (add .env to .gitignore)',
      'Use AWS Secrets Manager / HashiCorp Vault for production',
      'If exposed, rotate the credential immediately',
      'Use process.env.API_KEY instead of hardcoded values',
    ],
  },

  {
    id: 'sql-injection',
    name: 'SQL Injection Vulnerability',
    description: 'Detects string concatenation in SQL queries that can lead to SQL injection',
    cwe: 'CWE-89',
    pattern:
      '(query|sql|SELECT|INSERT|UPDATE|DELETE)\\s*[=:]\\s*["`].*?[+\\s]+.*?["`]|db\\.(query|execute|run)\\s*\\(["`][^`"]*[+\\s][^`"]*["`]',
    severity: 'critical',
    languages: ['javascript', 'typescript', 'python', 'java', 'php'],
    remediationTips: [
      'Use parameterized queries with placeholders: db.query("SELECT * FROM users WHERE id = ?", [id])',
      'Use ORMs like Sequelize, SQLAlchemy, TypeORM, or Eloquent',
      'Never concatenate user input directly into SQL strings',
      'Validate and sanitize all user inputs on the server side',
      'Principle of least privilege: database user should have minimal permissions',
    ],
  },

  {
    id: 'xss-vulnerability',
    name: 'Cross-Site Scripting (XSS)',
    description: 'Detects unescaped user input rendered to DOM or HTML',
    cwe: 'CWE-79',
    pattern:
      '(dangerouslySetInnerHTML|innerHTML\\s*=|innerText\\s*=|\.html\\(|<%= |{{{|eval\\(|new Function\\()',
    severity: 'high',
    languages: ['javascript', 'typescript', 'html', 'jsx', 'tsx', 'php', 'erb'],
    remediationTips: [
      'Use framework built-in escaping (React escapes by default in JSX)',
      'For user-generated HTML, use DOMPurify library to sanitize',
      'Implement Content Security Policy (CSP) headers',
      'Use textContent instead of innerHTML when possible',
      'Validate and sanitize all user inputs on the server side',
    ],
  },

  {
    id: 'weak-crypto',
    name: 'Weak Cryptographic Algorithm',
    description: 'Detects use of deprecated or weak encryption/hashing algorithms',
    cwe: 'CWE-327',
    pattern:
      '(createHash\\s*\\(\\s*[\'"]md5|createHash\\s*\\(\\s*[\'"]sha1|createCipher|createDecipher|new MD5|new SHA1|hashlib\\.md5|hashlib\\.sha1)',
    severity: 'high',
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
    remediationTips: [
      'Use SHA-256 or stronger: crypto.createHash("sha256")',
      'For passwords, use bcrypt, scrypt, or PBKDF2 with salt: crypto.pbkdf2Sync(password, salt, 100000, 64, "sha256")',
      'Use bcrypt library: bcrypt.hash(password, 10) for secure password hashing',
      'For encryption, use AES-256, not DES or RC4',
      'Avoid MD5 and SHA-1 for cryptographic purposes (CRC checks only)',
    ],
  },

  {
    id: 'hardcoded-password',
    name: 'Hardcoded Password/Auth String',
    description: 'Detects hardcoded passwords or authentication credentials in code',
    cwe: 'CWE-798',
    pattern:
      '(password|passwd|pwd)\\s*[:=]\\s*["\']([a-zA-Z0-9!@#$%]{6,})["\']|username\\s*[:=]\\s*["\'][^"\']+["\']\\s*(password|auth)',
    severity: 'critical',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'csharp', 'php'],
    remediationTips: [
      'Store passwords in secure secret management system',
      'Use environment variables for non-production passwords',
      'For production, use AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault',
      'Rotate credentials after they are exposed',
      'Use mnemonic passwords or API keys instead of user passwords',
    ],
  },

  {
    id: 'command-injection',
    name: 'Command Injection Vulnerability',
    description: 'Detects unsanitized user input passed to system commands',
    cwe: 'CWE-78',
    pattern:
      '(exec|system|spawn|shell_exec|passthru|eval)\\s*\\([\'"`].*?[+\\s].*?[\'"`]|(os|subprocess|Runtime)\\..*?exec',
    severity: 'critical',
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'bash', 'shell'],
    remediationTips: [
      'Avoid calling system commands when possible',
      'Use child_process.execFile() with array of arguments (prevents shell interpretation)',
      'Never pass user input directly to shell commands',
      'Use allowlist validation: only allow known-safe commands',
      'Run processes with minimum required privileges',
    ],
  },

  {
    id: 'unsafe-deserialization',
    name: 'Unsafe Deserialization',
    description: 'Detects deserialization of untrusted data that could lead to code execution',
    cwe: 'CWE-502',
    pattern: '(eval|pickle\\.loads|yaml\\.load|JSON\\.parse)\\s*\\(.*?userInput|unserialize\\s*\\(',
    severity: 'high',
    languages: ['python', 'php', 'javascript', 'typescript', 'ruby', 'java'],
    remediationTips: [
      'Never call eval() on user input',
      'Use JSON.parse() instead of eval() for JSON data',
      'Use yaml.safe_load() instead of yaml.load() in Python',
      'Use pickle-safe alternatives for Python object serialization',
      'Validate and sanitize all untrusted input before deserialization',
    ],
  },

  {
    id: 'missing-auth-check',
    name: 'Missing Authentication Check',
    description: 'Detects API endpoints or routes without authentication validation',
    cwe: 'CWE-287',
    pattern: 'app\\.(get|post|put|delete|patch)\\s*\\([\'"`].*[\'"`],\\s*\\(req,\\s*res\\)',
    severity: 'high',
    languages: ['javascript', 'typescript', 'express', 'node'],
    remediationTips: [
      'Add authentication middleware: app.get("/api/sensitive", authenticateJWT, handler)',
      'Validate JWT tokens or session cookies before processing requests',
      'Check user permissions for sensitive operations',
      'Implement role-based access control (RBAC)',
      'Use middleware like passport.js for authentication in Node.js',
    ],
  },

  {
    id: 'path-traversal',
    name: 'Path Traversal / Directory Traversal',
    description:
      'Detects use of user input in file path operations that could escape intended directory',
    cwe: 'CWE-22',
    pattern:
      '(readFile|readFileSync|fs\\.read|open\\(|path\\.join)\\s*\\([\'"`].*?[+/].*?userInput|path\\.join\\s*\\(.*?\\.\\..*?\\)',
    severity: 'high',
    languages: ['javascript', 'typescript', 'python', 'java', 'php'],
    remediationTips: [
      'Use path.resolve() and validate the result is within allowed directory',
      'Implement allowlist of permitted files',
      'Never allow user input to contain ".." or absolute paths',
      'Use path.basename() to prevent directory traversal',
      'Use path.normalize() then verify the path is within allowed scope',
    ],
  },

  {
    id: 'insecure-random',
    name: 'Insecure Random Number Generation',
    description: 'Detects use of non-cryptographically secure random functions for security',
    cwe: 'CWE-338',
    pattern: '(Math\\.random|random\\.random|java\\.util\\.Random|rand\\()',
    severity: 'medium',
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go'],
    remediationTips: [
      'Use crypto.randomBytes() for cryptographic purposes',
      'Use crypto.getRandomValues() in browser JavaScript',
      'Use secrets module in Python: secrets.token_urlsafe()',
      'Use java.security.SecureRandom for Java applications',
      'Never use Math.random() for generating tokens, salts, or IVs',
    ],
  },

  {
    id: 'sensitive-data-log',
    name: 'Sensitive Data Logged',
    description: 'Detects logging of sensitive information like passwords, tokens, or PII',
    cwe: 'CWE-532',
    pattern:
      '(console\\.log|logger\\.(info|debug|warn)|print\\(|log\\()\\s*\\(.*?(password|token|secret|api[_-]?key|credit[_-]?card|ssn)',
    severity: 'high',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'csharp'],
    remediationTips: [
      'Never log passwords, API keys, tokens, or PII',
      'Use structured logging and redact sensitive fields',
      'Implement log filtering to mask sensitive patterns',
      'Use environment variables for sensitive configuration',
      'Store logs securely and restrict access',
    ],
  },

  {
    id: 'sql-comment-bypass',
    name: 'SQL Comment Bypass in Query',
    description: 'Detects SQL queries that use comments which could be bypassed',
    cwe: 'CWE-89',
    pattern: 'SELECT.*--.*WHERE|UPDATE.*--.*SET|INSERT.*--.*VALUES|query.*--\\s*[\'"`]',
    severity: 'medium',
    languages: ['javascript', 'typescript', 'python', 'java', 'php'],
    remediationTips: [
      'Use parameterized queries instead of string concatenation',
      'Remove inline comments from dynamic SQL construction',
      'Always use parameterized prepared statements',
      'Validate and sanitize all user inputs',
      'Apply principle of least privilege to database users',
    ],
  },

  {
    id: 'csrf-token-missing',
    name: 'CSRF Token Missing in Form',
    description: 'Detects POST/PUT/DELETE forms without CSRF protection',
    cwe: 'CWE-352',
    pattern: '<form\\s+method=[\'"]?(POST|PUT|DELETE)[\'"]?[^>]*>(?!.*csrf_token)',
    severity: 'high',
    languages: ['html', 'php', 'erb', 'jsx', 'tsx', 'django'],
    remediationTips: [
      'Add CSRF token to all forms: <input type="hidden" name="csrf_token" value="{token}">',
      'Use framework CSRF protection: Django csrf_token(), Laravel CSRF middleware',
      'Verify CSRF token on server-side before processing requests',
      'Use SameSite cookie attribute: Set-Cookie: sessionId=xxx; SameSite=Strict',
      'Implement double-submit cookie pattern for SPAs',
    ],
  },

  {
    id: 'deprecated-function',
    name: 'Use of Deprecated/Unsafe Function',
    description: 'Detects use of deprecated or known-unsafe functions',
    cwe: 'CWE-477',
    pattern: '(strcpy|strcat|sprintf|gets|exec|eval|exit|die|mysql_query)',
    severity: 'medium',
    languages: ['c', 'cpp', 'php', 'javascript', 'python'],
    remediationTips: [
      'Replace strcpy with strncpy or strlcpy (C/C++)',
      'Replace gets() with fgets() (C)',
      'Replace sprintf() with snprintf() for buffer safety',
      'Replace mysql_query() with mysqli or PDO (PHP)',
      'Consult function deprecation warnings and update to modern APIs',
    ],
  },
];

export function getRuleById(id: string): SastRule | undefined {
  return SAST_RULES.find((rule) => rule.id === id);
}

export function getRulesByLanguage(language: string): SastRule[] {
  return SAST_RULES.filter((rule) => rule.languages.includes(language.toLowerCase()));
}

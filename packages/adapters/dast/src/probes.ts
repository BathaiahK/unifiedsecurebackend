import { randomUUID } from 'node:crypto';
import type { DastFinding, DastSeverity } from './types.js';

type RequestCounter = () => void;

function createFinding(
  probeName: string,
  title: string,
  description: string,
  severity: DastSeverity,
  cwe: string | null,
  endpoint: string,
  method: string,
  evidence: string,
  remediation: string[],
  payload?: string,
): DastFinding {
  return {
    id: randomUUID(),
    probeName,
    title,
    description,
    severity,
    cwe,
    endpoint,
    method,
    payload,
    evidence,
    remediation,
  };
}

export async function probeSecurityHeaders(
  targetUrl: string,
  counter: RequestCounter,
): Promise<DastFinding[] | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(targetUrl, { signal: controller.signal, redirect: 'manual' });
    clearTimeout(timeout);
    counter();

    const findings: DastFinding[] = [];
    const headers = res.headers;

    const missingHeaders = [
      { name: 'Content-Security-Policy', cwe: 'CWE-693' },
      { name: 'Strict-Transport-Security', cwe: 'CWE-295' },
      { name: 'X-Frame-Options', cwe: 'CWE-693' },
      { name: 'X-Content-Type-Options', cwe: 'CWE-693' },
      { name: 'Referrer-Policy', cwe: 'CWE-693' },
    ];

    for (const { name, cwe } of missingHeaders) {
      if (!headers.has(name.toLowerCase())) {
        findings.push(
          createFinding(
            'security-headers',
            `Missing ${name} header`,
            `The response is missing the ${name} security header, which helps protect against various attack vectors.`,
            'high',
            cwe,
            targetUrl,
            'GET',
            `Response headers do not include ${name}`,
            [
              `Add ${name} header to HTTP responses`,
              'Configure your web server or application framework to include this header',
            ],
          ),
        );
      }
    }

    return findings.length > 0 ? findings : null;
  } catch (err) {
    return null;
  }
}

export async function probeSqlInjection(
  targetUrl: string,
  counter: RequestCounter,
): Promise<DastFinding | null> {
  try {
    const payloads = ["'", "1' OR '1'='1", "admin' --", "' UNION SELECT NULL --"];
    const testUrl = new URL(targetUrl);
    testUrl.searchParams.set('id', payloads[0]);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(testUrl.toString(), { signal: controller.signal });
    clearTimeout(timeout);
    counter();

    const body = await res.text();
    const sqlErrorPatterns = [
      /syntax error/i,
      /mysql_fetch/i,
      /ORA-\d+/i,
      /SQLite/i,
      /unexpected EOF/i,
    ];

    for (const pattern of sqlErrorPatterns) {
      if (pattern.test(body)) {
        return createFinding(
          'sql-injection',
          'SQL Injection Vulnerability',
          'Application appears vulnerable to SQL injection attacks. SQL error messages are exposed in the response.',
          'critical',
          'CWE-89',
          testUrl.toString(),
          'GET',
          `SQL error pattern detected in response: ${body.substring(0, 100)}...`,
          [
            'Use parameterized queries or prepared statements',
            'Never concatenate user input into SQL queries',
            'Validate and sanitize all user inputs',
            'Apply principle of least privilege to database accounts',
          ],
          payloads[0],
        );
      }
    }

    return null;
  } catch (err) {
    return null;
  }
}

export async function probeXssReflection(
  targetUrl: string,
  counter: RequestCounter,
): Promise<DastFinding | null> {
  try {
    const payload = '<script>alert(1)</script>';
    const testUrl = new URL(targetUrl);
    testUrl.searchParams.set('q', payload);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(testUrl.toString(), { signal: controller.signal });
    clearTimeout(timeout);
    counter();

    const body = await res.text();

    if (body.includes(payload)) {
      return createFinding(
        'xss-reflection',
        'Reflected XSS Vulnerability',
        'User input is reflected in the response without proper encoding, allowing XSS attacks.',
        'high',
        'CWE-79',
        testUrl.toString(),
        'GET',
        `Payload reflected unescaped in response: ${payload}`,
        [
          'HTML-encode all user input before rendering',
          'Use content security policy (CSP) headers',
          'Validate and sanitize all inputs',
          'Use security-focused templating engines',
        ],
        payload,
      );
    }

    return null;
  } catch (err) {
    return null;
  }
}

export async function probeOpenRedirect(
  targetUrl: string,
  counter: RequestCounter,
): Promise<DastFinding | null> {
  try {
    const evilDomain = 'http://evil.example.com/malicious';
    const testUrl = new URL(targetUrl);
    testUrl.searchParams.set('redirect', evilDomain);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(testUrl.toString(), {
      signal: controller.signal,
      redirect: 'manual',
    });
    clearTimeout(timeout);
    counter();

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const location = res.headers.get('location');
      if (location && new URL(location).hostname !== new URL(targetUrl).hostname) {
        return createFinding(
          'open-redirect',
          'Open Redirect Vulnerability',
          'Application redirects to external domains based on user input, enabling phishing attacks.',
          'medium',
          'CWE-601',
          testUrl.toString(),
          'GET',
          `Response redirects to external domain: ${location}`,
          [
            'Maintain a whitelist of allowed redirect destinations',
            'Validate redirect URLs against the whitelist',
            'Avoid using user-supplied input directly in redirects',
            'Use relative URLs when possible',
          ],
          evilDomain,
        );
      }
    }

    return null;
  } catch (err) {
    return null;
  }
}

export async function probePathTraversal(
  targetUrl: string,
  counter: RequestCounter,
): Promise<DastFinding | null> {
  try {
    const paths = [
      '/../../../etc/passwd',
      '/..\\..\\..\\windows\\win.ini',
      '/.env',
      '/.aws/credentials',
    ];

    for (const path of paths) {
      const testUrl = new URL(targetUrl);
      testUrl.pathname = path;

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(testUrl.toString(), { signal: controller.signal });
      clearTimeout(timeout);
      counter();

      const body = await res.text();

      if (/root:x:0:0/.test(body) || /\[DEFAULT\]/.test(body)) {
        return createFinding(
          'path-traversal',
          'Path Traversal Vulnerability',
          'Application exposes sensitive files outside the intended directory through path traversal.',
          'critical',
          'CWE-22',
          testUrl.toString(),
          'GET',
          `Sensitive file accessed: ${path}`,
          [
            'Use path canonicalization functions',
            'Implement strict input validation',
            'Use allowlists for file access',
            'Serve files from a restricted directory only',
            'Never include user input directly in file paths',
          ],
          path,
        );
      }
    }

    return null;
  } catch (err) {
    return null;
  }
}

export async function probeSensitiveFiles(
  targetUrl: string,
  counter: RequestCounter,
): Promise<DastFinding[] | null> {
  try {
    const sensitiveFiles = [
      { path: '/.env', keyword: /^[A-Z_]+=/ },
      { path: '/.git/config', keyword: /\[core\]/ },
      { path: '/package.json', keyword: /"dependencies"/ },
      { path: '/admin', keyword: /admin|dashboard/i },
    ];

    const findings: DastFinding[] = [];

    for (const { path, keyword } of sensitiveFiles) {
      const testUrl = new URL(targetUrl);
      testUrl.pathname = path;

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(testUrl.toString(), { signal: controller.signal });
      clearTimeout(timeout);
      counter();

      if (res.status === 200) {
        const body = await res.text();
        if (keyword.test(body)) {
          findings.push(
            createFinding(
              'sensitive-files',
              `Sensitive File Exposed: ${path}`,
              `The application exposes ${path}, which may contain sensitive configuration or metadata.`,
              'high',
              'CWE-538',
              testUrl.toString(),
              'GET',
              `File accessible and contains sensitive data: ${body.substring(0, 100)}...`,
              [
                `Remove ${path} from web server access`,
                'Configure web server to deny access to sensitive files',
                'Store configuration in environment variables, not files',
                'Use .gitignore to prevent committing sensitive files',
              ],
              path,
            ),
          );
        }
      }
    }

    return findings.length > 0 ? findings : null;
  } catch (err) {
    return null;
  }
}

export async function probeInfoDisclosure(
  targetUrl: string,
  counter: RequestCounter,
): Promise<DastFinding[] | null> {
  try {
    const findings: DastFinding[] = [];

    // Check Server header
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(targetUrl, { signal: controller.signal });
    clearTimeout(timeout);
    counter();

    const server = res.headers.get('server');
    if (server && /\d+\.\d+/.test(server)) {
      findings.push(
        createFinding(
          'info-disclosure-header',
          'Server Information Disclosure',
          'Server header reveals version information that could be used to target known vulnerabilities.',
          'medium',
          'CWE-200',
          targetUrl,
          'GET',
          `Server header exposes version: ${server}`,
          [
            'Customize or hide the Server header',
            'Remove version information from HTTP headers',
            'Configure web server to not reveal version details',
          ],
        ),
      );
    }

    // Check for stack traces on error pages
    const testUrl = new URL(targetUrl);
    testUrl.pathname = '/nonexistent-' + Math.random().toString(36).substring(7);

    const controller2 = new AbortController();
    const timeout2 = setTimeout(() => controller2.abort(), 8000);
    const res2 = await fetch(testUrl.toString(), { signal: controller2.signal });
    clearTimeout(timeout2);
    counter();

    const body = await res2.text();
    if (/\s+at\s+|Traceback|Exception|Error|stack/i.test(body)) {
      findings.push(
        createFinding(
          'info-disclosure-error',
          'Stack Trace Information Disclosure',
          'Error pages display detailed stack traces that reveal sensitive application information.',
          'medium',
          'CWE-209',
          testUrl.toString(),
          'GET',
          `Stack trace or detailed error message visible: ${body.substring(0, 100)}...`,
          [
            'Display generic error messages to users',
            'Log detailed errors server-side only',
            'Implement custom error handling pages',
            'Disable debug mode in production',
          ],
        ),
      );
    }

    return findings.length > 0 ? findings : null;
  } catch (err) {
    return null;
  }
}

export async function probeCorsConfig(
  targetUrl: string,
  counter: RequestCounter,
): Promise<DastFinding | null> {
  try {
    const evilOrigin = 'http://evil.example.com';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(targetUrl, {
      signal: controller.signal,
      headers: { Origin: evilOrigin },
    });
    clearTimeout(timeout);
    counter();

    const acaoHeader = res.headers.get('access-control-allow-origin');
    const acmHeader = res.headers.get('access-control-allow-methods');
    const accHeader = res.headers.get('access-control-allow-credentials');

    if (acaoHeader === '*' && accHeader === 'true') {
      return createFinding(
        'cors-misconfiguration',
        'CORS Misconfiguration',
        'CORS is configured to allow all origins with credentials, enabling cross-origin attacks.',
        'high',
        'CWE-942',
        targetUrl,
        'GET',
        `ACAO: ${acaoHeader}, Allow-Credentials: ${accHeader}`,
        [
          'Specify exact allowed origins, not "*"',
          'Use Access-Control-Allow-Origin: specific-domain',
          'Avoid combining wildcard origin with credentials',
          'Validate all cross-origin requests',
        ],
        evilOrigin,
      );
    }

    return null;
  } catch (err) {
    return null;
  }
}

export async function probeRateLimiting(
  targetUrl: string,
  counter: RequestCounter,
): Promise<DastFinding | null> {
  try {
    const promises = [];
    for (let i = 0; i < 20; i++) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      const p = fetch(targetUrl, { signal: controller.signal }).then((res) => {
        clearTimeout(timeout);
        counter();
        return res.status;
      });
      promises.push(p);
    }

    const statuses = await Promise.all(promises);
    const has429 = statuses.some((status) => status === 429);

    if (!has429) {
      return createFinding(
        'rate-limiting-absent',
        'Missing Rate Limiting',
        'Application does not implement rate limiting, allowing abuse through repeated requests.',
        'medium',
        'CWE-770',
        targetUrl,
        'GET',
        `20 rapid requests accepted without 429 status`,
        [
          'Implement rate limiting per IP/user',
          'Return 429 Too Many Requests when limit exceeded',
          'Use libraries like express-rate-limit or similar',
          'Set reasonable limits based on API usage patterns',
        ],
      );
    }

    return null;
  } catch (err) {
    return null;
  }
}

export async function probeCookieSecurity(
  targetUrl: string,
  counter: RequestCounter,
): Promise<DastFinding[] | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(targetUrl, { signal: controller.signal });
    clearTimeout(timeout);
    counter();

    const setCookieHeaders = res.headers.getSetCookie?.() || [];
    const findings: DastFinding[] = [];

    for (const setCookie of setCookieHeaders) {
      const hasSecure = /Secure/i.test(setCookie);
      const hasHttpOnly = /HttpOnly/i.test(setCookie);
      const hasSameSite = /SameSite/i.test(setCookie);

      if (!hasSecure) {
        findings.push(
          createFinding(
            'cookie-missing-secure',
            'Cookie Missing Secure Flag',
            'Session cookies are transmitted over unencrypted connections, exposing them to interception.',
            'medium',
            'CWE-614',
            targetUrl,
            'GET',
            `Cookie set without Secure flag: ${setCookie.substring(0, 50)}...`,
            [
              'Add Secure flag to all cookies',
              'Enforce HTTPS-only connections',
              'Set Secure flag in Set-Cookie headers',
            ],
            setCookie,
          ),
        );
      }

      if (!hasHttpOnly) {
        findings.push(
          createFinding(
            'cookie-missing-httponly',
            'Cookie Missing HttpOnly Flag',
            'Session cookies can be accessed via JavaScript, enabling XSS attacks to steal sessions.',
            'medium',
            'CWE-1004',
            targetUrl,
            'GET',
            `Cookie set without HttpOnly flag: ${setCookie.substring(0, 50)}...`,
            [
              'Add HttpOnly flag to all sensitive cookies',
              'Prevent JavaScript access to session cookies',
              'Set HttpOnly flag in Set-Cookie headers',
            ],
            setCookie,
          ),
        );
      }

      if (!hasSameSite) {
        findings.push(
          createFinding(
            'cookie-missing-samesite',
            'Cookie Missing SameSite Flag',
            'Cookies can be sent in cross-site requests, enabling CSRF attacks.',
            'medium',
            'CWE-352',
            targetUrl,
            'GET',
            `Cookie set without SameSite flag: ${setCookie.substring(0, 50)}...`,
            [
              'Add SameSite=Strict or SameSite=Lax to cookies',
              'Prevent cookies from being sent in cross-site requests',
              'Set SameSite flag in Set-Cookie headers',
            ],
            setCookie,
          ),
        );
      }
    }

    return findings.length > 0 ? findings : null;
  } catch (err) {
    return null;
  }
}

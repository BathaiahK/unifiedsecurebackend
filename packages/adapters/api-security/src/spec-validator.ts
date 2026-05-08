import { randomUUID } from 'node:crypto';
import type { OpenApiSpec, ApiSecurityFinding, ApiSecuritySeverity } from './types.js';

const SENSITIVE_FIELDS = [
  'password',
  'secret',
  'token',
  'apikey',
  'api_key',
  'auth',
  'ssn',
  'creditcard',
  'credit_card',
  'cvv',
  'pin',
  'privatekey',
  'private_key',
];

function isSensitiveField(name: string): boolean {
  const lower = name.toLowerCase();
  return SENSITIVE_FIELDS.some((field) => lower.includes(field));
}

function getSchemaFieldNames(schema: unknown): string[] {
  if (!schema || typeof schema !== 'object') return [];
  const s = schema as Record<string, unknown>;
  if (s.properties && typeof s.properties === 'object') {
    return Object.keys(s.properties);
  }
  return [];
}

function createFinding(
  category: string,
  title: string,
  description: string,
  severity: ApiSecuritySeverity,
  cwe: string | null,
  endpoint: string | undefined,
  method: string | undefined,
  evidence: string,
  remediation: string[]
): ApiSecurityFinding {
  return {
    id: randomUUID(),
    category: category as any,
    title,
    description,
    severity,
    cwe,
    endpoint,
    method,
    evidence,
    remediation,
  };
}

export class ApiSpecValidator {
  async validate(spec: OpenApiSpec, serviceUrl: string): Promise<ApiSecurityFinding[]> {
    const findings: ApiSecurityFinding[] = [];

    // 1. Check for security schemes definition
    if (!spec.components?.securitySchemes || Object.keys(spec.components.securitySchemes).length === 0) {
      findings.push(
        createFinding(
          'missing-authentication',
          'No security schemes defined in spec',
          'The OpenAPI specification does not define any security schemes (OAuth, API Key, JWT, etc.)',
          'high',
          'CWE-306',
          undefined,
          undefined,
          'components.securitySchemes is missing or empty',
          [
            'Define security schemes in the OpenAPI spec (OAuth2, JWT, API Key, etc.)',
            'Add security requirements to all protected endpoints',
            'Document authentication requirements clearly',
          ]
        )
      );
    }

    // 2. Test each endpoint in real-time
    for (const path in spec.paths) {
      const pathItem = spec.paths[path];

      // Check each HTTP method
      for (const method of ['get', 'post', 'put', 'delete', 'patch']) {
        const operation = (pathItem as any)[method];
        if (!operation) continue;

        const endpoint = `${serviceUrl}${path}`;
        const methodUpper = method.toUpperCase();

        // Test the endpoint in real-time
        const endpointTestFindings = await this.testEndpoint(endpoint, method, path);
        findings.push(...endpointTestFindings);

        // Check for missing authentication on sensitive endpoints
        if (!operation.security && this.isSensitiveEndpoint(path)) {
          findings.push(
            createFinding(
              'missing-authentication',
              `${methodUpper} ${path} missing authentication`,
              `Sensitive endpoint does not declare security requirements`,
              'critical',
              'CWE-306',
              endpoint,
              methodUpper,
              `No security declaration for protected resource`,
              [
                'Add security requirements to this endpoint',
                'Use @security decorator or security field in spec',
                'Ensure all sensitive operations require authentication',
              ]
            )
          );
        }

        // Check response for sensitive data exposure
        if (operation.responses) {
          for (const statusCode in operation.responses) {
            const response = operation.responses[statusCode];
            if (response.content) {
              for (const contentType in response.content) {
                const schema = (response.content[contentType] as any)?.schema;
                const fields = getSchemaFieldNames(schema);

                for (const field of fields) {
                  if (isSensitiveField(field)) {
                    findings.push(
                      createFinding(
                        'sensitive-data-exposure',
                        `Sensitive field '${field}' exposed in ${method.toUpperCase()} ${path}`,
                        `The API response may expose sensitive information: ${field}`,
                        'high',
                        'CWE-200',
                        endpoint,
                        method.toUpperCase(),
                        `Field '${field}' found in response schema for status ${statusCode}`,
                        [
                          `Remove or encrypt the '${field}' field from the response`,
                          'Use separate DTOs for internal vs external responses',
                          'Implement field-level encryption for sensitive data',
                          'Use @Exclude or similar decorators to hide fields',
                        ]
                      )
                    );
                  }
                }
              }
            }
          }
        }

        // Check for overly permissive parameters
        if (operation.requestBody) {
          const schema = (operation.requestBody?.content?.['application/json'] as any)?.schema;
          if (schema && !schema.additionalProperties === false) {
            findings.push(
              createFinding(
                'overly-permissive',
                `Request body allows undefined properties at ${method.toUpperCase()} ${path}`,
                'The request body schema does not restrict additional properties, allowing arbitrary data injection',
                'medium',
                'CWE-20',
                endpoint,
                method.toUpperCase(),
                'Schema missing additionalProperties: false constraint',
                [
                  'Set additionalProperties: false in the request schema',
                  'Implement strict input validation',
                  'Whitelist only expected fields',
                  'Reject requests with unexpected properties',
                ]
              )
            );
          }
        }
      }
    }

    // 3. Check for missing rate limiting documentation
    if (
      !spec.info.description?.toLowerCase().includes('rate limit') &&
      !spec.info.description?.toLowerCase().includes('throttle')
    ) {
      findings.push(
        createFinding(
          'missing-rate-limiting',
          'Rate limiting not documented in API spec',
          'The API specification does not document rate limiting or throttling behavior',
          'medium',
          'CWE-770',
          undefined,
          undefined,
          'API info does not mention rate limiting',
          [
            'Document rate limits in the API specification',
            'Add rate-limit headers to responses (X-RateLimit-Limit, X-RateLimit-Remaining)',
            'Implement rate limiting in the API gateway',
            'Return 429 Too Many Requests when limits exceeded',
          ]
        )
      );
    }

    // 4. Check for missing CORS documentation
    const hasCorsDocs = spec.servers?.some((s) => s.url?.includes('cors')) ||
      spec.info.description?.toLowerCase().includes('cors') ||
      false;

    if (!hasCorsDocs) {
      findings.push(
        createFinding(
          'cors-misconfiguration',
          'CORS policy not documented in API spec',
          'The API specification does not document CORS (Cross-Origin Resource Sharing) policy',
          'medium',
          'CWE-942',
          undefined,
          undefined,
          'No CORS information in spec or server definitions',
          [
            'Document allowed origins in OpenAPI spec or API documentation',
            'Set appropriate Access-Control-Allow-Origin headers',
            'Avoid wildcard origins with credentials',
            'Document CORS preflight behavior',
          ]
        )
      );
    }

    // 5. Check for missing error documentation
    const needsErrorDocs = !spec.info.description?.toLowerCase().includes('error') ||
      !spec.info.description?.toLowerCase().includes('exception');

    if (needsErrorDocs) {
      findings.push(
        createFinding(
          'poor-error-handling',
          'Error responses not documented in API spec',
          'The API specification does not document error responses or error codes',
          'low',
          'CWE-209',
          undefined,
          undefined,
          'Missing error response documentation',
          [
            'Document all possible error codes and status codes',
            'Avoid exposing stack traces or internal details',
            'Return generic error messages to clients',
            'Log detailed errors server-side only',
          ]
        )
      );
    }

    // 6. Check for API versioning
    if (!spec.info.version) {
      findings.push(
        createFinding(
          'api-versioning',
          'API version not specified in spec',
          'The OpenAPI specification does not include a clear version number',
          'low',
          null,
          undefined,
          undefined,
          'Missing info.version field',
          ['Add version to OpenAPI spec (info.version)', 'Use semantic versioning', 'Document breaking changes']
        )
      );
    }

    // 7. Check for schema design flaws - missing required fields
    if (spec.components?.schemas) {
      for (const schemaName in spec.components.schemas) {
        const schema = spec.components.schemas[schemaName] as any;
        if (schema.properties && !schema.required) {
          findings.push(
            createFinding(
              'schema-design-flaw',
              `Schema '${schemaName}' does not define required fields`,
              'The schema defines properties but does not specify which fields are required',
              'medium',
              'CWE-20',
              undefined,
              undefined,
              `Schema ${schemaName} missing 'required' array`,
              [
                `Add 'required' array to schema ${schemaName}`,
                'Define which fields are mandatory',
                'Validate required fields at API boundaries',
              ]
            )
          );
        }
      }
    }

    return findings;
  }

  private isSensitiveEndpoint(path: string): boolean {
    const sensitivePatterns = ['/api/users', '/api/auth', '/api/admin', '/api/settings', '/api/secrets'];
    return sensitivePatterns.some((pattern) => path.toLowerCase().startsWith(pattern));
  }

  private async testEndpoint(endpoint: string, method: string, path: string): Promise<ApiSecurityFinding[]> {
    const findings: ApiSecurityFinding[] = [];
    const methodUpper = method.toUpperCase();

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3000);

      const res = await fetch(endpoint, {
        method: methodUpper,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'Origin': 'http://test-origin.example.com',
        },
      });
      clearTimeout(timeout);

      // 1. Check for missing security headers on response
      const headerIssues = this.checkSecurityHeaders(res, endpoint, methodUpper, path);
      findings.push(...headerIssues);

      // 2. Check for authentication requirements
      if (res.status === 200 && this.isSensitiveEndpoint(path)) {
        findings.push(
          createFinding(
            'missing-authentication',
            `${methodUpper} ${path} accessible without authentication`,
            `Sensitive endpoint returned 200 without credentials`,
            'critical',
            'CWE-306',
            endpoint,
            methodUpper,
            `Endpoint accessible without API key, bearer token, or auth header`,
            [
              'Add authentication middleware to this endpoint',
              'Validate Authorization header before processing',
              'Return 401 Unauthorized for unauthenticated requests',
            ]
          )
        );
      }

      // 3. Check for info disclosure in error responses
      if (res.status === 404 || res.status === 500) {
        const body = await res.text();
        if (body.includes('stack') || body.includes('Error') || body.includes('Exception')) {
          findings.push(
            createFinding(
              'poor-error-handling',
              `${methodUpper} ${path} exposes error details`,
              `Error response at ${endpoint} reveals internal implementation`,
              'medium',
              'CWE-209',
              endpoint,
              methodUpper,
              `Error message: ${body.substring(0, 80)}...`,
              [
                'Return generic error messages to clients',
                'Log detailed errors server-side only',
                'Don\'t expose stack traces in HTTP responses',
                'Use error codes instead of error messages',
              ]
            )
          );
        }
      }

      // 4. Check CORS configuration
      const corsHeader = res.headers.get('access-control-allow-origin');
      if (corsHeader === '*') {
        const credentialsHeader = res.headers.get('access-control-allow-credentials');
        if (credentialsHeader === 'true') {
          findings.push(
            createFinding(
              'cors-misconfiguration',
              `${methodUpper} ${path} has insecure CORS config`,
              `CORS allows wildcard origin with credentials enabled`,
              'high',
              'CWE-942',
              endpoint,
              methodUpper,
              `Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true`,
              [
                'Set specific allowed origins instead of *',
                'Never combine * origin with credentials',
                'Use Access-Control-Allow-Origin: https://trusted-domain.com',
              ]
            )
          );
        }
      }

      // 5. Check for rate limiting headers
      if (!res.headers.get('x-ratelimit-limit')) {
        findings.push(
          createFinding(
            'missing-rate-limiting',
            `${methodUpper} ${path} missing rate limit headers`,
            `Response does not include rate limiting headers`,
            'medium',
            'CWE-770',
            endpoint,
            methodUpper,
            `Missing: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset`,
            [
              'Add X-RateLimit-Limit header to responses',
              'Include X-RateLimit-Remaining to show remaining quota',
              'Return 429 Too Many Requests when limit exceeded',
            ]
          )
        );
      }
    } catch (err) {
      // Endpoint not accessible - could be network or auth issue
      const errMsg = String(err);
      if (errMsg.includes('abort')) {
        findings.push(
          createFinding(
            'poor-error-handling',
            `${methodUpper} ${path} times out (>3s)`,
            `Endpoint takes too long to respond`,
            'low',
            null,
            endpoint,
            methodUpper,
            `Request timeout after 3 seconds - possible performance issue`,
            [
              'Optimize endpoint performance',
              'Add caching for frequently accessed data',
              'Consider pagination for large datasets',
            ]
          )
        );
      }
    }

    return findings;
  }

  private checkSecurityHeaders(
    res: Response,
    endpoint: string,
    method: string,
    path: string
  ): ApiSecurityFinding[] {
    const findings: ApiSecurityFinding[] = [];
    const requiredHeaders = [
      { name: 'Content-Security-Policy', cwe: 'CWE-693', severity: 'high' as const },
      { name: 'X-Frame-Options', cwe: 'CWE-693', severity: 'medium' as const },
      { name: 'X-Content-Type-Options', cwe: 'CWE-693', severity: 'medium' as const },
    ];

    for (const header of requiredHeaders) {
      if (!res.headers.get(header.name.toLowerCase())) {
        findings.push(
          createFinding(
            'poor-error-handling',
            `${method} ${path} missing ${header.name}`,
            `Security header not present in response`,
            header.severity,
            header.cwe,
            endpoint,
            method,
            `Missing header: ${header.name}`,
            [
              `Add ${header.name} header to all responses`,
              'Configure in web server or application middleware',
            ]
          )
        );
      }
    }

    return findings;
  }
}

import type { OpenApiSpec } from './types.js';

export class ApiSpecDiscoverer {
  async discoverSpec(serviceUrl: string): Promise<OpenApiSpec> {
    // 1. Try to fetch existing OpenAPI spec from common locations
    const commonPaths = [
      '/openapi.json',
      '/api-docs',
      '/swagger.json',
      '/v3/api-docs',
      '/api/v1/docs',
      '/docs/openapi.json',
    ];

    for (const path of commonPaths) {
      try {
        const spec = await this.fetchSpec(`${serviceUrl}${path}`);
        if (spec) return spec;
      } catch {
        // Continue to next path
      }
    }

    // 2. If no spec found, try to discover from health/info endpoints
    const spec = await this.generateSpecFromService(serviceUrl);
    return spec;
  }

  private async fetchSpec(url: string): Promise<OpenApiSpec | null> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);

      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timeout);

      if (!res.ok) return null;

      const data = (await res.json()) as Record<string, unknown>;

      // Validate basic OpenAPI structure
      if (data.openapi || data.swagger) {
        return data as unknown as OpenApiSpec;
      }

      return null;
    } catch {
      return null;
    }
  }

  private async generateSpecFromService(serviceUrl: string): Promise<OpenApiSpec> {
    // Fetch service metadata
    let title = 'Unknown API';
    let version = '1.0.0';
    let description = 'Auto-discovered API specification';

    try {
      // Try to get service info
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3000);

      const res = await fetch(`${serviceUrl}/health`, { signal: controller.signal });
      clearTimeout(timeout);

      if (res.ok) {
        const health = (await res.json()) as Record<string, unknown>;
        if (typeof health.service === 'string') title = health.service;
      }
    } catch {
      // Ignore errors, use defaults
    }

    // Generate basic OpenAPI spec
    const spec: OpenApiSpec = {
      openapi: '3.0.0',
      info: {
        title,
        version,
        description,
      },
      servers: [
        {
          url: serviceUrl,
          description: 'API Server',
        },
      ],
      paths: await this.discoverEndpoints(serviceUrl),
      components: {
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
          },
        },
      },
    };

    return spec;
  }

  private async discoverEndpoints(serviceUrl: string): Promise<Record<string, any>> {
    const paths: Record<string, any> = {};

    // Common API patterns to test
    const commonEndpoints = [
      { path: '/api/health', method: 'GET', description: 'Health check' },
      { path: '/api/scans', method: 'GET', description: 'List scans' },
      { path: '/api/scans', method: 'POST', description: 'Create scan' },
      { path: '/api/scans/:id', method: 'GET', description: 'Get scan details' },
      { path: '/api/findings', method: 'GET', description: 'List findings' },
      { path: '/api/findings/:id', method: 'GET', description: 'Get finding details' },
      { path: '/api/stats', method: 'GET', description: 'Get statistics' },
      { path: '/api/assets', method: 'GET', description: 'List assets' },
    ];

    for (const endpoint of commonEndpoints) {
      try {
        const url = endpoint.path.replace(/:id/g, 'test-id');
        const fullUrl = `${serviceUrl}${url}`;

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 2000);

        const res = await fetch(fullUrl, {
          method: endpoint.method,
          signal: controller.signal,
        });
        clearTimeout(timeout);

        // If endpoint exists (not 404), add to spec
        if (res.status !== 404) {
          const pathKey = endpoint.path;

          if (!paths[pathKey]) {
            paths[pathKey] = {};
          }

          paths[pathKey][endpoint.method.toLowerCase()] = {
            summary: endpoint.description,
            operationId: `${endpoint.method.toLowerCase()}${pathKey.replace(/\//g, '_')}`,
            responses: {
              '200': {
                description: 'Success',
              },
              '401': {
                description: 'Unauthorized',
              },
              '404': {
                description: 'Not Found',
              },
            },
          };
        }
      } catch {
        // Endpoint not accessible, skip
      }
    }

    return paths;
  }
}

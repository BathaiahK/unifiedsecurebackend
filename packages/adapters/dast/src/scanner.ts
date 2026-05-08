import type { DastFinding } from './types.js';
import {
  probeSecurityHeaders,
  probeSqlInjection,
  probeXssReflection,
  probeOpenRedirect,
  probePathTraversal,
  probeSensitiveFiles,
  probeInfoDisclosure,
  probeCorsConfig,
  probeRateLimiting,
  probeCookieSecurity,
} from './probes.js';

export class DastScanner {
  async run(targetUrl: string): Promise<{
    findings: DastFinding[];
    requestCount: number;
    endpointsTested: string[];
  }> {
    let requestCount = 0;
    const counter = () => {
      requestCount++;
    };

    const results = await Promise.allSettled([
      probeSecurityHeaders(targetUrl, counter),
      probeSqlInjection(targetUrl, counter),
      probeXssReflection(targetUrl, counter),
      probeOpenRedirect(targetUrl, counter),
      probePathTraversal(targetUrl, counter),
      probeSensitiveFiles(targetUrl, counter),
      probeInfoDisclosure(targetUrl, counter),
      probeCorsConfig(targetUrl, counter),
      probeRateLimiting(targetUrl, counter),
      probeCookieSecurity(targetUrl, counter),
    ]);

    const findings: DastFinding[] = [];
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) {
        if (Array.isArray(r.value)) {
          findings.push(...r.value);
        } else {
          findings.push(r.value);
        }
      }
    }

    const endpointsTested = [...new Set(findings.map((f) => f.endpoint))];
    if (endpointsTested.length === 0) {
      endpointsTested.push(targetUrl);
    }

    return { findings, requestCount, endpointsTested };
  }
}

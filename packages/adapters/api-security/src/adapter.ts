import { randomUUID } from 'node:crypto';
import type { ScannerAdapter, ScanConfig, ScanStatus, UnifiedFinding } from '@usp/schema';
import type { ApiSecurityFinding, ApiSecurityReport, ApiSecuritySummary } from './types.js';
import { ApiSpecValidator } from './spec-validator.js';
import { ApiSpecDiscoverer } from './spec-discoverer.js';

interface PendingScan {
  report: ApiSecurityReport;
  startTime: number;
  completed: boolean;
}

export class ApiSecurityAdapter implements ScannerAdapter {
  readonly tool = 'api-security';
  private pendingScans = new Map<string, PendingScan>();
  private validator = new ApiSpecValidator();
  private discoverer = new ApiSpecDiscoverer();

  async trigger(config: ScanConfig): Promise<{ scanId: string }> {
    const scanId = `api-security-${Date.now()}-${randomUUID().slice(0, 8)}`;
    const serviceUrl = ((config.options?.serviceUrl as string | undefined) ?? 'http://localhost:4000').replace(/\/$/, '');
    const specUrl = config.options?.specUrl as string | undefined;

    const report: ApiSecurityReport = {
      scanId,
      specUrl: specUrl ?? serviceUrl,
      serviceUrl,
      specTitle: '',
      specVersion: '',
      totalEndpoints: 0,
      findings: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      scanDurationMs: 0,
    };

    this.pendingScans.set(scanId, { report, startTime: Date.now(), completed: false });
    this.performScan(scanId, serviceUrl, specUrl).catch((err) => {
      console.error(`API Security scan ${scanId} failed:`, err);
      const scan = this.pendingScans.get(scanId);
      if (scan) scan.completed = true;
    });

    return { scanId };
  }

  async poll(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const scan = this.pendingScans.get(scanId);
    if (!scan) return { status: 'failed', progress: 0 };
    if (scan.completed) return { status: 'complete', progress: 100 };
    const elapsed = Date.now() - scan.startTime;
    return { status: 'running', progress: Math.min(90, Math.floor((elapsed / 10000) * 100)) };
  }

  async normalize(raw: unknown): Promise<UnifiedFinding[]> {
    const scanId = raw as string;
    const scan = this.pendingScans.get(scanId);
    if (!scan || scan.report.findings.length === 0) return [];

    return scan.report.findings.map((f) => ({
      id: randomUUID(),
      tool: 'api-security' as const,
      severity: f.severity,
      cvss: null,
      cve: null,
      cwe: f.cwe,
      asset: scan.report.serviceUrl,
      status: 'open' as const,
      fixVersion: null,
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      title: f.title,
      remediationSteps: f.remediation,
      references: [],
      evidence: {
        category: f.category,
        endpoint: f.endpoint,
        method: f.method,
        evidence: f.evidence,
      },
      scanId: randomUUID(),
    } as UnifiedFinding));
  }

  async store() {
    // stub - API layer handles persistence
  }

  getApiSecurityReport(scanId: string): ApiSecuritySummary | null {
    const scan = this.pendingScans.get(scanId);
    if (!scan?.completed) return null;

    const { findings, summary, specTitle, specVersion, totalEndpoints, scanDurationMs } = scan.report;

    // Group findings by category to find top issues
    const categoryCount = new Map<string, number>();
    for (const finding of findings) {
      const count = categoryCount.get(finding.category) ?? 0;
      categoryCount.set(finding.category, count + 1);
    }

    const topIssues = [...categoryCount.entries()]
      .map(([category, count]) => ({ category: category as any, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return {
      specTitle,
      specVersion,
      totalEndpoints,
      totalFindings: summary.total,
      bySeverity: {
        critical: summary.critical,
        high: summary.high,
        medium: summary.medium,
        low: summary.low,
      },
      topIssues,
      scanDurationMs,
    };
  }

  private async performScan(scanId: string, serviceUrl: string, specUrl?: string): Promise<void> {
    const scan = this.pendingScans.get(scanId)!;
    try {
      // Discover or fetch OpenAPI spec
      let spec;
      if (specUrl) {
        spec = await this.fetchSpecFromUrl(specUrl);
      } else {
        spec = await this.discoverer.discoverSpec(serviceUrl);
      }

      // Update report with spec info
      scan.report.specTitle = spec.info.title;
      scan.report.specVersion = spec.info.version;
      scan.report.totalEndpoints = Object.keys(spec.paths || {}).length;

      // Validate spec for security issues
      const findings = await this.validator.validate(spec, serviceUrl);

      scan.report.findings = findings;
      scan.report.summary = {
        total: findings.length,
        critical: findings.filter((f) => f.severity === 'critical').length,
        high: findings.filter((f) => f.severity === 'high').length,
        medium: findings.filter((f) => f.severity === 'medium').length,
        low: findings.filter((f) => f.severity === 'low').length,
      };
      scan.report.scanDurationMs = Date.now() - scan.startTime;
    } finally {
      scan.completed = true;
    }
  }

  private async fetchSpecFromUrl(specUrl: string): Promise<any> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);

      const res = await fetch(specUrl, { signal: controller.signal });
      clearTimeout(timeout);

      if (!res.ok) throw new Error(`Failed to fetch spec: ${res.status}`);

      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('json')) {
        return await res.json();
      } else if (contentType.includes('yaml') || contentType.includes('yml')) {
        // For YAML, we'd need a parser. For now, assume JSON or text that can be parsed
        const text = await res.text();
        try {
          return JSON.parse(text);
        } catch {
          throw new Error('Spec URL returned non-JSON content. Please provide a JSON OpenAPI spec.');
        }
      } else {
        const text = await res.text();
        return JSON.parse(text);
      }
    } catch (err) {
      throw new Error(`Failed to fetch OpenAPI spec from ${specUrl}: ${String(err)}`);
    }
  }
}

import { randomUUID } from 'node:crypto';
import type { ScannerAdapter, ScanConfig, ScanStatus, UnifiedFinding } from '@usp/schema';
import type { DastFinding, DastReport, DastSummary } from './types.js';
import { DastScanner } from './scanner.js';

interface PendingScan {
  report: DastReport;
  startTime: number;
  completed: boolean;
}

export class DastAdapter implements ScannerAdapter {
  readonly tool = 'dast';
  private pendingScans = new Map<string, PendingScan>();
  private scanner = new DastScanner();

  async trigger(config: ScanConfig): Promise<{ scanId: string }> {
    const scanId = `dast-${Date.now()}-${randomUUID().slice(0, 8)}`;
    const targetUrl = (config.options?.targetUrl as string | undefined) ?? 'http://localhost:4000';

    const report: DastReport = {
      scanId,
      targetUrl,
      startedAt: new Date().toISOString(),
      completedAt: '',
      scanDurationMs: 0,
      totalRequests: 0,
      endpointsTested: [],
      findings: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    };

    this.pendingScans.set(scanId, { report, startTime: Date.now(), completed: false });
    this.performScan(scanId, targetUrl).catch((err) => {
      console.error(`DAST scan ${scanId} failed:`, err);
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
    return { status: 'running', progress: Math.min(90, Math.floor((elapsed / 20000) * 100)) };
  }

  async normalize(raw: unknown): Promise<UnifiedFinding[]> {
    const scanId = raw as string;
    const scan = this.pendingScans.get(scanId);
    if (!scan || scan.report.findings.length === 0) return [];

    return scan.report.findings.map(
      (f) =>
        ({
          id: randomUUID(),
          tool: 'dast' as const,
          severity: f.severity === 'info' ? 'info' : f.severity,
          cvss: null,
          cve: null,
          cwe: f.cwe,
          asset: scan.report.targetUrl,
          status: 'open' as const,
          fixVersion: null,
          firstSeen: scan.report.startedAt,
          lastSeen: scan.report.completedAt || scan.report.startedAt,
          title: f.title,
          remediationSteps: f.remediation,
          references: [],
          evidence: {
            endpoint: f.endpoint,
            method: f.method,
            payload: f.payload,
            evidence: f.evidence,
            probeName: f.probeName,
          },
          scanId: randomUUID(),
        }) as UnifiedFinding,
    );
  }

  async store() {
    // stub - API layer handles persistence
  }

  getDastReport(scanId: string): DastSummary | null {
    const scan = this.pendingScans.get(scanId);
    if (!scan?.completed) return null;

    const { findings, summary, targetUrl, scanDurationMs, endpointsTested, totalRequests } =
      scan.report;

    return {
      targetUrl,
      totalFindings: summary.total,
      bySeverity: {
        critical: summary.critical,
        high: summary.high,
        medium: summary.medium,
        low: summary.low,
      },
      endpointsTested: endpointsTested.length,
      totalRequests,
      scanDurationMs,
      topVulnerabilities: findings
        .slice(0, 5)
        .map((f) => ({ name: f.title, severity: f.severity, endpoint: f.endpoint })),
    };
  }

  private async performScan(scanId: string, targetUrl: string): Promise<void> {
    const scan = this.pendingScans.get(scanId)!;
    try {
      const { findings, requestCount, endpointsTested } = await this.scanner.run(targetUrl);
      scan.report.findings = findings;
      scan.report.totalRequests = requestCount;
      scan.report.endpointsTested = endpointsTested;
      scan.report.completedAt = new Date().toISOString();
      scan.report.scanDurationMs = Date.now() - scan.startTime;
      scan.report.summary = {
        total: findings.length,
        critical: findings.filter((f) => f.severity === 'critical').length,
        high: findings.filter((f) => f.severity === 'high').length,
        medium: findings.filter((f) => f.severity === 'medium').length,
        low: findings.filter((f) => f.severity === 'low').length,
        info: findings.filter((f) => f.severity === 'info').length,
      };
    } finally {
      scan.completed = true;
    }
  }
}

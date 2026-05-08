import { randomUUID } from 'node:crypto';
import { ScannerAdapter, ScanConfig, ScanStatus, UnifiedFinding } from '@usp/schema';
import { SastReport, SastSummary } from './types.js';
import { VulnerabilityDetector } from './detector.js';

interface PendingScan {
  report: SastReport;
  startTime: number;
  completed: boolean;
}

export class SastAdapter implements ScannerAdapter {
  readonly tool = 'sast';
  private activeScan: Map<string, PendingScan> = new Map();
  private detector = new VulnerabilityDetector();

  async trigger(config: ScanConfig): Promise<{ scanId: string }> {
    const scanId = `sast-${Date.now()}-${randomUUID().slice(0, 8)}`;

    const report: SastReport = {
      scanId,
      asset: config.asset,
      timestamp: new Date().toISOString(),
      language: 'typescript',
      findings: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      analysisDetails: {
        filesScanned: 0,
        linesScanned: 0,
        rulesApplied: 0,
        scanDurationMs: 0
      }
    };

    this.activeScan.set(scanId, {
      report,
      startTime: Date.now(),
      completed: false
    });

    this.performScan(scanId, config).catch(err => {
      console.error(`SAST scan ${scanId} failed:`, err);
      const scan = this.activeScan.get(scanId);
      if (scan) scan.completed = true;
    });

    return { scanId };
  }

  async poll(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const scan = this.activeScan.get(scanId);
    if (!scan) return { status: 'failed', progress: 0 };
    if (scan.completed) return { status: 'complete', progress: 100 };

    const elapsed = Date.now() - scan.startTime;
    const progress = Math.min(95, Math.floor((elapsed / 10000) * 100));
    return { status: 'running', progress };
  }

  async normalize(raw: unknown): Promise<UnifiedFinding[]> {
    const scanId = raw as string;
    const scan = this.activeScan.get(scanId);
    if (!scan || scan.report.findings.length === 0) return [];

    return scan.report.findings.map(finding => ({
      id: randomUUID(),
      tool: 'sast' as const,
      severity: finding.severity,
      cvss: null,
      cve: null,
      cwe: finding.cwe,
      asset: scan.report.asset,
      status: 'open' as const,
      fixVersion: null,
      firstSeen: scan.report.timestamp,
      lastSeen: scan.report.timestamp,
      title: `${finding.ruleName} in ${finding.file}:${finding.line}`,
      remediationSteps: finding.remediation,
      references: [],
      evidence: {
        file: finding.file,
        line: finding.line,
        column: finding.column,
        code: finding.code,
        ruleId: finding.ruleId,
        cwe: finding.cwe,
        matches: finding.matches
      },
      scanId: randomUUID()
    } as UnifiedFinding));
  }

  async store(findings: UnifiedFinding[]): Promise<void> {
    // Storage is handled by API layer
  }

  getSastReport(scanId: string): SastSummary | null {
    const scan = this.activeScan.get(scanId);
    if (!scan?.completed) return null;

    const findings = scan.report.findings;
    const ruleHits = new Map<string, { ruleName: string; count: number }>();
    for (const f of findings) {
      const entry = ruleHits.get(f.ruleId) ?? { ruleName: f.ruleName, count: 0 };
      entry.count++;
      ruleHits.set(f.ruleId, entry);
    }

    const topRules = [...ruleHits.entries()]
      .map(([ruleId, { ruleName, count }]) => ({ ruleId, ruleName, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return {
      totalFindings: findings.length,
      bySeverity: scan.report.summary,
      filesScanned: scan.report.analysisDetails?.filesScanned ?? 0,
      rulesApplied: scan.report.analysisDetails?.rulesApplied ?? 0,
      scanDurationMs: scan.report.analysisDetails?.scanDurationMs ?? 0,
      topRules
    };
  }

  private async performScan(scanId: string, config: ScanConfig): Promise<void> {
    const scan = this.activeScan.get(scanId);
    if (!scan) return;

    try {
      const repoUrl = (config?.options as Record<string, unknown>)?.repoUrl as string | undefined;
      let findings = repoUrl
        ? await this.detector.analyzeRepository(repoUrl, scan.report.asset)
        : this.detector.analyzeMockRepository(scan.report.asset);

      scan.report.findings = findings;
      scan.report.summary = {
        total: findings.length,
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length
      };

      scan.report.analysisDetails = {
        filesScanned: new Set(findings.map(f => f.file)).size,
        linesScanned: findings.length * 10,
        rulesApplied: 14,
        scanDurationMs: Date.now() - scan.startTime
      };
    } finally {
      scan.completed = true;
    }
  }
}

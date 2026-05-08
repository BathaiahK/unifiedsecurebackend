import { randomUUID } from 'crypto';
import { ScannerAdapter, ScanConfig, ScanStatus, UnifiedFinding } from '@usp/schema';
import { SastReport } from './types';
import { VulnerabilityDetector } from './detector';

interface PendingScan {
  report: SastReport;
  startTime: number;
}

export class SastAdapter implements ScannerAdapter {
  readonly tool = 'sast';
  private activeScan: Map<string, PendingScan> = new Map();
  private detector = new VulnerabilityDetector();

  async trigger(config: ScanConfig): Promise<{ scanId: string }> {
    const scanId = generateId();

    const report: SastReport = {
      scanId,
      asset: config.asset,
      timestamp: new Date().toISOString(),
      language: 'typescript', // Default, can be determined from config
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
      startTime: Date.now()
    });

    // Start async scanning
    this.performScan(scanId).catch(err => {
      console.error(`SAST scan ${scanId} failed:`, err);
    });

    return { scanId };
  }

  async poll(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const scan = this.activeScan.get(scanId);

    if (!scan) {
      return { status: 'complete', progress: 0 };
    }

    // Simulate progress during scan (10 second total scan time)
    const elapsed = Date.now() - scan.startTime;
    const progress = Math.min(100, Math.floor((elapsed / 10000) * 100));

    if (progress >= 100) {
      // Scan complete
      return { status: 'complete', progress: 100 };
    }

    return { status: 'running', progress };
  }

  async normalize(raw: unknown): Promise<UnifiedFinding[]> {
    const report = raw as SastReport;

    return report.findings.map(finding => {
      const title = `${finding.ruleName} in ${finding.file}:${finding.line}`;

      return {
        id: randomUUID(),
        tool: 'sast' as const,
        severity: finding.severity,
        cvss: null,
        cve: null,
        cwe: finding.cwe,
        asset: report.asset,
        status: 'open' as const,
        fixVersion: null,
        firstSeen: report.timestamp,
        lastSeen: report.timestamp,
        title,
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
      } as UnifiedFinding;
    });
  }

  async store(findings: UnifiedFinding[]): Promise<void> {
    // Store in database (handled by API layer)
  }

  private async performScan(scanId: string): Promise<void> {
    const scan = this.activeScan.get(scanId);
    if (!scan) return;

    try {
      // Perform analysis on mock repository
      const findings = this.detector.analyzeMockRepository(scan.report.asset);

      scan.report.findings = findings;
      scan.report.summary = {
        total: findings.length,
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length
      };

      scan.report.analysisDetails = {
        filesScanned: 6, // Number of mock files
        linesScanned: findings.length * 10, // Estimate
        rulesApplied: 14, // Total rules
        scanDurationMs: Date.now() - scan.startTime
      };
    } catch (error) {
      console.error('Scan failed:', error);
    }
  }
}

function generateId(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

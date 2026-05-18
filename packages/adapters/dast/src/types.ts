export type DastSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface DastFinding {
  id: string;
  probeName: string;
  title: string;
  description: string;
  severity: DastSeverity;
  cwe: string | null;
  endpoint: string;
  method: string;
  payload?: string;
  evidence: string;
  remediation: string[];
}

export interface DastReport {
  scanId: string;
  targetUrl: string;
  startedAt: string;
  completedAt: string;
  scanDurationMs: number;
  totalRequests: number;
  endpointsTested: string[];
  findings: DastFinding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface DastSummary {
  targetUrl: string;
  totalFindings: number;
  bySeverity: { critical: number; high: number; medium: number; low: number };
  endpointsTested: number;
  totalRequests: number;
  scanDurationMs: number;
  topVulnerabilities: Array<{ name: string; severity: string; endpoint: string }>;
}

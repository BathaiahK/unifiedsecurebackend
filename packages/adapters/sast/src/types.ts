export interface SastRule {
  id: string;
  name: string;
  description: string;
  cwe: string;
  pattern: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  languages: string[];
  remediationTips: string[];
}

export interface SastMatch {
  file: string;
  line: number;
  column: number;
  lineContent: string;
  matchedText: string;
}

export interface SastFinding {
  id: string;
  ruleId: string;
  ruleName: string;
  file: string;
  line: number;
  column: number;
  code: string;
  message: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cwe: string;
  remediation: string[];
  matches: SastMatch[];
}

export interface SastReport {
  scanId: string;
  asset: string;
  timestamp: string;
  language: string;
  findings: SastFinding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  analysisDetails?: {
    filesScanned: number;
    linesScanned: number;
    rulesApplied: number;
    scanDurationMs: number;
  };
}

export interface SastSummary {
  totalFindings: number;
  bySeverity: { total: number; critical: number; high: number; medium: number; low: number };
  filesScanned: number;
  rulesApplied: number;
  scanDurationMs: number;
  topRules: Array<{ ruleId: string; ruleName: string; count: number }>;
}

import type { ScanConfig, ScanStatus } from './scan.js';
import type { UnifiedFinding } from './finding.js';

export interface ScannerAdapter {
  readonly tool: string;

  trigger(config: ScanConfig): Promise<{ scanId: string }>;

  poll(scanId: string): Promise<{ status: ScanStatus; progress?: number }>;

  normalize(raw: unknown): Promise<UnifiedFinding[]>;

  store(findings: UnifiedFinding[]): Promise<void>;
}

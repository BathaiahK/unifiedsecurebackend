import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import type { ScannerAdapter, ScanConfig, ScanStatus, UnifiedFinding } from '@usp/schema';
import { scanRepository, cleanupOrphanedTempDirs, type RawSecret } from './scanner.js';
import { generateSimulatedFindings } from './simulator.js';
import { normalizeRawSecret } from './normalize.js';

interface PendingScan {
  asset: string;
  repoUrl: string | null;
  branch: string;
  depth: number;
  findings: UnifiedFinding[] | null;
  error: string | null;
  processed: number;
  total: number;
  cloneDir: string;
  startedAt: number;
}

export interface GitHistoryReport {
  repoUrl: string | null;
  branch: string;
  depth: number;
  secretsByCategory: Record<string, number>;
  secretsBySeverity: Record<string, number>;
  oldestCommitWithSecret: string | null;
  newestCommitWithSecret: string | null;
}

export class GitHistoryAdapter implements ScannerAdapter {
  readonly tool = 'git-history';

  private readonly pendingScans = new Map<string, PendingScan>();

  constructor() {
    // Cleanup orphaned temp directories on startup
    cleanupOrphanedTempDirs().catch((err) => {
      console.warn('[git-history] Failed to cleanup orphaned temp directories:', err);
    });
  }

  async trigger(config: ScanConfig): Promise<{ scanId: string }> {
    const repoUrl = (config.options?.['repoUrl'] as string | undefined) ?? null;
    const branch = (config.options?.['branch'] as string | undefined) ?? 'main';
    const depth = (config.options?.['depth'] as number | undefined) ?? 500;
    const scanId = `git-history-${Date.now()}-${randomUUID().slice(0, 8)}`;

    const tmpSubdir = `usp-git-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
    const cloneDir = path.join(os.tmpdir(), tmpSubdir);

    const pending: PendingScan = {
      asset: config.asset,
      repoUrl,
      branch,
      depth,
      findings: null,
      error: null,
      processed: 0,
      total: 0,
      cloneDir,
      startedAt: Date.now(),
    };

    this.pendingScans.set(scanId, pending);

    // Fire-and-forget async scan
    this._runScan(scanId, pending, config).catch((err) => {
      pending.error = String(err);
      pending.findings = []; // Mark as complete so polling doesn't hang
      console.error(`[git-history:${scanId}] Scan failed:`, err);
    });

    return { scanId };
  }

  private async _runScan(scanId: string, pending: PendingScan, config: ScanConfig): Promise<void> {
    try {
      // If no repo URL, use simulated findings for demo mode
      if (!pending.repoUrl) {
        const rawSecrets = generateSimulatedFindings(config.asset);
        pending.findings = rawSecrets.map((raw) => normalizeRawSecret(raw, config.asset, scanId));
        pending.total = 1;
        pending.processed = 1;
        return;
      }

      // Otherwise, scan the real repository
      const rawSecrets = await scanRepository({
        repoUrl: pending.repoUrl,
        branch: pending.branch,
        depth: pending.depth,
        cloneDir: pending.cloneDir,
        onProgress: (processed, total) => {
          pending.processed = processed;
          pending.total = total;
        },
      });

      pending.findings = rawSecrets.map((raw) => normalizeRawSecret(raw, config.asset, scanId));
      pending.total = Math.max(1, pending.total);
      pending.processed = pending.total;
    } finally {
      // Cleanup temp directory
      try {
        await fs.rm(pending.cloneDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  async poll(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) throw new Error(`Unknown git-history scan ID: ${scanId}`);

    // Error state
    if (pending.error) {
      return { status: 'failed', progress: 0 };
    }

    // Complete state
    if (pending.findings !== null) {
      return { status: 'complete', progress: 100 };
    }

    // Running state with progress
    const progress = pending.total > 0 ? Math.round((pending.processed / pending.total) * 100) : 5; // Show 5% while cloning
    return { status: 'running', progress };
  }

  async normalize(scanId: string): Promise<UnifiedFinding[]> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) throw new Error(`Unknown git-history scan ID: ${scanId}`);
    return pending.findings ?? [];
  }

  async store(_findings: UnifiedFinding[]): Promise<void> {
    // Findings are stored by the pipeline in apps/api/src/routes/scans.ts
    // This is a stub to satisfy the ScannerAdapter interface
  }

  getGitHistoryReport(scanId: string): GitHistoryReport | null {
    const pending = this.pendingScans.get(scanId);
    if (!pending || !pending.findings) return null;

    const secretsByCategory: Record<string, number> = {};
    const secretsBySeverity: Record<string, number> = {};
    let oldestCommit: string | null = null;
    let newestCommit: string | null = null;
    let oldestDate = new Date().toISOString();
    let newestDate = '1970-01-01T00:00:00Z';

    for (const finding of pending.findings) {
      const commitDate = (finding.evidence as Record<string, unknown>)['commitDate'] as
        | string
        | undefined;
      const category = (finding.evidence as Record<string, unknown>)['secretCategory'] as
        | string
        | undefined;

      if (category) {
        secretsByCategory[category] = (secretsByCategory[category] ?? 0) + 1;
      }

      secretsBySeverity[finding.severity] = (secretsBySeverity[finding.severity] ?? 0) + 1;

      if (commitDate) {
        if (commitDate < oldestDate) {
          oldestDate = commitDate;
          oldestCommit =
            ((finding.evidence as Record<string, unknown>)['commitHash'] as string | undefined) ??
            null;
        }
        if (commitDate > newestDate) {
          newestDate = commitDate;
          newestCommit =
            ((finding.evidence as Record<string, unknown>)['commitHash'] as string | undefined) ??
            null;
        }
      }
    }

    return {
      repoUrl: pending.repoUrl,
      branch: pending.branch,
      depth: pending.depth,
      secretsByCategory,
      secretsBySeverity,
      oldestCommitWithSecret: oldestCommit,
      newestCommitWithSecret: newestCommit,
    };
  }
}

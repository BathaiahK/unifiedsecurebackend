import type { ScannerAdapter, ScanConfig, ScanStatus, UnifiedFinding } from '@usp/schema';
import { getVulnStore, lookupPurls, type VulnStore } from '@usp/vuln-db';
import { normalizeMatch } from './normalize.js';

interface PendingScan {
  purls: string[];
  asset: string;
  startedAt: number;
  findings: UnifiedFinding[] | null;
}

export interface ScaAdapterConfig {
  mongoUrl: string;
  dbName?: string;
}

export class ScaAdapter implements ScannerAdapter {
  readonly tool = 'sca';

  private readonly mongoUrl: string;
  private readonly dbName: string;
  private _store: VulnStore | null = null;
  private readonly pendingScans = new Map<string, PendingScan>();

  constructor(config: ScaAdapterConfig) {
    this.mongoUrl = config.mongoUrl;
    this.dbName = config.dbName ?? 'vuln_db';
  }

  private async getStore(): Promise<VulnStore> {
    if (!this._store) {
      this._store = await getVulnStore(this.mongoUrl, this.dbName);
    }
    return this._store;
  }

  // ── ScannerAdapter.trigger ─────────────────────────────────────────────────

  async trigger(config: ScanConfig): Promise<{ scanId: string }> {
    const purls = (config.options?.['purls'] as string[] | undefined) ?? [];
    const scanId = `sca-${Date.now()}-${config.asset}`;

    this.pendingScans.set(scanId, {
      purls,
      asset: config.asset,
      startedAt: Date.now(),
      findings: null,
    });

    // Run query immediately — local DB, no network latency
    const store = await this.getStore();
    const matches = await lookupPurls(store, purls);
    const findings = matches.map((m) => normalizeMatch(m, config.asset, scanId));

    const pending = this.pendingScans.get(scanId)!;
    pending.findings = findings;

    return { scanId };
  }

  // ── ScannerAdapter.poll ────────────────────────────────────────────────────

  async poll(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) throw new Error(`Unknown SCA scan ID: ${scanId}`);
    return { status: pending.findings !== null ? 'complete' : 'running', progress: 100 };
  }

  // ── ScannerAdapter.normalize ───────────────────────────────────────────────

  async normalize(scanId: string): Promise<UnifiedFinding[]> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) throw new Error(`Unknown SCA scan ID: ${scanId}`);
    return pending.findings ?? [];
  }

  // ── ScannerAdapter.store ───────────────────────────────────────────────────

  async store(findings: UnifiedFinding[]): Promise<void> {
    console.log(`[sca] ${findings.length} findings ready for storage`);
  }

  get purlsScanned(): Map<string, number> {
    const result = new Map<string, number>();
    for (const [id, scan] of this.pendingScans) {
      result.set(id, scan.purls.length);
    }
    return result;
  }

  getPurlCount(scanId: string): number {
    return this.pendingScans.get(scanId)?.purls.length ?? 0;
  }
}

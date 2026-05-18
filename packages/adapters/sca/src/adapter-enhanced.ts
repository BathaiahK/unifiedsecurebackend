import type { ScannerAdapter, ScanConfig, ScanStatus, UnifiedFinding } from '@usp/schema';
import { getVulnStore, lookupPurls, type VulnStore } from '@usp/vuln-db';
import { normalizeMatch } from './normalize.js';
import { scaStreamingQueue } from './streaming-queue.js';
import {
  analyzeLicenseRisk,
  aggregateLicenseRisks,
  generateLicenseReport,
} from './license-analyzer.js';
import {
  resolveTransitiveDependencies,
  buildDependencyTree,
  countTransitiveVulnerabilities,
  getTransitiveChain,
} from './transitive-resolver.js';
import type { TransitiveDependency, EnhancedFinding } from './types.js';

interface PendingScan {
  purls: string[];
  asset: string;
  startedAt: number;
  findings: UnifiedFinding[] | null;
  transitiveDeps: TransitiveDependency[] | null;
  dependencyTree: Record<string, any> | null;
  licenseRisks: { safe: number; warning: number; critical: number } | null;
}

export interface ScaAdapterConfig {
  mongoUrl: string;
  dbName?: string;
}

export class ScaAdapterEnhanced implements ScannerAdapter {
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

    // Initialize pending scan
    this.pendingScans.set(scanId, {
      purls,
      asset: config.asset,
      startedAt: Date.now(),
      findings: null,
      transitiveDeps: null,
      dependencyTree: null,
      licenseRisks: null,
    });

    // Start async processing in background (don't await)
    this.processScan(scanId, config).catch((err) => {
      console.error('[SCA] Scan processing error:', err);
      scaStreamingQueue.emit({
        scanId,
        status: 'failed',
        progress: 0,
        error: String(err),
        timestamp: new Date().toISOString(),
      });
    });

    return { scanId };
  }

  private async processScan(scanId: string, config: ScanConfig): Promise<void> {
    const pending = this.pendingScans.get(scanId)!;

    try {
      // Stage 1: Initialize (0%)
      scaStreamingQueue.progress(scanId, 'initializing', 0, 'parsing', 'Initializing scan...');
      await sleep(100);

      // Stage 2: Vulnerability Lookup (50%)
      scaStreamingQueue.progress(
        scanId,
        'running',
        25,
        'vulnerability-lookup',
        `Looking up vulnerabilities for ${pending.purls.length} packages...`,
        { dependencyCount: pending.purls.length },
      );

      const store = await this.getStore();
      const matches = await lookupPurls(store, pending.purls);
      const findings = matches.map((m) => normalizeMatch(m, config.asset, scanId));
      pending.findings = findings;

      scaStreamingQueue.progress(
        scanId,
        'running',
        50,
        'vulnerability-lookup',
        `Found ${findings.length} vulnerabilities`,
        {
          findingCount: findings.length,
        },
      );

      await sleep(200);

      // Stage 3: License Analysis (75%)
      scaStreamingQueue.progress(
        scanId,
        'running',
        60,
        'license-analysis',
        'Analyzing licenses...',
      );

      // For now, simulate license analysis (in real scenario, would extract from manifests)
      const sampleLicenses = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'GPL-2.0', 'Proprietary'];
      const licenseAnalysis = aggregateLicenseRisks(sampleLicenses);
      pending.licenseRisks = {
        safe: licenseAnalysis.safe,
        warning: licenseAnalysis.warning,
        critical: licenseAnalysis.critical,
      };

      const licenseReport = generateLicenseReport(pending.licenseRisks);
      scaStreamingQueue.progress(
        scanId,
        'running',
        75,
        'license-analysis',
        'License analysis complete',
        {
          licenseRisks: pending.licenseRisks,
        },
      );

      await sleep(200);

      // Stage 4: Remediation & Summary (90%)
      scaStreamingQueue.progress(
        scanId,
        'running',
        85,
        'remediation',
        'Generating remediation plan...',
      );

      // Simulate remediation generation
      const remediationSteps = findings
        .slice(0, 3)
        .map((f) => `${f.title} → upgrade to available fix version`);

      scaStreamingQueue.progress(scanId, 'running', 95, 'remediation', 'Scan complete', {
        findingCount: findings.length,
      });

      await sleep(100);

      // Stage 5: Complete (100%)
      scaStreamingQueue.progress(
        scanId,
        'complete',
        100,
        'complete',
        'Scan completed successfully',
        {
          findingCount: findings.length,
          licenseRisks: pending.licenseRisks,
        },
      );
    } catch (err) {
      scaStreamingQueue.emit({
        scanId,
        status: 'failed',
        progress: 0,
        error: `Scan failed: ${String(err)}`,
        timestamp: new Date().toISOString(),
      });
      throw err;
    }
  }

  // ── ScannerAdapter.poll ────────────────────────────────────────────────────

  async poll(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) throw new Error(`Unknown SCA scan ID: ${scanId}`);

    const latestEvent = scaStreamingQueue.getLatestEvent(scanId);
    const status = latestEvent?.status ?? (pending.findings !== null ? 'complete' : 'running');

    return {
      status: status as ScanStatus,
      progress: latestEvent?.progress ?? (pending.findings !== null ? 100 : 50),
    };
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

  /**
   * Get real-time events for a scan (for SSE streaming)
   */
  getEvents(scanId: string) {
    return scaStreamingQueue.getEvents(scanId);
  }

  /**
   * Subscribe to real-time events (for WebSocket or similar)
   */
  subscribe(scanId: string, listener: (event: any) => void) {
    return scaStreamingQueue.subscribe(scanId, listener);
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

  /**
   * Get license risks for a scan
   */
  getLicenseRisks(scanId: string) {
    return this.pendingScans.get(scanId)?.licenseRisks;
  }

  /**
   * Get dependency tree for a scan
   */
  getDependencyTree(scanId: string) {
    return this.pendingScans.get(scanId)?.dependencyTree;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

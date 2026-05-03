import type { ScannerAdapter, ScanConfig, ScanStatus, UnifiedFinding } from '@usp/schema';
import { BlackDuckClient, type BlackDuckVulnerabilityPage, type BOMSummary, type ScanMode } from './client.js';
import { BlackDuckSimulator } from './simulator.js';
import { normalizeBlackDuckComponent } from './normalize.js';

export interface BlackDuckAdapterConfig {
  url: string;
  apiToken: string;
}

interface BlackDuckBackend {
  getProjectVersion(projectName: string): Promise<{ id: string; versionId: string } | null>;
  triggerScan(projectName: string, versionName: string, scanMode?: ScanMode): Promise<{ location: string }>;
  getScanStatus(scanUrl: string): Promise<{ status: string; percentComplete: number }>;
  getVulnerabilities(projectId: string, versionId: string, scanMode?: ScanMode): Promise<BlackDuckVulnerabilityPage>;
}

type PendingScan = {
  scanUrl: string;
  asset: string;
  projectId: string;
  versionId: string;
  scanMode: ScanMode;
};

export class BlackDuckAdapter implements ScannerAdapter {
  readonly tool = 'blackduck';
  private readonly backend: BlackDuckBackend;
  private readonly simulated: boolean;
  private readonly pendingScans = new Map<string, PendingScan>();

  constructor(config?: BlackDuckAdapterConfig) {
    if (config?.url && config?.apiToken) {
      this.backend = new BlackDuckClient(config);
      this.simulated = false;
    } else {
      this.backend = new BlackDuckSimulator();
      this.simulated = true;
    }
  }

  get isSimulated(): boolean { return this.simulated; }

  async trigger(config: ScanConfig): Promise<{ scanId: string }> {
    const scanMode = (config.options?.scanMode as ScanMode | undefined) ?? 'standard';

    const projectVersion = await this.backend.getProjectVersion(config.asset);
    if (!projectVersion) {
      throw new Error(`BlackDuck project not found for asset: ${config.asset}`);
    }

    const { location } = await this.backend.triggerScan(config.asset, 'latest', scanMode);
    const scanId = `bd-${Date.now()}-${projectVersion.id}`;

    this.pendingScans.set(scanId, {
      scanUrl: location,
      asset: config.asset,
      projectId: projectVersion.id,
      versionId: projectVersion.versionId,
      scanMode,
    });

    return { scanId };
  }

  async poll(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) throw new Error(`Unknown BlackDuck scan ID: ${scanId}`);

    const { status, percentComplete } = await this.backend.getScanStatus(pending.scanUrl);
    const mapped: ScanStatus =
      status === 'COMPLETE' ? 'complete' :
      status === 'FAILED'   ? 'failed'   : 'running';

    return { status: mapped, progress: percentComplete };
  }

  async normalize(scanId: string): Promise<UnifiedFinding[]> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) throw new Error(`Unknown BlackDuck scan ID: ${scanId}`);

    const page = await this.backend.getVulnerabilities(
      pending.projectId,
      pending.versionId,
      pending.scanMode,
    );

    return page.items.map((item) => normalizeBlackDuckComponent(item, pending.asset, scanId));
  }

  async store(findings: UnifiedFinding[]): Promise<void> {
    console.log(`[blackduck${this.simulated ? ':sim' : ''}] ${findings.length} findings ready for storage`);
  }

  // Not on the ScannerAdapter interface — called duck-typed from scans.ts
  async getBOMSummary(scanId: string): Promise<BOMSummary | null> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) return null;

    if (!(this.backend instanceof BlackDuckSimulator)) {
      // Real client: call BOM endpoint
      const realClient = this.backend as BlackDuckClient;
      const [bomPage, vulnPage] = await Promise.all([
        realClient.getComponentBOM(pending.projectId, pending.versionId),
        realClient.getVulnerabilities(pending.projectId, pending.versionId),
      ]);
      return (this.backend as BlackDuckSimulator).buildBOMSummary(pending.scanMode, bomPage, vulnPage);
    }

    // Simulator
    const sim = this.backend as BlackDuckSimulator;
    const [bomPage, vulnPage] = await Promise.all([
      sim.getComponentBOM(pending.projectId, pending.versionId, pending.scanMode),
      sim.getVulnerabilities(pending.projectId, pending.versionId, pending.scanMode),
    ]);
    return sim.buildBOMSummary(pending.scanMode, bomPage, vulnPage);
  }
}

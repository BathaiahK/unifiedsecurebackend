import type { ScannerAdapter, ScanConfig, ScanStatus, UnifiedFinding } from '@usp/schema';
import { BlackDuckClient, type BlackDuckVulnerabilityPage } from './client.js';
import { BlackDuckSimulator } from './simulator.js';
import { normalizeBlackDuckComponent } from './normalize.js';

export interface BlackDuckAdapterConfig {
  url: string;
  apiToken: string;
}

// The methods we need from either the real client or the simulator
interface BlackDuckBackend {
  getProjectVersion(projectName: string): Promise<{ id: string; versionId: string } | null>;
  triggerScan(projectName: string, versionName: string): Promise<{ location: string }>;
  getScanStatus(scanUrl: string): Promise<{ status: string; percentComplete: number }>;
  getVulnerabilities(projectId: string, versionId: string): Promise<BlackDuckVulnerabilityPage>;
}

export class BlackDuckAdapter implements ScannerAdapter {
  readonly tool = 'blackduck';
  private readonly backend: BlackDuckBackend;
  private readonly simulated: boolean;

  private readonly pendingScans = new Map<
    string,
    { scanUrl: string; asset: string; projectId: string; versionId: string }
  >();

  constructor(config?: BlackDuckAdapterConfig) {
    if (config?.url && config?.apiToken) {
      this.backend = new BlackDuckClient(config);
      this.simulated = false;
    } else {
      this.backend = new BlackDuckSimulator();
      this.simulated = true;
    }
  }

  get isSimulated(): boolean {
    return this.simulated;
  }

  async trigger(config: ScanConfig): Promise<{ scanId: string }> {
    const projectVersion = await this.backend.getProjectVersion(config.asset);
    if (!projectVersion) {
      throw new Error(`BlackDuck project not found for asset: ${config.asset}`);
    }

    const { location } = await this.backend.triggerScan(config.asset, 'latest');
    const scanId = `bd-${Date.now()}-${projectVersion.id}`;

    this.pendingScans.set(scanId, {
      scanUrl: location,
      asset: config.asset,
      projectId: projectVersion.id,
      versionId: projectVersion.versionId,
    });

    return { scanId };
  }

  async poll(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) throw new Error(`Unknown BlackDuck scan ID: ${scanId}`);

    const { status, percentComplete } = await this.backend.getScanStatus(pending.scanUrl);

    const mapped: ScanStatus =
      status === 'COMPLETE' ? 'complete' :
      status === 'FAILED'   ? 'failed'   :
      'running';

    return { status: mapped, progress: percentComplete };
  }

  async normalize(scanId: string): Promise<UnifiedFinding[]> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) throw new Error(`Unknown BlackDuck scan ID: ${scanId}`);

    const page: BlackDuckVulnerabilityPage = await this.backend.getVulnerabilities(
      pending.projectId,
      pending.versionId,
    );

    return page.items.map((item) =>
      normalizeBlackDuckComponent(item, pending.asset, scanId),
    );
  }

  async store(findings: UnifiedFinding[]): Promise<void> {
    // Storage handled centrally by the API scan pipeline (scans.ts).
    console.log(`[blackduck${this.simulated ? ':sim' : ''}] ${findings.length} findings ready for storage`);
  }
}

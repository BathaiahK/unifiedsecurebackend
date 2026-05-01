import type { ScannerAdapter, ScanConfig, ScanStatus, UnifiedFinding } from '@usp/schema';
import { BlackDuckClient, type BlackDuckVulnerabilityPage } from './client.js';
import { normalizeBlackDuckComponent } from './normalize.js';

export interface BlackDuckAdapterConfig {
  url: string;
  apiToken: string;
}

export class BlackDuckAdapter implements ScannerAdapter {
  readonly tool = 'blackduck';
  private readonly client: BlackDuckClient;

  private readonly pendingScans = new Map<
    string,
    { scanUrl: string; asset: string; projectId: string; versionId: string }
  >();

  constructor(config: BlackDuckAdapterConfig) {
    this.client = new BlackDuckClient(config);
  }

  async trigger(config: ScanConfig): Promise<{ scanId: string }> {
    const projectVersion = await this.client.getProjectVersion(config.asset);
    if (!projectVersion) {
      throw new Error(`BlackDuck project not found for asset: ${config.asset}`);
    }

    const { location } = await this.client.triggerScan(config.asset, 'latest');
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

    const { status, percentComplete } = await this.client.getScanStatus(pending.scanUrl);

    const mapped: ScanStatus =
      status === 'COMPLETE' ? 'complete' :
      status === 'FAILED' ? 'failed' :
      'running';

    return { status: mapped, progress: percentComplete };
  }

  async normalize(scanId: string): Promise<UnifiedFinding[]> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) throw new Error(`Unknown BlackDuck scan ID: ${scanId}`);

    const page: BlackDuckVulnerabilityPage = await this.client.getVulnerabilities(
      pending.projectId,
      pending.versionId,
    );

    return page.items.map((item) =>
      normalizeBlackDuckComponent(item, pending.asset, scanId),
    );
  }

  async store(findings: UnifiedFinding[]): Promise<void> {
    // Storage is handled centrally by the API (apps/api).
    // Adapters may optionally override this if they need custom persistence.
    console.log(`[blackduck] ${findings.length} findings ready for storage`);
  }
}

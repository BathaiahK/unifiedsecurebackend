import { randomUUID } from 'crypto';
import type { ScanConfig, ScanStatus, UnifiedFinding, ScannerAdapter } from '@usp/schema';
import type {
  ContainerAdapterConfig,
  ContainerPendingScan,
  ContainerScanReport,
  TrivyReport,
} from './types.js';
import { TrivyClient, type TrivyClientConfig } from './client.js';
import { ContainerSimulator } from './simulator.js';
import { normalizeContainerFindings } from './normalize.js';
import { fetchEpssScores, fetchKevCatalog } from './epss-client.js';
import { buildImageContext, evaluateRules } from './runtime-rules.js';
import { generateHardeningRecommendations } from './hardening-profiles.js';

interface FullScanResult {
  findings: UnifiedFinding[];
  report: ContainerScanReport;
  sbom: Record<string, unknown> | null;
}

export class ContainerAdapter implements ScannerAdapter {
  readonly tool = 'container';
  readonly isSimulated: boolean;

  private backend: TrivyClient | ContainerSimulator;
  private pendingScans = new Map<string, ContainerPendingScan>();

  constructor(config?: ContainerAdapterConfig) {
    const trivyPath = config?.trivyPath || 'trivy';

    const clientConfig: TrivyClientConfig = {
      trivyPath,
      ...(config?.registryUsername !== undefined && { registryUsername: config.registryUsername }),
      ...(config?.registryPassword !== undefined && { registryPassword: config.registryPassword }),
      ...(config?.registryToken !== undefined && { registryToken: config.registryToken }),
    };

    if (process.env['NODE_ENV'] !== 'production') {
      const client = new TrivyClient(clientConfig);
      this.backend = client;
      this.isSimulated = false;
    } else {
      this.backend = new TrivyClient(clientConfig);
      this.isSimulated = false;
    }
  }

  private async ensureBackend(): Promise<void> {
    if (this.backend instanceof TrivyClient) {
      const available = await this.backend.isAvailable();
      if (!available) {
        console.warn('Trivy CLI not available, falling back to simulator');
        this.backend = new ContainerSimulator();
        (this as any).isSimulated = true;
      }
    }
  }

  async trigger(config: ScanConfig): Promise<{ scanId: string }> {
    await this.ensureBackend();

    const scanId = `ct-${Date.now()}-${config.asset.replace(/[^a-z0-9]/gi, '')}`;
    const startTime = Date.now();

    // Extract options
    const image = (config.options?.['image'] as string | undefined) ?? config.asset;
    const scanMode = (config.options?.['scanMode'] as string | undefined) ?? 'full';

    const promise = (async (): Promise<FullScanResult> => {
      try {
        // 1. Run parallel scans based on mode
        const [vulnReport, cisReport, licenseReport, sbomReport] = await Promise.all([
          this.backend.scan(image),
          scanMode === 'full'
            ? this.backend instanceof TrivyClient
              ? this.backend.scanCisBenchmark(image)
              : Promise.resolve({
                  schemaVersion: 2,
                  artifactType: 'image',
                  artifactName: image,
                  results: [],
                })
            : Promise.resolve(null),
          scanMode !== 'vuln-only'
            ? this.backend instanceof TrivyClient
              ? this.backend.scanWithLicenses(image)
              : Promise.resolve({
                  schemaVersion: 2,
                  artifactType: 'image',
                  artifactName: image,
                  results: [],
                })
            : Promise.resolve(null),
          scanMode === 'full'
            ? this.backend instanceof TrivyClient
              ? this.backend.generateSbom(image)
              : Promise.resolve(null)
            : Promise.resolve(null),
        ]);

        // Merge results
        const mergedResults = [
          ...(vulnReport.results || []),
          ...(cisReport?.results || []),
          ...(licenseReport?.results || []),
        ];

        const mergedReport: TrivyReport = {
          ...vulnReport,
          results: mergedResults,
        };

        // 2. Build image context and evaluate runtime rules
        const imageContext = buildImageContext(image, mergedReport);
        const runtimeThreats = evaluateRules(imageContext);

        // 3. Generate hardening recommendations
        const hardeningRecs = generateHardeningRecommendations(imageContext, runtimeThreats);

        // 4. Collect CVEs for EPSS/KEV fetch
        const cves: string[] = [];
        for (const result of mergedResults) {
          if (result.vulnerabilities) {
            for (const vuln of result.vulnerabilities) {
              if (vuln.vulnerabilityID?.startsWith('CVE-')) {
                cves.push(vuln.vulnerabilityID);
              }
            }
          }
        }

        // 5. Fetch EPSS and KEV data in parallel
        const [epssMap, kevSet] = await Promise.all([fetchEpssScores(cves), fetchKevCatalog()]);

        // 6. Normalize findings with EPSS/KEV augmentation
        const findings = normalizeContainerFindings(mergedResults, image, scanId, epssMap, kevSet);

        // 7. Generate container report
        let containerReport: ContainerScanReport;
        if (this.backend instanceof ContainerSimulator) {
          containerReport = this.backend.generateReport(image, vulnReport);
        } else {
          containerReport = this.generateContainerReport(image, vulnReport, mergedReport);
        }

        // Augment with runtime threats and hardening recommendations
        containerReport.runtimeThreatDetails = runtimeThreats;
        containerReport.hardeningRecommendations = hardeningRecs;
        containerReport.sbomRef = scanId;

        return {
          findings,
          report: containerReport,
          sbom: sbomReport || null,
        };
      } catch (error) {
        console.error(`Container scan failed for ${image}:`, error);
        throw error;
      }
    })();

    this.pendingScans.set(scanId, {
      scanId,
      image,
      startTime,
      promise: promise as any,
    });

    return { scanId };
  }

  async poll(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) {
      return { status: 'failed' };
    }

    try {
      const result = await Promise.race([
        pending.promise,
        new Promise<null>((resolve) => setTimeout(() => resolve(null), 0)),
      ]);

      if (result === null) {
        const elapsed = Date.now() - pending.startTime;
        const estimatedTotal = 8000;
        const progress = Math.min(90, Math.floor((elapsed / estimatedTotal) * 100));
        return { status: 'running', progress };
      }

      return { status: 'complete', progress: 100 };
    } catch (error) {
      console.error(`Poll failed for ${scanId}:`, error);
      return { status: 'failed' };
    }
  }

  async normalize(scanId: string): Promise<UnifiedFinding[]> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) {
      return [];
    }

    try {
      const result = await pending.promise;
      return result.findings;
    } catch (error) {
      console.error(`Normalize failed for ${scanId}:`, error);
      return [];
    }
  }

  async store(): Promise<void> {
    console.log('Container adapter store() called (no-op)');
  }

  async getContainerReport(scanId: string): Promise<ContainerScanReport | null> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) {
      return null;
    }

    try {
      const result = await pending.promise;
      return result.report;
    } catch (error) {
      console.error(`getContainerReport failed for ${scanId}:`, error);
      return null;
    }
  }

  async getContainerSbom(scanId: string): Promise<Record<string, unknown> | null> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) {
      return null;
    }

    try {
      const result = await pending.promise;
      return result.sbom;
    } catch (error) {
      console.error(`getContainerSbom failed for ${scanId}:`, error);
      return null;
    }
  }

  private generateContainerReport(
    image: string,
    vulnReport: TrivyReport,
    mergedReport: TrivyReport,
  ): ContainerScanReport {
    let osVulns = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    let appVulns = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    let configIssues = 0;
    let secretsCount = 0;
    let licenseIssues = 0;

    const results = mergedReport.results || [];
    for (const result of results) {
      if (result.class === 'os-pkgs' && result.vulnerabilities) {
        for (const vuln of result.vulnerabilities) {
          const severity = (vuln.severity || 'UNKNOWN').toLowerCase();
          if (severity === 'critical') osVulns.critical++;
          else if (severity === 'high') osVulns.high++;
          else if (severity === 'medium') osVulns.medium++;
          else if (severity === 'low') osVulns.low++;
          else osVulns.info++;
          osVulns.total++;
        }
      } else if (result.class === 'lang-pkgs' && result.vulnerabilities) {
        for (const vuln of result.vulnerabilities) {
          const severity = (vuln.severity || 'UNKNOWN').toLowerCase();
          if (severity === 'critical') appVulns.critical++;
          else if (severity === 'high') appVulns.high++;
          else if (severity === 'medium') appVulns.medium++;
          else if (severity === 'low') appVulns.low++;
          else appVulns.info++;
          appVulns.total++;
        }
      } else if (result.class === 'misconfig' && result.misconfigurations) {
        configIssues += result.misconfigurations.length;
      } else if (result.class === 'secret' && result.secrets) {
        secretsCount += result.secrets.length;
      }
    }

    const metadata = vulnReport.metadata as any;
    const os = metadata?.OS || { Family: 'linux', Name: 'Unknown' };

    return {
      image,
      imageId: randomUUID(),
      os: {
        family: os.Family?.toLowerCase() || 'linux',
        name: os.Name || 'Unknown',
        version: os.Version,
        eosl: os.EOSL || false,
      },
      layers: (metadata?.DiffIDs?.length || 0) + 1,
      totalPackages: osVulns.total + appVulns.total,
      osPackages: osVulns.total,
      appPackages: appVulns.total,
      configIssues,
      secrets: secretsCount,
      runtimeThreats: 0,
      vulnerabilities: {
        critical: osVulns.critical + appVulns.critical,
        high: osVulns.high + appVulns.high,
        medium: osVulns.medium + appVulns.medium,
        low: osVulns.low + appVulns.low,
        info: osVulns.info + appVulns.info,
        total: osVulns.total + appVulns.total,
      },
      passedSecurityPolicy: osVulns.critical === 0 && appVulns.critical === 0 && secretsCount === 0,
      schemaVersion: vulnReport.schemaVersion?.toString() || '2',
      licenseIssues,
    };
  }
}

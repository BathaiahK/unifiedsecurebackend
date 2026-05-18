import type { ScannerAdapter, ScanConfig, ScanStatus, UnifiedFinding } from '@usp/schema';
import {
  OSSIndexClient,
  type SonatypeComponent,
  type ApplicationReport,
  type SonatypeScanMode,
} from './client.js';
import { SonatypeSimulator } from './simulator.js';
import {
  normalizeComponent,
  normalizeQualityRisk,
  normalizeSupplyChainThreat,
} from './normalize.js';

export interface SonatypeAdapterConfig {
  url?: string; // Reserved for Nexus IQ (commercial) base URL — unused for OSS Index
  username?: string; // OSS Index username (email)
  token?: string; // OSS Index user token
}

// ── Backend interface (duck-typed so simulator and real client are swappable) ─

interface SonatypeBackend {
  evaluateComponents(purls: string[], scanMode: SonatypeScanMode): Promise<SonatypeComponent[]>;
}

// ── Pending scan state ─────────────────────────────────────────────────────────

type PendingScan = {
  components: SonatypeComponent[];
  asset: string;
  scanMode: SonatypeScanMode;
  report: ApplicationReport | null;
  startedAt: number;
};

// ── Adapter ────────────────────────────────────────────────────────────────────

export class SonatypeAdapter implements ScannerAdapter {
  readonly tool = 'governance';

  private readonly backend: SonatypeBackend;
  private readonly simulated: boolean;
  private readonly pendingScans = new Map<string, PendingScan>();

  constructor(config?: SonatypeAdapterConfig) {
    if (config?.username && config?.token) {
      this.backend = new OSSIndexBackendAdapter(
        new OSSIndexClient({ username: config.username, token: config.token }),
      );
      this.simulated = false;
    } else {
      this.backend = new SonatypeSimulator();
      this.simulated = true;
    }
  }

  get isSimulated(): boolean {
    return this.simulated;
  }

  // ── ScannerAdapter.trigger ─────────────────────────────────────────────────

  async trigger(config: ScanConfig): Promise<{ scanId: string }> {
    const scanMode = (config.options?.['scanMode'] as SonatypeScanMode | undefined) ?? 'dependency';

    // Run component evaluation immediately — for OSS Index there is no async
    // "submit and poll" model; results come back in one HTTP response.
    // In simulated mode we pass an empty purl list (simulator ignores it).
    const purls = (config.options?.['purls'] as string[] | undefined) ?? [];
    const components = await this.backend.evaluateComponents(purls, scanMode);

    const scanId = `sn-${Date.now()}-${config.asset}`;

    this.pendingScans.set(scanId, {
      components,
      asset: config.asset,
      scanMode,
      report: null,
      startedAt: Date.now(),
    });

    return { scanId };
  }

  // ── ScannerAdapter.poll ────────────────────────────────────────────────────

  async poll(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) {
      throw new Error(`Unknown Sonatype scan ID: ${scanId}`);
    }

    // OSS Index evaluates synchronously in trigger(); by the time poll() is
    // called the data is already present.
    return { status: 'complete', progress: 100 };
  }

  // ── ScannerAdapter.normalize ───────────────────────────────────────────────

  async normalize(scanId: string): Promise<UnifiedFinding[]> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) {
      throw new Error(`Unknown Sonatype scan ID: ${scanId}`);
    }

    const findings: UnifiedFinding[] = [];

    for (const component of pending.components) {
      // One finding per vulnerability per component
      for (const vuln of component.vulnerabilities) {
        findings.push(normalizeComponent(component, pending.asset, scanId, vuln));
      }

      // Quality risk finding (one per component, if present)
      const qrFinding = normalizeQualityRisk(component, pending.asset, scanId);
      if (qrFinding !== null) {
        findings.push(qrFinding);
      }

      // Supply chain threat finding (one per component, if present)
      const sctFinding = normalizeSupplyChainThreat(component, pending.asset, scanId);
      if (sctFinding !== null) {
        findings.push(sctFinding);
      }
    }

    return findings;
  }

  // ── ScannerAdapter.store ───────────────────────────────────────────────────

  async store(findings: UnifiedFinding[]): Promise<void> {
    console.log(
      `[sonatype${this.simulated ? ':sim' : ''}] ${findings.length} findings ready for storage`,
    );
  }

  // ── Duck-typed extra method (not on ScannerAdapter interface) ─────────────

  /**
   * Build and return the ApplicationReport for a completed scan.
   * Called duck-typed from scans.ts — not part of the ScannerAdapter interface.
   * Returns null if the scan ID is unknown.
   */
  async getApplicationReport(scanId: string): Promise<ApplicationReport | null> {
    const pending = this.pendingScans.get(scanId);
    if (!pending) return null;

    // Build once and cache
    if (pending.report === null) {
      if (this.simulated) {
        const sim = this.backend as SonatypeSimulator;
        pending.report = sim.buildApplicationReport(pending.scanMode, pending.components);
      } else {
        // Real path: synthesise report from the component data we already have
        pending.report = buildReportFromComponents(pending.scanMode, pending.components);
      }
    }

    return pending.report;
  }
}

// ── Wrapper to make OSSIndexClient satisfy SonatypeBackend ────────────────────

class OSSIndexBackendAdapter implements SonatypeBackend {
  constructor(private readonly client: OSSIndexClient) {}

  async evaluateComponents(
    purls: string[],
    // scanMode is not used by OSS Index — the API returns whatever it knows
    // regardless of how you obtained the purls.
    _scanMode: SonatypeScanMode,
  ): Promise<SonatypeComponent[]> {
    const raw = await this.client.evaluateComponents(purls);

    // OSS Index returns OSSIndexComponent[]; we promote each to SonatypeComponent
    // with conservative defaults for the enriched fields (not provided by the API).
    return raw.map((c) => ({
      ...c,
      detectionType: 'dependency' as const,
      licenseId: null,
      licenseRisk: 'UNKNOWN' as const,
      goldenVersion: null,
      isReachable: null,
      qualityRisk: null,
      supplyChainThreat: null,
      ecosystem: extractEcosystem(c.coordinates),
    }));
  }
}

// ── Utility: build ApplicationReport from raw component data ──────────────────

function buildReportFromComponents(
  scanMode: SonatypeScanMode,
  components: SonatypeComponent[],
): ApplicationReport {
  const vulnerableComponents = components.filter((c) => c.vulnerabilities.length > 0).length;
  const policyViolations = components.reduce((sum, c) => sum + c.vulnerabilities.length, 0);

  const licenseViolations: ApplicationReport['licenseViolations'] = [];
  const qualityRisks: ApplicationReport['qualityRisks'] = [];
  const supplyChainThreats: ApplicationReport['supplyChainThreats'] = [];

  for (const c of components) {
    const name = extractComponentName(c.coordinates);
    const version = extractVersion(c.coordinates);

    if (c.licenseId) {
      if (/^GPL/i.test(c.licenseId) || /^AGPL/i.test(c.licenseId)) {
        licenseViolations.push({
          component: name,
          version,
          licenseId: c.licenseId,
          risk: 'HIGH',
          reason: `${c.licenseId} is a copyleft licence that may require disclosure of proprietary source code.`,
        });
      } else if (/^LGPL/i.test(c.licenseId)) {
        licenseViolations.push({
          component: name,
          version,
          licenseId: c.licenseId,
          risk: 'MEDIUM',
          reason: `${c.licenseId} is a weak copyleft licence — dynamic linking may trigger disclosure obligations.`,
        });
      }
    }

    if (c.qualityRisk?.isAbandoned) {
      qualityRisks.push({
        component: name,
        version,
        risk: 'abandoned',
        detail: `No releases in ${c.qualityRisk.daysStale ?? '?'} days.`,
      });
    }

    if (c.supplyChainThreat) {
      supplyChainThreats.push({ component: name, version, threat: c.supplyChainThreat });
    }
  }

  const goldenVersionsAvailable = components.filter(
    (c) => c.goldenVersion !== null && c.vulnerabilities.length > 0,
  ).length;

  const topComponents = components.map((c) => ({
    name: extractComponentName(c.coordinates),
    version: extractVersion(c.coordinates),
    ecosystem: c.ecosystem,
    licenseId: c.licenseId ?? 'UNKNOWN',
    licenseRisk: c.licenseRisk,
    vulnerabilityCount: c.vulnerabilities.length,
    goldenVersion: c.goldenVersion,
  }));

  return {
    scanMode,
    totalComponents: components.length,
    vulnerableComponents,
    policyViolations,
    licenseViolations,
    qualityRisks,
    supplyChainThreats,
    goldenVersionsAvailable,
    topComponents,
  };
}

// ── Purl parsing helpers ──────────────────────────────────────────────────────

function extractEcosystem(purl: string): string {
  const m = purl.match(/^pkg:([^/]+)\//);
  return m?.[1] ?? 'unknown';
}

function extractComponentName(purl: string): string {
  const withoutPrefix = purl.replace(/^pkg:[^/]+\//, '');
  const atIdx = withoutPrefix.lastIndexOf('@');
  const rawName = atIdx === -1 ? withoutPrefix : withoutPrefix.slice(0, atIdx);
  // Decode percent-encoding (e.g. %40babel → @babel) — OSS Index returns purls with encoded @
  const decoded = decodeURIComponent(rawName);
  const slashIdx = decoded.indexOf('/');
  // Scoped npm packages start with @ — keep the full @scope/name intact
  if (slashIdx === -1 || decoded.startsWith('@')) return decoded;
  return decoded.slice(slashIdx + 1);
}

function extractVersion(purl: string): string {
  const atIdx = purl.lastIndexOf('@');
  return atIdx === -1 ? 'unknown' : purl.slice(atIdx + 1);
}

export type ScanMode = 'package-manager' | 'standard' | 'full';
export type DetectionType = 'package-manager' | 'signature' | 'snippet' | 'binary';
export type AdvisorySource = 'bdsa' | 'nvd';

export interface BlackDuckConfig {
  url: string;
  apiToken: string;
}

export class BlackDuckClient {
  private readonly base: string;
  private readonly token: string;

  constructor(config: BlackDuckConfig) {
    this.base = config.url.replace(/\/$/, '');
    this.token = config.apiToken;
  }

  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    const res = await fetch(`${this.base}${path}`, {
      ...options,
      headers: {
        Authorization: `Bearer ${this.token}`,
        'Content-Type': 'application/json',
        Accept: 'application/vnd.blackducksoftware.scan-5+json',
        ...options?.headers,
      },
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`BlackDuck API error ${res.status} on ${path}: ${text}`);
    }

    return res.json() as Promise<T>;
  }

  async triggerScan(projectName: string, versionName: string): Promise<{ location: string }> {
    return this.request<{ location: string }>('/api/scan/data/', {
      method: 'POST',
      body: JSON.stringify({ projectName, versionName }),
    });
  }

  async getScanStatus(scanUrl: string): Promise<{ status: string; percentComplete: number }> {
    const path = scanUrl.replace(this.base, '');
    return this.request<{ status: string; percentComplete: number }>(path);
  }

  async getVulnerabilities(projectId: string, versionId: string): Promise<BlackDuckVulnerabilityPage> {
    return this.request<BlackDuckVulnerabilityPage>(
      `/api/projects/${projectId}/versions/${versionId}/vulnerable-bom-components?limit=200`,
    );
  }

  async getComponentBOM(projectId: string, versionId: string): Promise<BlackDuckBOMPage> {
    return this.request<BlackDuckBOMPage>(
      `/api/projects/${projectId}/versions/${versionId}/components?limit=500`,
    );
  }

  async getProjectVersion(projectName: string): Promise<{ id: string; versionId: string } | null> {
    const projects = await this.request<{ items: Array<{ name: string; _meta: { href: string } }> }>(
      `/api/projects?q=name:${encodeURIComponent(projectName)}&limit=1`,
    );
    const project = projects.items[0];
    if (!project) return null;

    const projectId = project._meta.href.split('/').at(-1) ?? '';
    const versions = await this.request<{ items: Array<{ _meta: { href: string } }> }>(
      `/api/projects/${projectId}/versions?limit=1`,
    );
    const version = versions.items[0];
    if (!version) return null;

    const versionId = version._meta.href.split('/').at(-1) ?? '';
    return { id: projectId, versionId };
  }
}

// ── Vulnerability types ───────────────────────────────────────────────────────

export interface BlackDuckVulnerabilityPage {
  totalCount: number;
  items: BlackDuckVulnerableComponent[];
}

export interface BlackDuckVulnerableComponent {
  componentName: string;
  componentVersionName: string;
  vulnerabilityWithRemediation: {
    vulnerabilityName: string;
    description: string;
    baseScore: number | null;
    severity: string;
    remediationStatus: string;
    cweId: string | null;
    targetRemediationDate: string | null;
    remediationCreatedAt: string | null;
  };
  _meta: { href: string };
  // Enriched fields added by simulator / real API extension
  detectionType?: DetectionType;
  advisorySource?: AdvisorySource;
  bdsaId?: string;
}

// ── BOM (component inventory) types ──────────────────────────────────────────

export interface BlackDuckBOMPage {
  totalCount: number;
  items: BlackDuckBOMComponent[];
}

export interface BlackDuckBOMComponent {
  componentName: string;
  componentVersionName: string;
  licenses: Array<{
    spdxId: string;
    licenseDisplay: string;
    licenseType: 'OPEN_SOURCE' | 'PROPRIETARY' | 'UNKNOWN';
  }>;
  usages: string[];
  reviewStatus: 'REVIEWED' | 'UNREVIEWED' | 'DYNAMIC_IN_USE';
}

export interface BOMSummary {
  scanMode: ScanMode;
  totalComponents: number;
  vulnerableComponents: number;
  bdsaCount: number;
  licenseRisk: { high: number; medium: number; low: number };
  licenseViolations: Array<{ component: string; version: string; license: string; risk: 'HIGH' | 'MEDIUM' }>;
  topComponents: Array<{ name: string; version: string; license: string; licenseRisk: 'HIGH' | 'MEDIUM' | 'LOW' }>;
}

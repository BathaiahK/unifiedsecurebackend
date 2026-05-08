export interface ScanProgressEvent {
  scanId: string;
  status: 'initializing' | 'running' | 'complete' | 'failed';
  progress: number; // 0-100
  stage?: 'parsing' | 'vulnerability-lookup' | 'license-analysis' | 'supply-chain' | 'remediation' | 'complete';
  message?: string;

  // Intermediate results
  manifestCount?: number;
  dependencyCount?: number;
  findingCount?: number;
  licenseRisks?: {
    safe: number;
    warning: number;
    critical: number;
  };

  error?: string;
  timestamp: string;
}

export interface LicenseRisk {
  license: string;
  riskLevel: 'safe' | 'warning' | 'critical';
  reason: string;
}

export interface TransitiveDependency {
  name: string;
  version: string;
  ecosystem: string;
  depth: number; // 0 = direct, 1+ = transitive
  parent?: string;
  vulnerabilities: number;
}

export interface EnhancedFinding {
  // Standard finding data
  id: string;
  tool: string;
  severity: string;
  cvss: number | null;
  cve: string | null;
  cwe: string | null;
  title: string;
  asset: string;
  status: string;
  fixVersion: string | null;
  firstSeen: string;
  lastSeen: string;
  remediationSteps: string[];
  references: Array<{ label: string; url: string }>;
  evidence: Record<string, unknown>;
  scanId: string;

  // Enhanced data
  isTransitive?: boolean;
  transitiveParents?: string[];
  licenseRisks?: LicenseRisk[];
  dependencyContext?: {
    affectedTransitiveDeps: TransitiveDependency[];
    upgradeImpact: string;
    migrationGuide?: string;
  };
}

export interface ManifestFile {
  type: 'package.json' | 'requirements.txt' | 'pom.xml' | 'go.mod' | 'Gemfile' | 'packages.config' | 'package-lock.json';
  path: string;
  content: string;
}

export interface ParsedDependency {
  name: string;
  version: string;
  isDirect: boolean;
  manifestType: string;
}

// ─── Phase 2: Supply Chain Security ────────────────────────────────────────

export type SupplyChainThreatType = 'unmaintained' | 'typosquatting' | 'duplicate-version';

export interface SupplyChainThreat {
  packageName: string;
  version: string;
  purl: string;
  threatType: SupplyChainThreatType;
  severity: 'high' | 'medium' | 'low';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  // Unmaintained-specific
  lastPublishDate?: string;
  daysSinceLastPublish?: number;
  // Typosquatting-specific
  suspectedTargetPackage?: string;
  editDistance?: number;
  // Duplicate-version-specific
  conflictingVersions?: string[];
}

export interface SupplyChainReport {
  generatedAt: string;
  totalPackagesAnalyzed: number;
  threats: SupplyChainThreat[];
  unmaintainedCount: number;
  typosquattingCount: number;
  duplicateVersionCount: number;
}

// ─── Phase 3: SBOM Generation ─────────────────────────────────────────────

export interface SBOMComponent {
  type: 'library';
  name: string;
  version: string;
  purl: string;
  ecosystem: string;
  licenses: string[];
  hashes?: { alg: string; content: string }[];
}

export interface SBOMDocument {
  format: 'cyclonedx' | 'spdx';
  version: string;
  serialNumber?: string;
  spdxId?: string;
  name: string;
  createdAt: string;
  tool: string;
  components: SBOMComponent[];
}

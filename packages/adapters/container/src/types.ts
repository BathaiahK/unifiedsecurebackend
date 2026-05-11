// Trivy JSON output types
export interface TrivyReport {
  schemaVersion: number;
  artifactType: string;
  artifactName: string;
  artifactRef?: string;
  metadata?: TrivyMetadata;
  results?: TrivyResult[];
}

export interface TrivyResult {
  target: string;
  class: 'os-pkgs' | 'lang-pkgs' | 'misconfig' | 'secret';
  type: string;
  vulnerabilities?: TrivyVulnerability[];
  misconfigurations?: TrivyMisconfiguration[];
  secrets?: TrivySecret[];
}

export interface TrivyVulnerability {
  vulnerabilityID: string;
  pkgID?: string;
  pkgName: string;
  installedVersion: string;
  fixedVersion?: string;
  title?: string;
  description?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  type?: string;
  references?: string[];
  primaryURL?: string;
  publishedDate?: string;
  lastModifiedDate?: string;
  cvss?: {
    nvd?: { v3Score: number; v3Vector: string };
    redhat?: { v3Score: number; v3Vector: string };
  };
  cweIDs?: string[];
  dataSource?: {
    ID: string;
    Name: string;
    URL: string;
  };
}

export interface TrivyMisconfiguration {
  type: string;
  id: string;
  title: string;
  description?: string;
  message?: string;
  namespace?: string;
  query?: string;
  resolution?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  references?: string[];
  status?: string;
  layer?: {
    digest: string;
    diffID: string;
  };
  causeMetadata?: {
    startLine?: number;
    endLine?: number;
    code?: {
      lines: Array<{ number: number; content: string }>;
    };
  };
}

export interface TrivySecret {
  ruleID: string;
  category: string;
  severity: string;
  title?: string;
  description?: string;
  startLine?: number;
  endLine?: number;
  match?: string;
  layer?: {
    digest: string;
    diffID: string;
  };
}

// === NEW TYPES ===

export interface LayerDetail {
  index: number;
  digest: string;
  diffId: string;
  sizeBytes: number;
  command: string;
  vulnerabilityCount: number;
  secretCount: number;
}

export interface CisCheck {
  id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'PASS' | 'FAIL' | 'WARN';
  remediation: string;
}

export interface BaseImageInfo {
  name: string;
  tag: string;
  digest?: string;
  os: string;
  osVersion: string;
  eosl: boolean;
}

export interface HardeningRecommendation {
  category: 'seccomp' | 'apparmor' | 'user' | 'readonly' | 'capabilities';
  title: string;
  description: string;
  profile?: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface EpssEntry {
  cve: string;
  epss: number;
  percentile: number;
  date: string;
}

export interface RuntimeThreat {
  ruleId: string;
  ruleName: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  matchedPattern: string;
  syscallTrace: string[];
  timestamp: string;
}

export interface TrivyMetadata {
  OS?: { Family: string; Name: string; EOSL?: boolean };
  ImageID?: string;
  DiffIDs?: string[];
  RepoTags?: string[];
  RepoDigests?: string[];
  ImageConfig?: {
    history?: Array<{ created_by: string; empty_layer?: boolean }>;
  };
}

// Container scan report for duck-typed metadata storage
export interface ContainerScanReport {
  image: string;
  imageId: string;
  os: {
    family: string;
    name: string;
    version?: string;
    eosl?: boolean;
  };
  layers: number;
  totalPackages: number;
  osPackages: number;
  appPackages: number;
  configIssues: number;
  secrets: number;
  runtimeThreats: number;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  passedSecurityPolicy: boolean;
  schemaVersion: string;
  // NEW optional fields
  layerDetails?: LayerDetail[];
  cisChecks?: CisCheck[];
  baseImage?: BaseImageInfo;
  hardeningRecommendations?: HardeningRecommendation[];
  sbomRef?: string;
  epssData?: EpssEntry[];
  kevMatches?: string[];
  runtimeThreatDetails?: RuntimeThreat[];
  licenseIssues?: number;
}

// In-flight scan state
export interface ContainerPendingScan {
  scanId: string;
  image: string;
  startTime: number;
  promise: Promise<{ findings: any[]; report: ContainerScanReport; sbom: Record<string, unknown> | null }>;
}

export interface ContainerAdapterConfig {
  trivyPath?: string;
  registryUsername?: string;
  registryPassword?: string;
  registryToken?: string;
}

export type SupplyChainThreatType =
  | 'typosquatting'
  | 'dependency-confusion'
  | 'unmaintained'
  | 'malicious-advisory'
  | 'namespace-jacking';

export interface SupplyChainThreat {
  packageName: string;
  version: string;
  purl: string;
  threatType: SupplyChainThreatType;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;

  // Typosquatting-specific
  suspectedTargetPackage?: string;
  editDistance?: number;

  // Unmaintained-specific
  lastPublishDate?: string;
  daysSinceLastPublish?: number;

  // Dependency confusion-specific
  visiblyExposedPublicly?: boolean;

  // Malicious advisory-specific
  advisoryId?: string;
  advisoryUrl?: string;
}

export interface SupplyChainReport {
  generatedAt: string;
  totalPackagesAnalyzed: number;
  threats: SupplyChainThreat[];
  typosquattingCount: number;
  dependencyConfusionCount: number;
  unmaintainedCount: number;
  maliciousAdvisoryCount: number;
  namespaceJackingCount: number;
}

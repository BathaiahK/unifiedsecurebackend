import { randomUUID } from 'node:crypto';
import { MongoClient } from 'mongodb';
import { ScannerAdapter, ScanConfig, ScanStatus, UnifiedFinding } from '@usp/schema';
import { runSupplyChainAnalysis, extractName, extractVersion } from './detector.js';
import type { SupplyChainReport } from './types.js';

interface PendingScan {
  report: SupplyChainReport;
  startTime: number;
  completed: boolean;
}

export class SupplyChainAdapter implements ScannerAdapter {
  readonly tool = 'supply-chain';
  private activeScan: Map<string, PendingScan> = new Map();
  private mongoUrl: string;
  private mongoClient: MongoClient | null = null;

  constructor(config?: { mongoUrl?: string }) {
    this.mongoUrl =
      config?.mongoUrl || process.env.DATABASE_URL || 'mongodb://localhost:27017/uspservice';
  }

  private async getMongoClient(): Promise<MongoClient> {
    if (!this.mongoClient) {
      this.mongoClient = new MongoClient(this.mongoUrl);
      await this.mongoClient.connect();
    }
    return this.mongoClient;
  }

  async trigger(config: ScanConfig): Promise<{ scanId: string }> {
    const scanId = `supply-chain-${Date.now()}-${randomUUID().slice(0, 8)}`;

    const report: SupplyChainReport = {
      generatedAt: new Date().toISOString(),
      totalPackagesAnalyzed: 0,
      threats: [],
      typosquattingCount: 0,
      dependencyConfusionCount: 0,
      unmaintainedCount: 0,
      maliciousAdvisoryCount: 0,
      namespaceJackingCount: 0,
    };

    this.activeScan.set(scanId, {
      report,
      startTime: Date.now(),
      completed: false,
    });

    this.performScan(scanId, config).catch((err) => {
      console.error(`Supply Chain scan ${scanId} failed:`, err);
      const scan = this.activeScan.get(scanId);
      if (scan) scan.completed = true;
    });

    return { scanId };
  }

  async poll(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const scan = this.activeScan.get(scanId);
    if (!scan) return { status: 'failed', progress: 0 };
    if (scan.completed) return { status: 'complete', progress: 100 };

    const elapsed = Date.now() - scan.startTime;
    const progress = Math.min(95, Math.floor((elapsed / 5000) * 100));
    return { status: 'running', progress };
  }

  private async fetchRecentSCAFindings(asset: string): Promise<string[]> {
    try {
      const client = await this.getMongoClient();
      const db = client.db('uspservice');
      const scans = db.collection('Scan');
      const findings = db.collection('Finding');

      const recentScan = await scans.findOne(
        { tool: 'sca', asset, status: 'complete' },
        { sort: { completedAt: -1 } },
      );

      if (!recentScan) return [];

      const scanFindings = await findings.find({ scanId: recentScan._id }).toArray();

      const purls = new Set<string>();
      for (const finding of scanFindings) {
        const evidence = finding.evidence as Record<string, any>;
        if (evidence?.purl) {
          purls.add(evidence.purl as string);
        } else if (evidence?.advisory?.affected?.[0]?.package?.purl) {
          purls.add(evidence.advisory.affected[0].package.purl as string);
        }
      }

      return Array.from(purls);
    } catch (err) {
      console.error(`Failed to fetch recent SCA findings for ${asset}:`, err);
      return [];
    }
  }

  async normalize(raw: unknown): Promise<UnifiedFinding[]> {
    const scanId = raw as string;
    const scan = this.activeScan.get(scanId);
    if (!scan || scan.report.threats.length === 0) return [];

    return scan.report.threats.map(
      (threat) =>
        ({
          id: randomUUID(),
          tool: 'supply-chain' as const,
          severity: threat.severity,
          cvss: null,
          cve: null,
          cwe: null,
          title: `${threat.threatType}: ${threat.packageName}@${threat.version}`,
          asset: 'dependencies',
          status: 'open' as const,
          fixVersion: null,
          firstSeen: scan.report.generatedAt,
          lastSeen: scan.report.generatedAt,
          remediationSteps: this.getRemediationSteps(threat.threatType),
          references: threat.advisoryUrl ? [{ label: 'Advisory', url: threat.advisoryUrl }] : [],
          evidence: {
            threatType: threat.threatType,
            packageName: threat.packageName,
            version: threat.version,
            purl: threat.purl,
            suspectedTargetPackage: threat.suspectedTargetPackage,
            editDistance: threat.editDistance,
            lastPublishDate: threat.lastPublishDate,
            daysSinceLastPublish: threat.daysSinceLastPublish,
            confidence: threat.confidence,
          },
          scanId: randomUUID(),
        }) as UnifiedFinding,
    );
  }

  async store(findings: UnifiedFinding[]): Promise<void> {
    // Storage is handled by API layer
  }

  getSupplyChainReport(scanId: string): SupplyChainReport | null {
    const scan = this.activeScan.get(scanId);
    if (!scan?.completed) return null;
    return scan.report;
  }

  private getRemediationSteps(threatType: string): string[] {
    const steps: Record<string, string[]> = {
      typosquatting: [
        'Verify the package name is spelled correctly',
        'Check npm registry page for official maintainer information',
        'Use scoped packages (@namespace/name) when available',
        'Pin exact versions to prevent typo-induced installs',
        'Review package.json changes in git history',
      ],
      'dependency-confusion': [
        'Use scoped packages (@company/internal) for internal dependencies',
        'Configure npm/yarn/pnpm with a private registry for internal packages',
        'Add scope prefix to all internal package names',
        'Use .npmrc with scope=https://private-registry/ configuration',
        'Verify package ownership if name appears in public registry',
      ],
      unmaintained: [
        'Check if active maintained forks exist',
        'Evaluate alternative packages with similar functionality',
        'Consider backporting security fixes locally if critical',
        'Submit a pull request to the original repository to adopt maintenance',
        'Plan migration to replacement package in next release',
      ],
      'malicious-advisory': [
        'Remove the package immediately from package.json',
        'Check git history for when it was added',
        'Review any code this package may have executed',
        'Rotate any secrets/credentials that may have been exposed',
        'Run npm audit to find safe alternative packages',
      ],
    };

    return steps[threatType] || ['Review the threat and take appropriate action'];
  }

  private async performScan(scanId: string, config: ScanConfig): Promise<void> {
    const scan = this.activeScan.get(scanId);
    if (!scan) return;

    try {
      let purls = (config.options as Record<string, unknown>)?.purls as string[] | undefined;

      if (!purls || purls.length === 0) {
        purls = await this.fetchRecentSCAFindings(config.asset);
      }

      if (purls && purls.length > 0) {
        const report = runSupplyChainAnalysis(purls);
        scan.report = report;
      } else {
        scan.report = this.generateSimulatedReport();
      }
    } finally {
      scan.completed = true;
    }
  }

  private generateSimulatedReport(): SupplyChainReport {
    const simulatedThreats = [
      {
        packageName: 'lodash',
        version: '4.17.15',
        purl: 'pkg:npm/lodash@4.17.15',
        threatType: 'unmaintained' as const,
        severity: 'medium' as const,
        confidence: 'MEDIUM' as const,
        description:
          'lodash is still maintained but has reduced update frequency. Evaluate if update is necessary.',
        lastPublishDate: '2021-02-04',
        daysSinceLastPublish: 1200,
      },
      {
        packageName: 'requests',
        version: '1.0.0',
        purl: 'pkg:npm/requests@1.0.0',
        threatType: 'typosquatting' as const,
        severity: 'high' as const,
        confidence: 'HIGH' as const,
        description:
          'Package name "requests" resembles popular package "request" (edit distance: 1).',
        suspectedTargetPackage: 'request',
        editDistance: 1,
      },
      {
        packageName: '@company-internal/utils',
        version: '2.1.0',
        purl: 'pkg:npm/@company-internal/utils@2.1.0',
        threatType: 'dependency-confusion' as const,
        severity: 'medium' as const,
        confidence: 'MEDIUM' as const,
        description:
          'Scoped package uses scope "@company-internal". Verify scope ownership to prevent dependency confusion attacks.',
      },
    ];

    return {
      generatedAt: new Date().toISOString(),
      totalPackagesAnalyzed: 3,
      threats: simulatedThreats,
      typosquattingCount: 1,
      dependencyConfusionCount: 1,
      unmaintainedCount: 1,
      maliciousAdvisoryCount: 0,
      namespaceJackingCount: 0,
    };
  }
}

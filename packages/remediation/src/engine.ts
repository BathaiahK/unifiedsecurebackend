import type { UnifiedFinding } from '@usp/schema';
import { enrichFromNvd } from './nvd-client.js';
import { enrichFromOsv } from './osv-client.js';

export interface RemediationEngineConfig {
  nvdApiKey?: string;
  nvdApiUrl?: string;
  osvApiUrl?: string;
  concurrency?: number;
}

export async function enrichFindings(
  findings: UnifiedFinding[],
  config: RemediationEngineConfig = {},
): Promise<UnifiedFinding[]> {
  const { concurrency = 5 } = config;
  const results: UnifiedFinding[] = [];

  for (let i = 0; i < findings.length; i += concurrency) {
    const batch = findings.slice(i, i + concurrency);
    const enriched = await Promise.all(batch.map((f) => enrichFinding(f, config)));
    results.push(...enriched);
  }

  return results;
}

async function enrichFinding(
  finding: UnifiedFinding,
  config: RemediationEngineConfig,
): Promise<UnifiedFinding> {
  if (!finding.cve) return finding;

  const [nvd, osv] = await Promise.all([
    enrichFromNvd(finding.cve, config.nvdApiKey, config.nvdApiUrl).catch(() => null),
    enrichFromOsv(finding.cve, config.osvApiUrl).catch(() => null),
  ]);

  const enriched = { ...finding };

  if (nvd) {
    if (enriched.cvss === null && nvd.cvss !== null) enriched.cvss = nvd.cvss;
    if (enriched.cwe === null && nvd.cwe !== null) enriched.cwe = nvd.cwe;
  }

  if (osv) {
    if (enriched.fixVersion === null && osv.fixVersion !== null) {
      enriched.fixVersion = osv.fixVersion;
    }
    const additionalSteps = buildAdditionalSteps(osv.fixVersion, osv.advisoryUrls);
    enriched.remediationSteps = dedupe([...enriched.remediationSteps, ...additionalSteps]);
  }

  return enriched;
}

function buildAdditionalSteps(fixVersion: string | null, advisoryUrls: string[]): string[] {
  const steps: string[] = [];
  if (fixVersion) steps.push(`Upgrade to version ${fixVersion} or later`);
  for (const url of advisoryUrls.slice(0, 2)) steps.push(`See advisory: ${url}`);
  return steps;
}

function dedupe(steps: string[]): string[] {
  return [...new Set(steps)];
}

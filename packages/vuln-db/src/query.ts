import type { VulnStore } from './store.js';
import type { VulnMatch } from './types.js';
import { PURL_ECOSYSTEM_MAP } from './types.js';
import { isVersionAffected } from './semver-match.js';

interface ParsedPurl {
  type: string;
  name: string;
  version: string;
  ecosystem: string;
}

function parsePurl(purl: string): ParsedPurl | null {
  // pkg:npm/%40babel/core@7.24.7  or  pkg:npm/lodash@4.17.21
  const m = purl.match(/^pkg:([^/]+)\/(.+)@([^@]+)$/);
  if (!m) return null;
  const [, type, rawName, version] = m;
  const name = decodeURIComponent(rawName!).toLowerCase();
  const ecosystem = PURL_ECOSYSTEM_MAP[type!.toLowerCase()] ?? null;
  if (!ecosystem) return null;
  return { type: type!, name, version: version!, ecosystem };
}

/**
 * Look up all advisories matching each purl in the local vuln-db.
 * Returns one VulnMatch per (purl, advisory) pair.
 *
 * Reduces N+1 queries → 1-2 queries by grouping PURLs by ecosystem and batching.
 */
export async function lookupPurls(store: VulnStore, purls: string[]): Promise<VulnMatch[]> {
  // Group PURLs by ecosystem
  const byEcosystem = new Map<string, { purl: string; name: string; version: string }[]>();
  for (const purl of purls) {
    const parsed = parsePurl(purl);
    if (!parsed) continue;
    if (!byEcosystem.has(parsed.ecosystem)) {
      byEcosystem.set(parsed.ecosystem, []);
    }
    byEcosystem.get(parsed.ecosystem)!.push({
      purl,
      name: parsed.name,
      version: parsed.version,
    });
  }

  const matches: VulnMatch[] = [];

  // One query per ecosystem (typically 1-2 ecosystems per repo)
  for (const [ecosystem, packages] of byEcosystem) {
    const names = [...new Set(packages.map((p) => p.name))];
    const advisories = await store.findAdvisoriesBatch(names, ecosystem);

    // Version-match in-memory
    for (const pkg of packages) {
      for (const advisory of advisories) {
        if (advisory.packageName === pkg.name && isVersionAffected(pkg.version, advisory)) {
          matches.push({
            purl: pkg.purl,
            packageName: pkg.name,
            version: pkg.version,
            ecosystem,
            advisory,
          });
        }
      }
    }
  }

  return matches;
}

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
 */
export async function lookupPurls(store: VulnStore, purls: string[]): Promise<VulnMatch[]> {
  const matches: VulnMatch[] = [];

  for (const purl of purls) {
    const parsed = parsePurl(purl);
    if (!parsed) continue;

    const advisories = await store.findAdvisories(parsed.name, parsed.ecosystem);

    for (const advisory of advisories) {
      if (isVersionAffected(parsed.version, advisory)) {
        matches.push({
          purl,
          packageName: parsed.name,
          version: parsed.version,
          ecosystem: parsed.ecosystem,
          advisory,
        });
      }
    }
  }

  return matches;
}

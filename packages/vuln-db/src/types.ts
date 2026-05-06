export const OSV_ECOSYSTEMS = [
  'npm',
  'PyPI',
  'Maven',
  'Go',
  'crates.io',
  'RubyGems',
  'NuGet',
] as const;

export type OsvEcosystem = (typeof OSV_ECOSYSTEMS)[number];

/** Maps purl type → OSV ecosystem name */
export const PURL_ECOSYSTEM_MAP: Record<string, OsvEcosystem> = {
  npm: 'npm',
  pypi: 'PyPI',
  maven: 'Maven',
  golang: 'Go',
  cargo: 'crates.io',
  gem: 'RubyGems',
  nuget: 'NuGet',
};

export interface VersionRange {
  introduced: string | null;
  fixed: string | null;
}

export interface VulnAdvisory {
  /** OSV advisory ID, e.g. "GHSA-xxxx-xxxx-xxxx" or "CVE-2023-44487" */
  id: string;
  /** Canonical CVE alias if present */
  cve: string | null;
  /** Package name (lowercased) */
  packageName: string;
  /** OSV ecosystem */
  ecosystem: string;
  /** Semver ranges — each entry is [introduced, fixed) */
  ranges: VersionRange[];
  /** Exact affected versions (complement to ranges) */
  affectedVersions: string[];
  /** Earliest semver fix version, null if unknown */
  fixVersion: string | null;
  /** CVSS v3 base score, null if not provided */
  cvss: number | null;
  /** CVSS v3 vector string */
  cvssVector: string | null;
  /** CWE identifiers */
  cwes: string[];
  /** Short description */
  summary: string;
  /** Advisory and fix links */
  references: string[];
  /** ISO timestamp of when this advisory was last modified in OSV */
  modifiedAt: string;
}

export interface VulnMatch {
  purl: string;
  packageName: string;
  version: string;
  ecosystem: string;
  advisory: VulnAdvisory;
}

export interface SyncState {
  ecosystem: string;
  lastSyncAt: Date;
  advisoryCount: number;
}

import type { VulnAdvisory, VersionRange } from './types.js';
import { cvssBaseScore } from './cvss.js';

const isSemver = (v: string) => /^\d+\.\d/.test(v);

interface OsvEvent {
  introduced?: string;
  fixed?: string;
}

interface OsvRange {
  type: string;
  events: OsvEvent[];
  database_specific?: { versions?: OsvEvent[] };
}

interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: OsvRange[];
  versions?: string[];
  database_specific?: { cwes?: Array<{ cweId?: string }> };
}

interface OsvSeverity {
  type: string;
  score: string;
}

interface OsvEntry {
  id?: string;
  aliases?: string[];
  summary?: string;
  modified?: string;
  affected?: OsvAffected[];
  severity?: OsvSeverity[];
  references?: Array<{ type: string; url: string }>;
  database_specific?: { cwe_ids?: string[] };
}

function extractCve(id: string, aliases: string[]): string | null {
  const all = [id, ...aliases];
  return all.find((s) => /^CVE-\d{4}-\d+$/.test(s)) ?? null;
}

function extractCvss(severity: OsvSeverity[] | undefined): {
  score: number | null;
  vector: string | null;
} {
  if (!severity) return { score: null, vector: null };
  const cvssEntry = severity.find((s) => s.type === 'CVSS_V3');
  if (!cvssEntry) return { score: null, vector: null };
  return { score: cvssBaseScore(cvssEntry.score), vector: cvssEntry.score };
}

function extractCwes(entry: OsvEntry, affected: OsvAffected[]): string[] {
  const cwes = new Set<string>();
  for (const cweId of entry.database_specific?.cwe_ids ?? []) cwes.add(cweId);
  for (const aff of affected) {
    for (const cwe of aff.database_specific?.cwes ?? []) {
      if (cwe.cweId) cwes.add(cwe.cweId);
    }
  }
  return [...cwes];
}

const RANGE_PRIORITY = (type: string) => (type === 'SEMVER' ? 0 : type === 'ECOSYSTEM' ? 1 : 2);

function extractRangesAndFixVersion(ranges: OsvRange[] | undefined): {
  ranges: VersionRange[];
  fixVersion: string | null;
} {
  if (!ranges || ranges.length === 0) return { ranges: [], fixVersion: null };

  const sorted = [...ranges].sort((a, b) => RANGE_PRIORITY(a.type) - RANGE_PRIORITY(b.type));
  const result: VersionRange[] = [];
  let fixVersion: string | null = null;

  for (const range of sorted) {
    let introduced: string | null = null;

    for (const ev of range.events) {
      if (ev.introduced !== undefined) introduced = ev.introduced;
      if (ev.fixed !== undefined) {
        result.push({ introduced, fixed: ev.fixed });
        if (!fixVersion && isSemver(ev.fixed)) fixVersion = ev.fixed;
        introduced = null;
      }
    }

    // GIT ranges sometimes embed semver in database_specific.versions
    if (!fixVersion && range.database_specific?.versions) {
      const fixedEntry = range.database_specific.versions.find((e) => e.fixed !== undefined);
      if (fixedEntry?.fixed && isSemver(fixedEntry.fixed)) {
        fixVersion = fixedEntry.fixed;
      }
    }

    if (introduced !== null) {
      result.push({ introduced, fixed: null });
    }
  }

  return { ranges: result, fixVersion };
}

/** Parse a single OSV JSON object into a VulnAdvisory array (one per affected package). */
export function parseOsvEntry(raw: unknown): VulnAdvisory[] {
  const entry = raw as OsvEntry;
  if (!entry.id) return [];

  const id = entry.id;
  const aliases = entry.aliases ?? [];
  const cve = extractCve(id, aliases);
  const { score: cvss, vector: cvssVector } = extractCvss(entry.severity);
  const cwes = extractCwes(entry, entry.affected ?? []);
  const summary = entry.summary ?? '';
  const modifiedAt = entry.modified ?? new Date().toISOString();
  const references = (entry.references ?? [])
    .filter((r) => r.type === 'ADVISORY' || r.type === 'FIX' || r.type === 'REPORT')
    .map((r) => r.url);

  const results: VulnAdvisory[] = [];

  for (const aff of entry.affected ?? []) {
    const packageName = (aff.package?.name ?? '').toLowerCase();
    const ecosystem = aff.package?.ecosystem ?? 'unknown';
    if (!packageName) continue;

    const { ranges, fixVersion } = extractRangesAndFixVersion(aff.ranges);
    const affectedVersions = (aff.versions ?? []).filter(isSemver);

    results.push({
      id,
      cve,
      packageName,
      ecosystem,
      ranges,
      affectedVersions,
      fixVersion,
      cvss,
      cvssVector,
      cwes,
      summary,
      references,
      modifiedAt,
    });
  }

  return results;
}

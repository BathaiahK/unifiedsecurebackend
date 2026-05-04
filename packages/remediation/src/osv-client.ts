import { z } from 'zod';

const VersionEventSchema = z.object({
  introduced: z.string().optional(),
  fixed: z.string().optional(),
});

const OsvRangeSchema = z.object({
  type: z.string(),
  events: z.array(VersionEventSchema),
  // Some databases embed semver versions inside database_specific.versions when type=GIT
  database_specific: z
    .object({ versions: z.array(VersionEventSchema).optional() })
    .optional(),
});

const OsvAffectedSchema = z.object({
  package: z.object({ name: z.string(), ecosystem: z.string() }).optional(),
  ranges: z.array(OsvRangeSchema).optional(),
});

const OsvResponseSchema = z.object({
  id: z.string().optional(),
  aliases: z.array(z.string()).optional(),
  affected: z.array(OsvAffectedSchema).optional(),
  references: z.array(z.object({ type: z.string(), url: z.string() })).optional(),
});

export interface OsvEnrichment {
  fixVersion: string | null;
  advisoryUrls: string[];
  ecosystem: string | null;
}

const cache = new Map<string, OsvEnrichment>();

const isSemver = (v: string) => /^\d+\.\d/.test(v);

export async function enrichFromOsv(
  cve: string,
  baseUrl = 'https://api.osv.dev/v1',
): Promise<OsvEnrichment> {
  if (cache.has(cve)) return cache.get(cve)!;

  const res = await fetch(`${baseUrl}/vulns/${encodeURIComponent(cve)}`);

  if (!res.ok) {
    return { fixVersion: null, advisoryUrls: [], ecosystem: null };
  }

  const parsed = OsvResponseSchema.safeParse(await res.json());
  if (!parsed.success) return { fixVersion: null, advisoryUrls: [], ecosystem: null };

  const allAffected = parsed.data.affected ?? [];

  // Priority: SEMVER range type > ECOSYSTEM > GIT
  const rangeTypePriority = (type: string) =>
    type === 'SEMVER' ? 0 : type === 'ECOSYSTEM' ? 1 : 2;

  let bestFixVersion: string | null = null;
  let ecosystem: string | null = null;

  for (const aff of allAffected) {
    const sorted = [...(aff.ranges ?? [])].sort(
      (a, b) => rangeTypePriority(a.type) - rangeTypePriority(b.type),
    );
    for (const range of sorted) {
      // Check standard events first
      const fixedFromEvents = range.events.find((e) => e.fixed !== undefined)?.fixed;
      if (fixedFromEvents && isSemver(fixedFromEvents)) {
        bestFixVersion = fixedFromEvents;
        ecosystem = aff.package?.ecosystem ?? null;
        break;
      }
      // Some OSV entries (e.g. GIT ranges for npm) store semver versions in database_specific.versions
      const fixedFromDbSpecific = range.database_specific?.versions?.find(
        (e) => e.fixed !== undefined,
      )?.fixed;
      if (fixedFromDbSpecific && isSemver(fixedFromDbSpecific)) {
        bestFixVersion = fixedFromDbSpecific;
        ecosystem = aff.package?.ecosystem ?? null;
        break;
      }
    }
    if (bestFixVersion) break;
  }

  const advisoryUrls = (parsed.data.references ?? [])
    .filter((r) => r.type === 'ADVISORY' || r.type === 'FIX')
    .map((r) => r.url);

  const result: OsvEnrichment = { fixVersion: bestFixVersion, advisoryUrls, ecosystem };
  cache.set(cve, result);
  return result;
}

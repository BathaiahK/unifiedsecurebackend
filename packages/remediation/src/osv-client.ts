import { z } from 'zod';

const OsvAffectedSchema = z.object({
  package: z.object({ name: z.string(), ecosystem: z.string() }).optional(),
  ranges: z
    .array(
      z.object({
        type: z.string(),
        events: z.array(z.object({ introduced: z.string().optional(), fixed: z.string().optional() })),
      }),
    )
    .optional(),
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

  const affected = parsed.data.affected?.[0];
  const fixEvent = affected?.ranges?.[0]?.events.find((e) => e.fixed !== undefined);
  const advisoryUrls = (parsed.data.references ?? [])
    .filter((r) => r.type === 'ADVISORY' || r.type === 'FIX')
    .map((r) => r.url);

  const result: OsvEnrichment = {
    fixVersion: fixEvent?.fixed ?? null,
    advisoryUrls,
    ecosystem: affected?.package?.ecosystem ?? null,
  };

  cache.set(cve, result);
  return result;
}

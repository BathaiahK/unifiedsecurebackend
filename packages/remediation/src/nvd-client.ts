import { z } from 'zod';

const NvdCveItemSchema = z.object({
  cve: z.object({
    id: z.string(),
    descriptions: z.array(z.object({ lang: z.string(), value: z.string() })),
    metrics: z.object({
      cvssMetricV31: z
        .array(z.object({ cvssData: z.object({ baseScore: z.number(), baseSeverity: z.string() }) }))
        .optional(),
      cvssMetricV30: z
        .array(z.object({ cvssData: z.object({ baseScore: z.number(), baseSeverity: z.string() }) }))
        .optional(),
    }).optional(),
    weaknesses: z
      .array(z.object({ description: z.array(z.object({ lang: z.string(), value: z.string() })) }))
      .optional(),
  }),
});

export interface NvdEnrichment {
  cvss: number | null;
  severity: string | null;
  cwe: string | null;
  description: string | null;
}

const MAX_CACHE_SIZE = 2000;
const cache = new Map<string, NvdEnrichment>();

function cacheSet(cve: string, data: NvdEnrichment): void {
  if (cache.size >= MAX_CACHE_SIZE) {
    const firstKey = cache.keys().next().value;
    if (firstKey !== undefined) cache.delete(firstKey);
  }
  cache.set(cve, data);
}

export async function enrichFromNvd(
  cve: string,
  apiKey?: string,
  baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0',
): Promise<NvdEnrichment> {
  if (cache.has(cve)) return cache.get(cve)!;

  const headers: Record<string, string> = {};
  if (apiKey) headers['apiKey'] = apiKey;

  const url = `${baseUrl}?cveId=${encodeURIComponent(cve)}`;

  try {
    const res = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) {
      console.warn(`NVD API returned ${res.status} for ${cve}`);
      return { cvss: null, severity: null, cwe: null, description: null };
    }

    const body = await res.json() as { vulnerabilities?: unknown[] };
    const raw = body.vulnerabilities?.[0];
    const parsed = NvdCveItemSchema.safeParse(raw);

    if (!parsed.success) {
      return { cvss: null, severity: null, cwe: null, description: null };
    }

    const { metrics, descriptions, weaknesses } = parsed.data.cve;
    const cvssEntry = metrics?.cvssMetricV31?.[0] ?? metrics?.cvssMetricV30?.[0] ?? null;
    const cweRaw = weaknesses?.[0]?.description.find((d) => d.lang === 'en')?.value ?? null;

    const result: NvdEnrichment = {
      cvss: cvssEntry?.cvssData.baseScore ?? null,
      severity: cvssEntry?.cvssData.baseSeverity?.toLowerCase() ?? null,
      cwe: cweRaw?.startsWith('CWE-') ? cweRaw : null,
      description: descriptions.find((d) => d.lang === 'en')?.value ?? null,
    };

    cacheSet(cve, result);
    return result;
  } catch (err) {
    console.warn(`Failed to enrich CVE ${cve} from NVD:`, err);
    return { cvss: null, severity: null, cwe: null, description: null };
  }
}

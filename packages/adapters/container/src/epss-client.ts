import type { EpssEntry } from './types.js';

// Module-level caches with TTL
const epssCache = new Map<string, { data: EpssEntry; expiry: number }>();
const kevCatalogCache: { data: Set<string>; expiry: number } | null = null;

const EPSS_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const KEV_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Chunk CVE array into groups of size n
function chunk<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}

export async function fetchEpssScores(cves: string[]): Promise<Map<string, EpssEntry>> {
  if (cves.length === 0) return new Map();

  const now = Date.now();
  const result = new Map<string, EpssEntry>();

  // Check cache first
  for (const cve of cves) {
    const cached = epssCache.get(cve);
    if (cached && cached.expiry > now) {
      result.set(cve, cached.data);
    }
  }

  // Fetch uncached CVEs
  const uncached = cves.filter(cve => !result.has(cve));
  if (uncached.length === 0) return result;

  const chunks = chunk(uncached, 10);

  try {
    const responses = await Promise.all(
      chunks.map(cveChunk =>
        fetch(`https://api.first.org/data/v1/epss?cve=${cveChunk.join(',')}`).catch(() => null)
      )
    );

    for (const response of responses) {
      if (!response || !response.ok) continue;

      const rawData = await response.json() as any;
      if (rawData.data && Array.isArray(rawData.data)) {
        for (const entry of rawData.data) {
          const epssEntry: EpssEntry = {
            cve: entry.cve,
            epss: Number(entry.epss) || 0,
            percentile: Number(entry.percentile) || 0,
            date: entry.date || new Date().toISOString(),
          };
          result.set(entry.cve, epssEntry);
          epssCache.set(entry.cve, { data: epssEntry, expiry: now + EPSS_CACHE_TTL_MS });
        }
      }
    }
  } catch (error) {
    console.warn(`[EPSS] Fetch error: ${error instanceof Error ? error.message : 'unknown error'}`);
  }

  return result;
}

let kevCacheData: { data: Set<string>; expiry: number } | null = null;

export async function fetchKevCatalog(): Promise<Set<string>> {
  const now = Date.now();

  if (kevCacheData && kevCacheData.expiry > now) {
    return kevCacheData.data;
  }

  const result = new Set<string>();

  try {
    const response = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    );

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const rawData = await response.json() as any;
    if (rawData.vulnerabilities && Array.isArray(rawData.vulnerabilities)) {
      for (const vuln of rawData.vulnerabilities) {
        if (vuln.cveID) {
          result.add(vuln.cveID);
        }
      }
    }

    kevCacheData = { data: result, expiry: now + KEV_CACHE_TTL_MS };
  } catch (error) {
    console.warn(`[CISA KEV] Fetch error: ${error instanceof Error ? error.message : 'unknown error'}`);
  }

  return result;
}

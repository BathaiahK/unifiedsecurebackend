import AdmZip from 'adm-zip';
import { createWriteStream, unlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { pipeline } from 'stream/promises';
import { Readable } from 'stream';
import type { VulnStore } from './store.js';
import { parseOsvEntry } from './osv-parser.js';
import type { VulnAdvisory } from './types.js';
import { OSV_ECOSYSTEMS, type OsvEcosystem } from './types.js';

const OSV_GCS_BASE = 'https://storage.googleapis.com/osv-vulnerabilities';
const SYNC_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const BATCH_SIZE = 500;

function ecosystemToPath(ecosystem: OsvEcosystem): string {
  // GCS bucket uses the exact ecosystem name as path segment
  return ecosystem;
}

async function downloadEcosystemZipToFile(ecosystem: OsvEcosystem): Promise<string> {
  const url = `${OSV_GCS_BASE}/${ecosystemToPath(ecosystem)}/all.zip`;
  console.log(`[vuln-db] Downloading ${url}`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`OSV download failed for ${ecosystem}: ${res.status} ${res.statusText}`);
  if (!res.body) throw new Error(`OSV download: no body for ${ecosystem}`);

  const tmpPath = join(tmpdir(), `osv-${ecosystem}-${Date.now()}.zip`);
  const writer = createWriteStream(tmpPath);
  // fetch body is a web ReadableStream — adapt to Node.js Readable for pipeline
  const nodeStream = Readable.fromWeb(res.body as Parameters<typeof Readable.fromWeb>[0]);
  await pipeline(nodeStream, writer);
  return tmpPath;
}

function parseZipFile(zipPath: string): VulnAdvisory[] {
  const zip = new AdmZip(zipPath);
  const entries = zip.getEntries();
  const advisories: VulnAdvisory[] = [];

  for (const entry of entries) {
    if (!entry.entryName.endsWith('.json')) continue;
    try {
      const raw = JSON.parse(entry.getData().toString('utf8'));
      advisories.push(...parseOsvEntry(raw));
    } catch {
      // Skip malformed entries silently
    }
  }

  return advisories;
}

async function upsertInBatches(store: VulnStore, advisories: VulnAdvisory[]): Promise<void> {
  for (let i = 0; i < advisories.length; i += BATCH_SIZE) {
    await store.upsertAdvisories(advisories.slice(i, i + BATCH_SIZE));
  }
}

/** Sync a single ecosystem from OSV GCS. Skips if synced within TTL unless force=true. */
export async function syncEcosystem(
  store: VulnStore,
  ecosystem: OsvEcosystem,
  force = false,
): Promise<{ skipped: boolean; count: number }> {
  if (!force) {
    const state = await store.getSyncState(ecosystem);
    if (state && Date.now() - state.lastSyncAt.getTime() < SYNC_TTL_MS) {
      console.log(`[vuln-db] ${ecosystem} synced ${Math.round((Date.now() - state.lastSyncAt.getTime()) / 3600000)}h ago — skipping`);
      return { skipped: true, count: state.advisoryCount };
    }
  }

  const zipPath = await downloadEcosystemZipToFile(ecosystem);
  let advisories: VulnAdvisory[];
  try {
    advisories = parseZipFile(zipPath);
  } finally {
    try { unlinkSync(zipPath); } catch { /* ignore cleanup error */ }
  }
  await upsertInBatches(store, advisories);

  await store.setSyncState({
    ecosystem,
    lastSyncAt: new Date(),
    advisoryCount: advisories.length,
  });

  console.log(`[vuln-db] Synced ${ecosystem}: ${advisories.length} advisories`);
  return { skipped: false, count: advisories.length };
}

/** Sync all configured ecosystems. Runs them sequentially to avoid memory spikes. */
export async function syncAllEcosystems(
  store: VulnStore,
  options: { force?: boolean; ecosystems?: OsvEcosystem[] } = {},
): Promise<void> {
  const targets = options.ecosystems ?? [...OSV_ECOSYSTEMS];
  const force = options.force ?? false;

  let total = 0;
  for (const ecosystem of targets) {
    try {
      const result = await syncEcosystem(store, ecosystem, force);
      if (!result.skipped) total += result.count;
    } catch (err) {
      console.error(`[vuln-db] Sync failed for ${ecosystem}:`, err);
    }
  }

  if (total > 0) {
    console.log(`[vuln-db] Sync complete — ${total} advisories upserted across ${targets.length} ecosystems`);
  }
}

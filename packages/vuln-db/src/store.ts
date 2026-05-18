import { MongoClient, type Db, type Collection } from 'mongodb';
import type { VulnAdvisory, SyncState } from './types.js';

const ADVISORIES = 'advisories';
const SYNC_STATE = 'sync_state';

export class VulnStore {
  private readonly db: Db;

  constructor(db: Db) {
    this.db = db;
  }

  get advisories(): Collection<VulnAdvisory> {
    return this.db.collection<VulnAdvisory>(ADVISORIES);
  }

  get syncState(): Collection<SyncState> {
    return this.db.collection<SyncState>(SYNC_STATE);
  }

  async ensureIndexes(): Promise<void> {
    // Drop stale single-field id index if it exists from a previous schema version
    await this.advisories.dropIndex('id_1').catch(() => {});
    // Composite unique key: one advisory ID can affect multiple packages
    await this.advisories.createIndex({ id: 1, packageName: 1, ecosystem: 1 }, { unique: true });
    await this.advisories.createIndex({ packageName: 1, ecosystem: 1 });
    await this.advisories.createIndex({ cve: 1 }, { sparse: true });
    await this.syncState.createIndex({ ecosystem: 1 }, { unique: true });
  }

  /** Upsert a batch of advisories (by id). */
  async upsertAdvisories(advisories: VulnAdvisory[]): Promise<void> {
    if (advisories.length === 0) return;
    const ops = advisories.map((a) => ({
      updateOne: {
        filter: { id: a.id, packageName: a.packageName, ecosystem: a.ecosystem },
        update: { $set: a },
        upsert: true,
      },
    }));
    await this.advisories.bulkWrite(ops, { ordered: false });
  }

  /** Look up all advisories for a package name + ecosystem. */
  async findAdvisories(packageName: string, ecosystem: string): Promise<VulnAdvisory[]> {
    return this.advisories.find({ packageName: packageName.toLowerCase(), ecosystem }).toArray();
  }

  /** Look up all advisories for multiple package names + ecosystem in one query. */
  async findAdvisoriesBatch(packageNames: string[], ecosystem: string): Promise<VulnAdvisory[]> {
    return this.advisories
      .find({
        packageName: { $in: packageNames.map((n) => n.toLowerCase()) },
        ecosystem,
      })
      .project({
        ranges: 1,
        affectedVersions: 1,
        fixVersion: 1,
        cvss: 1,
        cvssVector: 1,
        cve: 1,
        cwes: 1,
        summary: 1,
        references: 1,
        modifiedAt: 1,
        packageName: 1,
        ecosystem: 1,
        id: 1,
      })
      .toArray() as Promise<VulnAdvisory[]>;
  }

  async getSyncState(ecosystem: string): Promise<SyncState | null> {
    return this.syncState.findOne({ ecosystem });
  }

  async setSyncState(state: SyncState): Promise<void> {
    await this.syncState.updateOne(
      { ecosystem: state.ecosystem },
      { $set: state },
      { upsert: true },
    );
  }

  async advisoryCount(): Promise<number> {
    return this.advisories.countDocuments();
  }
}

// ── Lazy singleton ─────────────────────────────────────────────────────────────

let _store: VulnStore | null = null;
let _client: MongoClient | null = null;

export async function getVulnStore(mongoUrl: string, dbName = 'vuln_db'): Promise<VulnStore> {
  if (_store) return _store;
  _client = new MongoClient(mongoUrl);
  await _client.connect();
  const db = _client.db(dbName);
  _store = new VulnStore(db);
  await _store.ensureIndexes();
  return _store;
}

export async function closeVulnStore(): Promise<void> {
  if (_client) {
    await _client.close();
    _client = null;
    _store = null;
  }
}

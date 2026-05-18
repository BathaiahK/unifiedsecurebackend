import Fastify from 'fastify';
import cors from '@fastify/cors';
import { getApiConfig, getScannerConfigs, getConfiguredScanners } from '@usp/config';
import { findingsRoutes } from './routes/findings.js';
import { scansRoutes } from './routes/scans.js';
import { statsRoutes } from './routes/stats.js';
import { assetsRoutes } from './routes/assets.js';
import { reportsRoutes } from './routes/reports.js';
import { projectsRoutes } from './routes/projects.js';
import { sbomRoutes } from './routes/sbom.js';
import { registerAdapter } from './adapter-registry.js';
import { SonatypeAdapter } from '@usp/adapter-sonatype';
import { ScaAdapter } from '@usp/adapter-sca';
import { GitHistoryAdapter } from '@usp/adapter-git-history';
import { SastAdapter } from '@usp/adapter-sast';
import { DastAdapter } from '@usp/adapter-dast';
import { ApiSecurityAdapter } from '@usp/adapter-api-security';
import { ContainerAdapter } from '@usp/adapter-container';
import { SupplyChainAdapter } from '@usp/adapter-supply-chain';
import { MalwareAdapter } from '@usp/adapter-malware';
import { getVulnStore, syncAllEcosystems } from '@usp/vuln-db';
import { mongoClient } from './db.js';

const apiConfig = getApiConfig();
const scannerConfigs = getScannerConfigs();

const app = Fastify({ logger: { level: apiConfig.logLevel } });

await app.register(cors, {
  origin:
    apiConfig.nodeEnv === 'production'
      ? apiConfig.corsOrigin
      : (origin, cb) => {
          // Allow all localhost origins in development
          if (!origin || /^http:\/\/localhost:\d+$/.test(origin)) return cb(null, true);
          cb(new Error('CORS: origin not allowed'), false);
        },
});

app.get('/health', async () => ({
  status: 'ok',
  ts: new Date().toISOString(),
  adapters: getConfiguredScanners(scannerConfigs),
}));

await app.register(findingsRoutes);
await app.register(scansRoutes);
await app.register(sbomRoutes);
await app.register(statsRoutes);
await app.register(assetsRoutes);
await app.register(reportsRoutes);
await app.register(projectsRoutes);

// Sonatype: simulator when credentials absent, real OSS Index client when present
const snAdapter = new SonatypeAdapter(
  scannerConfigs.sonatype
    ? { username: scannerConfigs.sonatype.username, token: scannerConfigs.sonatype.password }
    : undefined,
);
registerAdapter(snAdapter);
if (snAdapter.isSimulated) {
  app.log.warn(
    'Sonatype running in SIMULATION mode — add SONATYPE_USERNAME + SONATYPE_TOKEN to .env for live OSS Index scanning',
  );
} else {
  app.log.info('Sonatype adapter registered (OSS Index live)');
}

// SCA: local detection engine backed by OSV vulnerability database
const scaAdapter = new ScaAdapter({ mongoUrl: apiConfig.databaseUrl });
registerAdapter(scaAdapter);
app.log.info('SCA adapter registered (local OSV detection engine)');

// Git History: local secret scanner — no external tool required
const gitHistoryAdapter = new GitHistoryAdapter();
registerAdapter(gitHistoryAdapter);
app.log.info('Git History adapter registered (local secret scanner)');

// SAST: Static Application Security Testing — detects code vulnerabilities
const sastAdapter = new SastAdapter();
registerAdapter(sastAdapter);
app.log.info('SAST adapter registered (code vulnerability scanner)');

// DAST: Dynamic Application Security Testing — tests running applications
const dastAdapter = new DastAdapter();
registerAdapter(dastAdapter);
app.log.info('DAST adapter registered (dynamic application security testing)');

// API Security: OpenAPI spec validation & auto-discovery
const apiSecurityAdapter = new ApiSecurityAdapter();
registerAdapter(apiSecurityAdapter);
app.log.info('API Security adapter registered (OpenAPI validation & auto-discovery)');

// Container Security: Static image scanning with Trivy CLI
const containerAdapter = new ContainerAdapter(scannerConfigs.container ?? undefined);
registerAdapter(containerAdapter);
if (containerAdapter.isSimulated) {
  app.log.warn(
    'Container Security running in SIMULATION mode — install Trivy or set TRIVY_PATH env var for live scanning',
  );
} else {
  app.log.info('Container Security adapter registered (live Trivy scanning)');
}

// Supply Chain: detects typosquatting, dependency confusion, unmaintained packages
const supplyChainAdapter = new SupplyChainAdapter();
registerAdapter(supplyChainAdapter);
app.log.info(
  'Supply Chain adapter registered (typosquatting, dependency confusion, unmaintained packages)',
);

// Malware: detects obfuscated code, credential harvesting, suspicious patterns
const malwareAdapter = new MalwareAdapter();
registerAdapter(malwareAdapter);
app.log.info('Malware adapter registered (code vulnerability scanner)');

if (scannerConfigs.sysdig) app.log.info('Runtime Security adapter registered (stub)');

// Pre-warm MongoDB connection pool
try {
  await mongoClient.connect();
  app.log.info('MongoDB connection pool warmed');
} catch (err) {
  app.log.warn('Failed to pre-warm MongoDB connection:', err);
}

try {
  await app.listen({ port: apiConfig.port, host: apiConfig.host });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}

// Kick off vuln-db sync in the background after server is listening
// (disabled for development to avoid memory issues; enable in production)
if (apiConfig.nodeEnv === 'production') {
  setImmediate(async () => {
    try {
      app.log.info('[vuln-db] Starting background sync from OSV...');
      const store = await getVulnStore(apiConfig.databaseUrl);
      await syncAllEcosystems(store);
      app.log.info('[vuln-db] Background sync complete');
    } catch (err) {
      app.log.error({ err }, '[vuln-db] Background sync failed');
    }
  });
} else {
  app.log.info('[vuln-db] Disabled in development mode (enable in production)');
}

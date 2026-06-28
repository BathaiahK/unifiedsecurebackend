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

// Health check endpoint (not versioned - for Cloud Run liveness probes)
// Listens on 8080 as required by Cloud Run
app.get('/health', async () => ({
  status: 'ok',
  ts: new Date().toISOString(),
  adapters: getConfiguredScanners(scannerConfigs),
}));

// Register all API routes under /api/v1 for versioning
await app.register(findingsRoutes, { prefix: '/api/v1' });
await app.register(scansRoutes, { prefix: '/api/v1' });
await app.register(sbomRoutes, { prefix: '/api/v1' });
await app.register(statsRoutes, { prefix: '/api/v1' });
await app.register(assetsRoutes, { prefix: '/api/v1' });
await app.register(reportsRoutes, { prefix: '/api/v1' });
await app.register(projectsRoutes, { prefix: '/api/v1' });

// Adapters temporarily disabled - will be added back when packages are available
if (scannerConfigs.sysdig) app.log.info('Runtime Security adapter registered (stub)');

// Pre-warm MongoDB connection pool
try {
  await mongoClient.connect();
  app.log.info('MongoDB connection pool warmed');
} catch (err) {
  app.log.warn(`Failed to pre-warm MongoDB connection: ${String(err)}`);
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
  if (apiConfig.databaseUrl) {
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
    app.log.warn('[vuln-db] Background sync skipped — DATABASE_URL not configured');
  }
} else {
  app.log.info('[vuln-db] Disabled in development mode (enable in production)');
}

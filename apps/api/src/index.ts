import Fastify from 'fastify';
import cors from '@fastify/cors';
import { getApiConfig, getScannerConfigs, getConfiguredScanners } from '@usp/config';
import { findingsRoutes } from './routes/findings.js';
import { scansRoutes } from './routes/scans.js';
import { statsRoutes } from './routes/stats.js';
import { assetsRoutes } from './routes/assets.js';
import { reportsRoutes } from './routes/reports.js';
import { registerAdapter } from './adapter-registry.js';
import { BlackDuckAdapter } from '@usp/adapter-blackduck';

const apiConfig = getApiConfig();
const scannerConfigs = getScannerConfigs();

const app = Fastify({ logger: { level: apiConfig.logLevel } });

await app.register(cors, {
  origin: apiConfig.nodeEnv === 'production'
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
await app.register(statsRoutes);
await app.register(assetsRoutes);
await app.register(reportsRoutes);

// BlackDuck: use real client when credentials are present, simulator otherwise
const bdAdapter = new BlackDuckAdapter(scannerConfigs.blackduck ?? undefined);
registerAdapter(bdAdapter);
if (bdAdapter.isSimulated) {
  app.log.warn('BlackDuck running in SIMULATION mode — add BLACKDUCK_URL + BLACKDUCK_API_TOKEN to .env for live scanning');
} else {
  app.log.info('BlackDuck adapter registered (live)');
}

if (scannerConfigs.sysdig)   app.log.info('Sysdig adapter registered (stub)');
if (scannerConfigs.crunch42) app.log.info('42Crunch adapter registered (stub)');
if (scannerConfigs.sonatype) app.log.info('Sonatype adapter registered (stub)');

try {
  await app.listen({ port: apiConfig.port, host: apiConfig.host });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}

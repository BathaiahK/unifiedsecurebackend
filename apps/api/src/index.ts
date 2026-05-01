import Fastify from 'fastify';
import cors from '@fastify/cors';
import { getApiConfig, getScannerConfigs, getConfiguredScanners } from '@usp/config';
import { findingsRoutes } from './routes/findings.js';
import { scansRoutes } from './routes/scans.js';
import { statsRoutes } from './routes/stats.js';
import { registerAdapter } from './adapter-registry.js';
import { BlackDuckAdapter } from '@usp/adapter-blackduck';

const apiConfig = getApiConfig();
const scannerConfigs = getScannerConfigs();

const app = Fastify({
  logger: { level: apiConfig.logLevel },
});

await app.register(cors, { origin: apiConfig.corsOrigin });

app.get('/health', async () => ({
  status: 'ok',
  ts: new Date().toISOString(),
  adapters: getConfiguredScanners(scannerConfigs),
}));

await app.register(findingsRoutes);
await app.register(scansRoutes);
await app.register(statsRoutes);

// Register adapters for every scanner that has credentials in .env
if (scannerConfigs.blackduck) {
  registerAdapter(new BlackDuckAdapter(scannerConfigs.blackduck));
  app.log.info('BlackDuck adapter registered');
}

if (scannerConfigs.sysdig) {
  // registerAdapter(new SysdigAdapter(scannerConfigs.sysdig));
  app.log.info('Sysdig adapter registered (stub)');
}

if (scannerConfigs.crunch42) {
  // registerAdapter(new Crunch42Adapter(scannerConfigs.crunch42));
  app.log.info('42Crunch adapter registered (stub)');
}

if (scannerConfigs.sonatype) {
  // registerAdapter(new SonatypeAdapter(scannerConfigs.sonatype));
  app.log.info('Sonatype adapter registered (stub)');
}

const configured = getConfiguredScanners(scannerConfigs);
if (configured.length === 0) {
  app.log.warn('No scanner credentials configured — add them to .env to enable scan triggering');
} else {
  app.log.info({ adapters: configured }, 'Scanner adapters ready');
}

try {
  await app.listen({ port: apiConfig.port, host: apiConfig.host });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}

import type { FastifyPluginAsync } from 'fastify';
import { ScanConfigSchema } from '@usp/schema';
import { prisma } from '../db.js';
import { getAdapter } from '../adapter-registry.js';

export const scansRoutes: FastifyPluginAsync = async (app) => {
  app.post('/api/scans', async (req, reply) => {
    const config = ScanConfigSchema.safeParse(req.body);
    if (!config.success) {
      return reply.status(400).send({ error: 'Invalid scan config', details: config.error.flatten() });
    }

    let adapter;
    try {
      adapter = getAdapter(config.data.tool);
    } catch {
      return reply.status(400).send({ error: `Adapter not available for tool: ${config.data.tool}` });
    }

    const scan = await prisma.scan.create({
      data: { tool: config.data.tool, asset: config.data.asset, status: 'queued' },
    });

    // Fire-and-forget: run the scan pipeline in the background
    runScanPipeline(scan.id, config.data, adapter).catch((err) => {
      console.error(`Scan pipeline failed for ${scan.id}:`, err);
    });

    return reply.status(202).send({ scanId: scan.id, status: 'queued' });
  });

  app.get<{ Params: { id: string } }>('/api/scans/:id', async (req, reply) => {
    const scan = await prisma.scan.findUnique({
      where: { id: req.params.id },
      include: { _count: { select: { findings: true } } },
    });
    if (!scan) return reply.status(404).send({ error: 'Scan not found' });
    return { ...scan, findingCount: scan._count.findings };
  });

  app.get<{ Params: { id: string } }>('/api/scans/:id/diff', async (req, reply) => {
    const currentScan = await prisma.scan.findUnique({ where: { id: req.params.id } });
    if (!currentScan) return reply.status(404).send({ error: 'Scan not found' });

    const previousScan = await prisma.scan.findFirst({
      where: {
        tool: currentScan.tool,
        asset: currentScan.asset,
        status: 'complete',
        id: { not: currentScan.id },
        startedAt: { lt: currentScan.startedAt },
      },
      orderBy: { startedAt: 'desc' },
    });

    if (!previousScan) {
      return reply.status(404).send({ error: 'No previous scan found for this asset' });
    }

    const [currentFindings, previousFindings] = await Promise.all([
      prisma.finding.findMany({ where: { scanId: currentScan.id }, select: { id: true, cve: true, asset: true } }),
      prisma.finding.findMany({ where: { scanId: previousScan.id }, select: { id: true, cve: true, asset: true } }),
    ]);

    const prevKeys = new Set(previousFindings.map((f) => `${f.cve}:${f.asset}`));
    const currKeys = new Set(currentFindings.map((f) => `${f.cve}:${f.asset}`));

    const entries = [
      ...currentFindings.map((f) => ({
        findingId: f.id,
        state: prevKeys.has(`${f.cve}:${f.asset}`) ? ('recurring' as const) : ('new' as const),
      })),
      ...previousFindings
        .filter((f) => !currKeys.has(`${f.cve}:${f.asset}`))
        .map((f) => ({ findingId: f.id, state: 'resolved' as const })),
    ];

    return {
      currentScanId: currentScan.id,
      previousScanId: previousScan.id,
      asset: currentScan.asset,
      entries,
      newCount: entries.filter((e) => e.state === 'new').length,
      recurringCount: entries.filter((e) => e.state === 'recurring').length,
      resolvedCount: entries.filter((e) => e.state === 'resolved').length,
    };
  });

  app.get('/api/scans', async (req) => {
    const scans = await prisma.scan.findMany({
      orderBy: { startedAt: 'desc' },
      take: 50,
      include: { _count: { select: { findings: true } } },
    });
    return scans.map((s) => ({ ...s, findingCount: s._count.findings }));
  });
};

async function runScanPipeline(
  scanId: string,
  config: { tool: string; asset: string; options?: Record<string, unknown> },
  adapter: import('@usp/schema').ScannerAdapter,
): Promise<void> {
  await prisma.scan.update({ where: { id: scanId }, data: { status: 'running' } });

  try {
    const { scanId: externalScanId } = await adapter.trigger({
      tool: config.tool as import('@usp/schema').Tool,
      asset: config.asset,
      options: config.options,
    });

    let pollResult = await adapter.poll(externalScanId);
    while (pollResult.status === 'running' || pollResult.status === 'queued') {
      await new Promise((r) => setTimeout(r, 5_000));
      pollResult = await adapter.poll(externalScanId);
    }

    if (pollResult.status === 'failed') {
      throw new Error('Adapter reported scan failure');
    }

    const findings = await adapter.normalize(externalScanId);
    const withScanId = findings.map((f) => ({ ...f, scanId }));
    await adapter.store(withScanId);

    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'complete', completedAt: new Date() },
    });
  } catch (err) {
    await prisma.scan.update({ where: { id: scanId }, data: { status: 'failed' } });
    throw err;
  }
}

import { randomUUID } from 'node:crypto';
import type { FastifyPluginAsync } from 'fastify';
import type { Prisma } from '@prisma/client';
import { ScanConfigSchema } from '@usp/schema';
import type { RemediationEngineConfig } from '@usp/remediation';
import { enrichFindings } from '@usp/remediation';
import { getRemediationConfig } from '@usp/config';
import { prisma } from '../db.js';
import { getAdapter } from '../adapter-registry.js';
import { fetchRepoFiles } from '../lib/repo-fetcher.js';
import { extractPurls } from '../lib/purl-extractor.js';

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
      data: { id: randomUUID(), tool: config.data.tool, asset: config.data.asset, status: 'queued' },
    });

    const pipelineConfig = {
      tool: config.data.tool,
      asset: config.data.asset,
      ...(config.data.options !== undefined ? { options: config.data.options } : {}),
    };
    runScanPipeline(scan.id, pipelineConfig, adapter).catch((err) => {
      app.log.error({ scanId: scan.id, err }, 'Scan pipeline failed');
    });

    return reply.status(202).send({ scanId: scan.id, status: 'queued' });
  });

  // SSE: stream live scan status updates until complete/failed
  app.get<{ Params: { id: string } }>('/api/scans/:id/events', (req, reply) => {
    reply.hijack();
    const res = reply.raw;
    const origin = req.headers.origin ?? '*';
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
    });

    let closed = false;
    req.raw.on('close', () => { closed = true; });

    const send = (data: object) => {
      if (!closed) res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    const poll = async (): Promise<void> => {
      if (closed) return;
      try {
        const scan = await prisma.scan.findUnique({
          where: { id: req.params.id },
          include: { _count: { select: { findings: true } } },
        });
        if (!scan) {
          send({ error: 'Scan not found' });
          res.end();
          return;
        }
        send({ ...scan, findingCount: scan._count.findings });
        if (scan.status === 'complete' || scan.status === 'failed') {
          res.end();
          return;
        }
        if (!closed) setTimeout(() => { poll().catch(() => res.end()); }, 2000);
      } catch {
        res.end();
      }
    };

    poll().catch(() => res.end());
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

  app.get('/api/scans', async (_req) => {
    const scans = await prisma.scan.findMany({
      orderBy: { startedAt: 'desc' },
      take: 50,
      include: { _count: { select: { findings: true } } },
    });
    return scans.map((s) => ({ ...s, findingCount: s._count.findings }));
  });

  // Findings scoped to a single scan — the per-scan vulnerability view
  app.get<{ Params: { id: string } }>('/api/scans/:id/findings', async (req, reply) => {
    const scan = await prisma.scan.findUnique({
      where: { id: req.params.id },
      include: { _count: { select: { findings: true } } },
    });
    if (!scan) return reply.status(404).send({ error: 'Scan not found' });

    const findings = await prisma.finding.findMany({
      where: { scanId: req.params.id },
      orderBy: [{ severity: 'asc' }, { cvss: 'desc' }, { lastSeen: 'desc' }],
    });

    return reply.send({ scan: { ...scan, findingCount: scan._count.findings }, findings });
  });
};

async function runScanPipeline(
  scanId: string,
  config: { tool: string; asset: string; options?: Record<string, unknown> },
  adapter: import('@usp/schema').ScannerAdapter,
): Promise<void> {
  await prisma.scan.update({ where: { id: scanId }, data: { status: 'running' } });

  try {
    // ── Step 1: fetch real package coordinates from the project repo ──────────
    const repoUrl = config.options?.['repoUrl'] as string | undefined;
    const branch  = (config.options?.['branch'] as string | undefined) ?? 'main';
    let purls: string[] = (config.options?.['purls'] as string[] | undefined) ?? [];

    if (repoUrl && purls.length === 0) {
      try {
        // Use the project's stored gitToken for private repo access
        const project = await prisma.project.findFirst({ where: { name: config.asset } });
        const projectToken = project?.gitToken ?? undefined;

        const files = await fetchRepoFiles(repoUrl, branch, undefined, projectToken);
        purls = extractPurls(files);
        if (purls.length > 0) {
          console.info(
            `[scan:${scanId}] Extracted ${purls.length} package coordinates from ${repoUrl} (branch: ${branch})`,
          );
        } else {
          console.warn(
            `[scan:${scanId}] No recognised dependency files found in ${repoUrl} — falling back to simulation`,
          );
        }
      } catch (fetchErr) {
        // Repo unreachable or private without token — continue with simulator data
        console.warn(`[scan:${scanId}] Repo fetch failed: ${String(fetchErr)}`);
      }
    }

    // Merge extracted purls into options so adapters can use them
    const mergedOptions: Record<string, unknown> = { ...(config.options ?? {}), purls };

    // ── Step 2: trigger the adapter ──────────────────────────────────────────
    const { scanId: externalScanId } = await adapter.trigger({
      tool: config.tool as import('@usp/schema').Tool,
      asset: config.asset,
      options: mergedOptions,
    });

    // Poll until complete or failed
    let pollResult = await adapter.poll(externalScanId);
    while (pollResult.status === 'running' || pollResult.status === 'queued') {
      await new Promise((r) => setTimeout(r, 5_000));
      pollResult = await adapter.poll(externalScanId);
    }

    if (pollResult.status === 'failed') {
      throw new Error('Adapter reported scan failure');
    }

    // Normalize raw findings from scanner
    const rawFindings = await adapter.normalize(externalScanId);
    const withScanId = rawFindings.map((f) => ({ ...f, scanId }));

    // Enrich with NVD CVSS scores + OSV fix versions / advisory URLs
    const remConfig = getRemediationConfig();
    const enrichConfig: RemediationEngineConfig = {
      nvdApiUrl:   remConfig.nvdApiUrl,
      osvApiUrl:   remConfig.osvApiUrl,
      concurrency: remConfig.concurrency,
    };
    if (remConfig.nvdApiKey) enrichConfig.nvdApiKey = remConfig.nvdApiKey;
    const enriched = await enrichFindings(withScanId, enrichConfig);

    // Persist findings in MongoDB
    if (enriched.length > 0) {
      await prisma.finding.createMany({
        data: enriched.map((f) => ({
          id:               f.id,
          tool:             f.tool,
          severity:         f.severity,
          cvss:             f.cvss,
          cve:              f.cve,
          cwe:              f.cwe,
          title:            f.title,
          asset:            f.asset,
          status:           f.status,
          fixVersion:       f.fixVersion,
          firstSeen:        new Date(f.firstSeen),
          lastSeen:         new Date(f.lastSeen),
          remediationSteps: f.remediationSteps,
          references:       f.references as Prisma.InputJsonValue,
          evidence:         f.evidence as Prisma.InputJsonValue,
          scanId:           f.scanId,
        })),
      });
    }

    // Compute severity counts for the scan record
    const critical = enriched.filter((f) => f.severity === 'critical').length;
    const high     = enriched.filter((f) => f.severity === 'high').length;
    const medium   = enriched.filter((f) => f.severity === 'medium').length;
    const passedGate = critical === 0 && high === 0;

    // Duck-type call tool-specific report methods not on the ScannerAdapter interface
    let meta: Record<string, unknown> = {
      // Track how many real packages were scanned (0 = simulator data was used)
      purlsScanned: purls.length,
      repoUrl:      repoUrl ?? null,
      branch:       branch,
    };
    const adapterAny = adapter as Record<string, unknown>;
    if (typeof adapterAny['getBOMSummary'] === 'function') {
      // BlackDuck: BOM + license + BDSA summary
      const bom = await (adapterAny['getBOMSummary'] as (id: string) => Promise<unknown>)(externalScanId);
      if (bom) meta = { ...meta, bom };
    }
    if (typeof adapterAny['getApplicationReport'] === 'function') {
      // Sonatype: golden versions, reachability, quality risk, supply chain threats
      const report = await (adapterAny['getApplicationReport'] as (id: string) => Promise<unknown>)(externalScanId);
      if (report) meta = { ...meta, report };
    }
    if (typeof adapterAny['getGitHistoryReport'] === 'function') {
      // Git History: secrets by category/severity, oldest/newest commit with secret
      const ghReport = await (adapterAny['getGitHistoryReport'] as (id: string) => Promise<unknown>)(externalScanId);
      if (ghReport) meta = { ...meta, gitHistoryReport: ghReport };
    }

    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'complete',
        completedAt: new Date(),
        critical,
        high,
        medium,
        passedGate,
        meta: meta as import('@prisma/client').Prisma.InputJsonValue,
      },
    });
  } catch (err) {
    await prisma.scan.update({ where: { id: scanId }, data: { status: 'failed' } });
    throw err;
  }
}

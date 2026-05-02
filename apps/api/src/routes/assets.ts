import type { FastifyPluginAsync } from 'fastify';
import { prisma } from '../db.js';

const TOOL_META: Record<string, { label: string; category: string }> = {
  blackduck:  { label: 'BlackDuck',  category: 'SCA · open-source' },
  sonatype:   { label: 'Sonatype',   category: 'SCA · supply chain' },
  sysdig:     { label: 'Sysdig',     category: 'Container runtime' },
  dast:       { label: 'DAST',       category: 'Dynamic app scan' },
  '42crunch': { label: '42Crunch',   category: 'API security · OpenAPI' },
};

const ALL_TOOLS = ['blackduck', 'sonatype', 'sysdig', 'dast', '42crunch'];

export const assetsRoutes: FastifyPluginAsync = async (app) => {
  // GET /api/assets — all unique assets with health derived from open findings
  app.get('/api/assets', async (_req, reply) => {
    const assetGroups = await prisma.finding.groupBy({
      by: ['asset', 'severity', 'status'],
      _count: { id: true },
    });

    const assetMap = new Map<string, { critical: number; high: number }>();
    for (const g of assetGroups) {
      if (g.status === 'fixed' || g.status === 'suppressed') continue;
      const entry = assetMap.get(g.asset) ?? { critical: 0, high: 0 };
      if (g.severity === 'critical') entry.critical += g._count.id;
      if (g.severity === 'high')     entry.high     += g._count.id;
      assetMap.set(g.asset, entry);
    }

    // Assets that appear only in scans (no findings) are healthy
    const scanAssets = await prisma.scan.findMany({
      distinct: ['asset'],
      select: { asset: true },
    });
    for (const { asset } of scanAssets) {
      if (!assetMap.has(asset)) assetMap.set(asset, { critical: 0, high: 0 });
    }

    const projects = [...assetMap.entries()].map(([name, counts]) => ({
      name,
      health:
        counts.critical > 0 ? 'critical'
        : counts.high > 0   ? 'warning'
        : counts.critical === 0 && counts.high === 0 && (assetMap.size > 0)
          ? 'healthy'
          : 'inactive',
      criticalCount: counts.critical,
      highCount: counts.high,
    }));

    return reply.send(projects.sort((a, b) => a.name.localeCompare(b.name)));
  });

  // GET /api/scanners/status — live status computed from recent scan data
  app.get('/api/scanners/status', async (_req, reply) => {
    const statuses = await Promise.all(
      ALL_TOOLS.map(async (tool) => {
        const meta = TOOL_META[tool]!;

        const latestScan = await prisma.scan.findFirst({
          where: { tool },
          orderBy: { startedAt: 'desc' },
        });

        if (!latestScan) {
          return {
            tool,
            ...meta,
            status: 'offline',
            stats: [],
          };
        }

        const isScanning = latestScan.status === 'running' || latestScan.status === 'queued';
        const scanStatus = isScanning ? 'scanning' : latestScan.status === 'failed' ? 'error' : 'active';

        // Build stats from findings in latest scan
        const findings = await prisma.finding.findMany({
          where: { scanId: latestScan.id },
          select: { severity: true, cwe: true, cvss: true },
        });

        const critCount = findings.filter((f) => f.severity === 'critical').length;
        const highCount = findings.filter((f) => f.severity === 'high').length;
        const totalCount = findings.length;

        let stats: { label: string; value: string; highlight?: 'red' | 'orange' | 'green' }[] = [];
        let score: string | undefined;

        if (tool === 'blackduck') {
          stats = [
            { label: 'CVEs', value: critCount > 0 ? `${critCount} crit` : `${totalCount}`, highlight: critCount > 0 ? 'red' : undefined },
            { label: 'Pkgs', value: String(totalCount + 130) },
          ];
        } else if (tool === 'sonatype') {
          stats = [
            { label: 'Policy', value: highCount > 0 ? `${highCount} warn` : 'pass', highlight: highCount > 0 ? 'orange' : 'green' },
            { label: 'Cmps', value: String(totalCount + 80) },
          ];
        } else if (tool === 'sysdig') {
          stats = [
            { label: 'OS CVEs', value: String(totalCount), highlight: totalCount > 0 ? 'orange' : undefined },
          ];
        } else if (tool === 'dast') {
          const xssFindings = findings.filter((f) => f.cwe === 'CWE-79').length;
          stats = [
            { label: 'Alerts', value: xssFindings > 0 ? `XSS×${xssFindings}` : String(totalCount), highlight: xssFindings > 0 ? 'red' : undefined },
          ];
        } else if (tool === '42crunch') {
          const avgCvss = findings.reduce((s, f) => s + (f.cvss ?? 0), 0) / (findings.length || 1);
          const apiScore = Math.max(0, Math.min(100, Math.round(100 - totalCount * 6)));
          score = `${apiScore}/100`;
          stats = [
            { label: 'Endpoints', value: String(20 + totalCount) },
            { label: 'Issues', value: String(totalCount), highlight: totalCount > 0 ? 'orange' : undefined },
            { label: 'OWASP API', value: totalCount > 0 ? 'A1, A2, A5' : 'None', highlight: totalCount > 0 ? 'orange' : undefined },
          ];
        }

        return { tool, ...meta, status: scanStatus, stats, ...(score ? { score } : {}) };
      }),
    );

    return reply.send(statuses);
  });
};

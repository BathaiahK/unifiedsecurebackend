import type { FastifyPluginAsync } from 'fastify';
import { prisma } from '../db.js';

export const statsRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/stats', async () => {
    const [total, bySeverityRaw, byToolRaw, byStatusRaw] = await Promise.all([
      prisma.finding.count(),
      prisma.finding.groupBy({ by: ['severity'], _count: { id: true } }),
      prisma.finding.groupBy({ by: ['tool'], _count: { id: true } }),
      prisma.finding.groupBy({ by: ['status'], _count: { id: true } }),
    ]);

    return {
      total,
      bySeverity: Object.fromEntries(bySeverityRaw.map((r) => [r.severity, r._count.id])),
      byTool: Object.fromEntries(byToolRaw.map((r) => [r.tool, r._count.id])),
      byStatus: Object.fromEntries(byStatusRaw.map((r) => [r.status, r._count.id])),
    };
  });

  app.get('/api/assets', async () => {
    const assets = await prisma.finding.findMany({
      distinct: ['asset'],
      select: { asset: true },
      orderBy: { asset: 'asc' },
    });
    return assets.map((a) => a.asset);
  });
};

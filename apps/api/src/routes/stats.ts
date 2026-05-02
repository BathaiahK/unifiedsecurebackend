import type { FastifyPluginAsync } from 'fastify';
import { prisma } from '../db.js';

function computeScore(critical: number, high: number, medium: number): number {
  return Math.max(0, Math.min(100, Math.round(100 - critical * 8 - high * 2 - medium * 0.3)));
}

export const statsRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/stats', async (_req, reply) => {
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const [total, bySeverityRaw, byToolRaw, byStatusRaw, newCritical, fixedHigh] =
      await Promise.all([
        prisma.finding.count(),
        prisma.finding.groupBy({ by: ['severity'], _count: { id: true } }),
        prisma.finding.groupBy({ by: ['tool'], _count: { id: true } }),
        prisma.finding.groupBy({ by: ['status'], _count: { id: true } }),
        prisma.finding.count({
          where: { severity: 'critical', status: 'open', firstSeen: { gte: sevenDaysAgo } },
        }),
        prisma.finding.count({
          where: { severity: 'high', status: 'fixed', lastSeen: { gte: sevenDaysAgo } },
        }),
      ]);

    type GroupRow = { _count: { id: number } };
    const bySeverity = Object.fromEntries(
      bySeverityRaw.map((r: GroupRow & { severity: string }) => [r.severity, r._count.id]),
    );
    const byStatus = Object.fromEntries(
      byStatusRaw.map((r: GroupRow & { status: string }) => [r.status, r._count.id]),
    );

    const criticalOpen = (bySeverity['critical'] as number) ?? 0;
    const highOpen     = (bySeverity['high']     as number) ?? 0;
    const mediumOpen   = (bySeverity['medium']   as number) ?? 0;

    return reply.send({
      total,
      bySeverity,
      byTool:   Object.fromEntries(
        byToolRaw.map((r: GroupRow & { tool: string }) => [r.tool, r._count.id]),
      ),
      byStatus,
      securityScore: computeScore(criticalOpen, highOpen, mediumOpen),
      criticalDelta: newCritical,
      highDelta:     -fixedHigh,
      mediumDelta:   mediumOpen > 10 ? 'needs attention' : 'stable',
    });
  });

  app.get('/api/trend', async (_req, reply) => {
    const now = new Date();
    const trend = [];

    for (let i = 5; i >= 0; i--) {
      const monthEnd = new Date(now.getFullYear(), now.getMonth() - i + 1, 0, 23, 59, 59);

      const [crit, high, med] = await Promise.all([
        prisma.finding.count({ where: { severity: 'critical', firstSeen: { lte: monthEnd } } }),
        prisma.finding.count({ where: { severity: 'high',     firstSeen: { lte: monthEnd } } }),
        prisma.finding.count({ where: { severity: 'medium',   firstSeen: { lte: monthEnd } } }),
      ]);

      trend.push({
        label:    new Date(now.getFullYear(), now.getMonth() - i, 1)
                    .toLocaleString('en-US', { month: 'short' }),
        critical: crit,
        high,
        medium:   med,
        score:    computeScore(crit, high, med),
      });
    }

    return reply.send(trend);
  });
};

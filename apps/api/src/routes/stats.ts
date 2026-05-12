import type { FastifyPluginAsync } from 'fastify';
import { prisma, mongoClient } from '../db.js';

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
    const db = mongoClient.db('uspservice');

    // Single aggregation to fetch all findings grouped by month/severity
    const pipeline = [
      {
        $match: {
          firstSeen: {
            $gte: new Date(now.getFullYear(), now.getMonth() - 5, 1),
          },
        },
      },
      {
        $group: {
          _id: {
            month: { $dateToString: { format: '%Y-%m', date: '$firstSeen' } },
            severity: '$severity',
          },
          count: { $sum: 1 },
        },
      },
      {
        $sort: { _id: 1 },
      },
    ];

    const raw = await db.collection('Finding').aggregate(pipeline).toArray();

    // Reorganize into cumulative counts per month
    const countsByMonth = new Map<
      string,
      { critical: number; high: number; medium: number }
    >();

    for (const doc of raw) {
      const month = doc._id.month as string;
      const severity = doc._id.severity as string;
      const count = doc.count as number;

      if (!countsByMonth.has(month)) {
        countsByMonth.set(month, { critical: 0, high: 0, medium: 0 });
      }
      const monthData = countsByMonth.get(month)!;
      if (severity === 'critical') monthData.critical = count;
      else if (severity === 'high') monthData.high = count;
      else if (severity === 'medium') monthData.medium = count;
    }

    // Build result with cumulative counts
    const trend = [];
    let cumulativeCritical = 0;
    let cumulativeHigh = 0;
    let cumulativeMedium = 0;

    for (let i = 5; i >= 0; i--) {
      const month = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const monthStr = month.toISOString().slice(0, 7);

      const monthData = countsByMonth.get(monthStr) || {
        critical: 0,
        high: 0,
        medium: 0,
      };

      cumulativeCritical += monthData.critical;
      cumulativeHigh += monthData.high;
      cumulativeMedium += monthData.medium;

      trend.push({
        label: month.toLocaleString('en-US', { month: 'short' }),
        critical: cumulativeCritical,
        high: cumulativeHigh,
        medium: cumulativeMedium,
        score: computeScore(cumulativeCritical, cumulativeHigh, cumulativeMedium),
      });
    }

    return reply.send(trend);
  });
};

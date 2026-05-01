import type { FastifyPluginAsync } from 'fastify';
import { FindingsQuerySchema } from '@usp/schema';
import { prisma } from '../db.js';

export const findingsRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/findings', async (req, reply) => {
    const query = FindingsQuerySchema.safeParse(req.query);
    if (!query.success) {
      return reply.status(400).send({ error: 'Invalid query', details: query.error.flatten() });
    }

    const { tool, severity, status, asset, cve, page, pageSize } = query.data;

    const where = {
      ...(tool && { tool }),
      ...(severity && { severity }),
      ...(status && { status }),
      ...(asset && { asset: { contains: asset, mode: 'insensitive' as const } }),
      ...(cve && { cve }),
    };

    const [findings, total] = await Promise.all([
      prisma.finding.findMany({
        where,
        skip: (page - 1) * pageSize,
        take: pageSize,
        orderBy: [{ severity: 'asc' }, { lastSeen: 'desc' }],
      }),
      prisma.finding.count({ where }),
    ]);

    return { findings, total, page, pageSize, totalPages: Math.ceil(total / pageSize) };
  });

  app.get<{ Params: { id: string } }>('/api/findings/:id', async (req, reply) => {
    const finding = await prisma.finding.findUnique({ where: { id: req.params.id } });
    if (!finding) return reply.status(404).send({ error: 'Finding not found' });
    return finding;
  });
};

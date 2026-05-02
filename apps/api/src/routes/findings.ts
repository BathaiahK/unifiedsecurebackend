import type { FastifyPluginAsync } from 'fastify';
import { FindingsQuerySchema, UpdateFindingStatusSchema } from '@usp/schema';
import { prisma } from '../db.js';

export const findingsRoutes: FastifyPluginAsync = async (app) => {
  // Must be registered before /:id to avoid param conflict
  app.get('/api/findings/recent-critical', async (_req, reply) => {
    const findings = await prisma.finding.findMany({
      where: { severity: { in: ['critical', 'high'] }, status: { in: ['open', 'in_progress'] } },
      orderBy: [{ severity: 'asc' }, { cvss: 'desc' }, { lastSeen: 'desc' }],
      take: 5,
    });
    return reply.send(findings);
  });

  app.get('/api/findings', async (req, reply) => {
    const query = FindingsQuerySchema.safeParse(req.query);
    if (!query.success) {
      return reply.status(400).send({ error: 'Invalid query', details: query.error.flatten() });
    }

    const { tool, severity, status, asset, cve, search, page, pageSize } = query.data;

    const where: Record<string, unknown> = {
      ...(tool && { tool }),
      ...(severity && { severity }),
      ...(status && { status }),
      ...(asset && { asset: { contains: asset, mode: 'insensitive' } }),
      ...(cve && { cve: { contains: cve, mode: 'insensitive' } }),
      ...(search && {
        OR: [
          { title: { contains: search, mode: 'insensitive' } },
          { cve: { contains: search, mode: 'insensitive' } },
          { asset: { contains: search, mode: 'insensitive' } },
        ],
      }),
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

    return reply.send({ findings, total, page, pageSize, totalPages: Math.ceil(total / pageSize) });
  });

  app.get<{ Params: { id: string } }>('/api/findings/:id', async (req, reply) => {
    const finding = await prisma.finding.findUnique({ where: { id: req.params.id } });
    if (!finding) return reply.status(404).send({ error: 'Finding not found' });

    const relatedFindings = finding.cve
      ? await prisma.finding.findMany({
          where: { cve: finding.cve, id: { not: finding.id } },
          select: { id: true, asset: true, severity: true, status: true, tool: true },
        })
      : [];

    const otherAffectedAssets = [...new Set(relatedFindings.map((f: { asset: string }) => f.asset))];

    return reply.send({
      finding,
      blastRadius: { affectedAsset: finding.asset, otherAffectedAssets, relatedFindings },
    });
  });

  app.patch<{ Params: { id: string } }>('/api/findings/:id/status', async (req, reply) => {
    const body = UpdateFindingStatusSchema.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'Invalid body', details: body.error.flatten() });
    }
    const finding = await prisma.finding.update({
      where: { id: req.params.id },
      data: { status: body.data.status, lastSeen: new Date() },
    });
    return reply.send(finding);
  });
};

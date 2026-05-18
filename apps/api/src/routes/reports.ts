import type { FastifyPluginAsync } from 'fastify';
import { randomUUID } from 'node:crypto';
import { GenerateReportSchema } from '@usp/schema';
import { prisma } from '../db.js';

const TEMPLATES = [
  {
    id: 'executive',
    title: 'Executive Summary',
    description:
      'High-level security posture overview with risk trends, top findings, and remediation progress. Designed for management and stakeholders.',
    audience: 'Management',
    formats: ['PDF'],
  },
  {
    id: 'full',
    title: 'Full Vulnerability Report',
    description:
      'Complete list of all findings with CVSS scores, affected assets, remediation steps, and evidence. Used for security audits and engineering review.',
    audience: 'Engineering / Audit',
    formats: ['PDF', 'CSV'],
  },
  {
    id: 'owasp',
    title: 'OWASP Compliance Report',
    description:
      'Maps findings to OWASP Top 10 and OWASP API Security Top 10 categories. Shows coverage and gaps per category.',
    audience: 'Compliance',
    formats: ['PDF', 'CSV'],
  },
];

export const reportsRoutes: FastifyPluginAsync = async (app) => {
  // GET /api/reports — templates + recent download history
  app.get('/api/reports', async (_req, reply) => {
    const recentDownloads = await prisma.reportDownload.findMany({
      orderBy: { createdAt: 'desc' },
      take: 10,
    });
    return reply.send({ templates: TEMPLATES, recentDownloads });
  });

  // POST /api/reports/generate — record a download and return a stub
  app.post('/api/reports/generate', async (req, reply) => {
    const body = GenerateReportSchema.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'Invalid body', details: body.error.flatten() });
    }

    const { templateId, format } = body.data;
    const template = TEMPLATES.find((t) => t.id === templateId);
    if (!template) return reply.status(404).send({ error: 'Template not found' });

    const month = new Date().toLocaleString('en-US', { month: 'short', year: 'numeric' });
    const name = `${template.title} — ${month}`;
    const size =
      format === 'PDF'
        ? `${Math.floor(Math.random() * 100 + 80)} KB`
        : `${Math.floor(Math.random() * 50 + 30)} KB`;

    const record = await prisma.reportDownload.create({
      data: { id: randomUUID(), name, format, size },
    });

    return reply.status(201).send(record);
  });
};

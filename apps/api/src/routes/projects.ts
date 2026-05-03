import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { FastifyPluginAsync } from 'fastify';
import { prisma } from '../db.js';

const CreateProjectSchema = z.object({
  name:          z.string().min(1),
  repoUrl:       z.string().url(),
  defaultBranch: z.string().min(1).default('main'),
  description:   z.string().optional(),
});

export const projectsRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/projects', async (_req, reply) => {
    const projects = await prisma.project.findMany({ orderBy: { createdAt: 'asc' } });
    return reply.send(projects);
  });

  app.post('/api/projects', async (req, reply) => {
    const body = CreateProjectSchema.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'Invalid project data', details: body.error.flatten() });
    }
    try {
      const project = await prisma.project.create({
        data: { id: randomUUID(), ...body.data },
      });
      return reply.status(201).send(project);
    } catch (err: unknown) {
      const e = err as { code?: string };
      if (e.code === 'P2002') {
        return reply.status(409).send({ error: `A project named "${body.data.name}" already exists` });
      }
      throw err;
    }
  });

  app.delete<{ Params: { id: string } }>('/api/projects/:id', async (req, reply) => {
    try {
      await prisma.project.delete({ where: { id: req.params.id } });
      return reply.status(204).send();
    } catch {
      return reply.status(404).send({ error: 'Project not found' });
    }
  });
};

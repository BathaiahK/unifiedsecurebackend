import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { FastifyPluginAsync } from 'fastify';
import { prisma, mongoClient } from '../db.js';

const CreateProjectSchema = z.object({
  name:          z.string().min(1),
  repoUrl:       z.string().url(),
  defaultBranch: z.string().min(1).default('main'),
  description:   z.string().optional(),
  gitToken:      z.string().optional(),
});

const UpdateProjectSchema = z.object({
  name:          z.string().min(1).optional(),
  repoUrl:       z.string().url().optional(),
  defaultBranch: z.string().min(1).optional(),
  description:   z.string().optional(),
  gitToken:      z.string().nullable().optional(),
});

export const projectsRoutes: FastifyPluginAsync = async (app) => {
  app.get('/api/projects', async (_req, reply) => {
    const db = mongoClient.db();
    const projects = await db.collection('Project').find({}).sort({ createdAt: 1 }).toArray();
    return reply.send(projects.map((p: any) => {
      const { _id, ...rest } = p;
      return maskToken({ id: _id, ...rest });
    }));
  });

  app.post('/api/projects', async (req, reply) => {
    const body = CreateProjectSchema.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'Invalid project data', details: body.error.flatten() });
    }
    try {
      const projectId = randomUUID();
      const createdAt = new Date();
      const projectData = {
        _id: projectId,
        name: body.data.name,
        repoUrl: body.data.repoUrl,
        defaultBranch: body.data.defaultBranch || 'main',
        description: body.data.description || null,
        gitToken: body.data.gitToken || null,
        createdAt,
      };

      const db = mongoClient.db();
      await db.collection('Project').insertOne(projectData as any);

      const project = {
        id: projectId,
        ...body.data,
        createdAt,
      };
      return reply.status(201).send(maskToken(project));
    } catch (err: unknown) {
      const e = err as any;
      if (e?.code === 11000 || e?.message?.includes('duplicate')) {
        return reply.status(409).send({ error: `A project named "${body.data.name}" already exists` });
      }
      throw err;
    }
  });

  app.patch<{ Params: { id: string } }>('/api/projects/:id', async (req, reply) => {
    const body = UpdateProjectSchema.safeParse(req.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'Invalid project data', details: body.error.flatten() });
    }
    try {
      const db = mongoClient.db();
      const result = await db.collection('Project').updateOne(
        { _id: req.params.id },
        { $set: body.data },
      );
      if (result.matchedCount === 0) {
        return reply.status(404).send({ error: 'Project not found' });
      }
      const project = await db.collection('Project').findOne({ _id: req.params.id });
      const { _id, ...rest } = project || {};
      return reply.send(maskToken({ id: _id, ...rest }));
    } catch {
      return reply.status(404).send({ error: 'Project not found' });
    }
  });

  app.delete<{ Params: { id: string } }>('/api/projects/:id', async (req, reply) => {
    try {
      const db = mongoClient.db();
      const result = await db.collection('Project').deleteOne({ _id: req.params.id });
      if (result.deletedCount === 0) {
        return reply.status(404).send({ error: 'Project not found' });
      }
      return reply.status(204).send();
    } catch {
      return reply.status(404).send({ error: 'Project not found' });
    }
  });
};

// Never expose the raw token — return a masked indicator instead
function maskToken<T extends { gitToken?: string | null }>(project: T): T & { gitToken: string | null } {
  const { gitToken, ...rest } = project;
  return {
    ...(rest as T),
    gitToken: gitToken ? `••••${gitToken.slice(-4)}` : null,
  };
}

import type { FastifyPluginAsync } from 'fastify';

export const sbomRoutes: FastifyPluginAsync = async (app) => {
  // SBOM route disabled - requires @usp/adapter-sca package
  app.get('/api/scans/:id/sbom', async (req, reply) => {
    return reply.status(501).send({ error: 'SBOM generation not available' });
  });
};

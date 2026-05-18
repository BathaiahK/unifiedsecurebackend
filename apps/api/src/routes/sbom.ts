import type { FastifyPluginAsync } from 'fastify';
import { generateCycloneDxSbom, generateSpdxSbom } from '@usp/adapter-sca';
import { mongoClient } from '../db.js';

export const sbomRoutes: FastifyPluginAsync = async (app) => {
  app.get<{
    Params: { id: string };
    Querystring: { format?: string };
  }>('/api/scans/:id/sbom', async (req, reply) => {
    const { id } = req.params;
    const format = (req.query.format ?? 'cyclonedx').toLowerCase();

    if (format !== 'cyclonedx' && format !== 'spdx') {
      return reply.status(400).send({ error: 'format must be "cyclonedx" or "spdx"' });
    }

    const db = mongoClient.db();
    const scan = await db.collection('Scan').findOne({ _id: id });
    if (!scan) {
      return reply.status(404).send({ error: 'Scan not found' });
    }

    if (scan.status !== 'complete') {
      return reply.status(409).send({ error: 'Scan is not complete yet' });
    }

    // Recover the purl list from scan meta — stored there from runScanPipeline
    let purls: string[] = (scan.meta?.purls as string[] | undefined) ?? [];

    // If purls not in meta (older scans), reconstruct from findings
    if (purls.length === 0) {
      const findings = await db.collection('Finding').find({ scanId: id }).toArray();
      purls = findings
        .map((f) => (f.evidence as Record<string, unknown>)?.purl as string | undefined)
        .filter((p): p is string => !!p);
    }

    const asset = scan.asset as string;
    const tool = scan.tool as string;

    // For container scans, try to use the Trivy CycloneDX SBOM first
    if (tool === 'container' && format === 'cyclonedx') {
      const containerSbom = (scan.meta as Record<string, unknown> | undefined)?.containerSbom as
        | Record<string, unknown>
        | undefined;
      if (containerSbom) {
        const filename = `sbom-${id.slice(0, 8)}-cdx.json`;
        reply
          .header('Content-Type', 'application/json')
          .header('Content-Disposition', `attachment; filename="${filename}"`)
          .send(containerSbom);
        return;
      }
    }

    // Fallback: reconstruct from findings using SCA generators
    const sbom =
      format === 'cyclonedx'
        ? generateCycloneDxSbom(id, asset, purls)
        : generateSpdxSbom(id, asset, purls);

    const filename = `sbom-${id.slice(0, 8)}-${format === 'cyclonedx' ? 'cdx' : 'spdx'}.json`;
    reply
      .header('Content-Type', 'application/json')
      .header('Content-Disposition', `attachment; filename="${filename}"`)
      .send(sbom);
  });
};

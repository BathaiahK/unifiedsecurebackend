import { z } from 'zod';
import { SeveritySchema, ToolSchema, FindingStatusSchema } from './finding.js';

export const FindingsQuerySchema = z.object({
  tool: ToolSchema.optional(),
  severity: SeveritySchema.optional(),
  status: FindingStatusSchema.optional(),
  asset: z.string().optional(),
  cve: z.string().optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
});
export type FindingsQuery = z.infer<typeof FindingsQuerySchema>;

export const StatsResponseSchema = z.object({
  total: z.number().int(),
  bySeverity: z.record(SeveritySchema, z.number().int()),
  byTool: z.record(ToolSchema, z.number().int()),
  byStatus: z.record(FindingStatusSchema, z.number().int()),
});
export type StatsResponse = z.infer<typeof StatsResponseSchema>;

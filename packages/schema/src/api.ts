import { z } from 'zod';
import { SeveritySchema, ToolSchema, FindingStatusSchema } from './finding.js';

export const FindingsQuerySchema = z.object({
  tool: ToolSchema.optional(),
  severity: SeveritySchema.optional(),
  status: FindingStatusSchema.optional(),
  asset: z.string().optional(),
  cve: z.string().optional(),
  search: z.string().optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
});
export type FindingsQuery = z.infer<typeof FindingsQuerySchema>;

export const UpdateFindingStatusSchema = z.object({
  status: FindingStatusSchema,
});

export const TriggerScanSchema = z.object({
  tool: ToolSchema,
  asset: z.string().min(1),
  branch: z.string().optional(),
  environment: z.string().optional(),
  options: z.record(z.unknown()).optional(),
});
export type TriggerScan = z.infer<typeof TriggerScanSchema>;

export const GenerateReportSchema = z.object({
  templateId: z.enum(['executive', 'full', 'owasp']),
  format: z.enum(['PDF', 'CSV']),
  asset: z.string().optional(),
});

export const StatsResponseSchema = z.object({
  total: z.number().int(),
  bySeverity: z.record(z.number().int()),
  byTool: z.record(z.number().int()),
  byStatus: z.record(z.number().int()),
  securityScore: z.number().int(),
  criticalDelta: z.number().int(),
  highDelta: z.number().int(),
  mediumDelta: z.string(),
});
export type StatsResponse = z.infer<typeof StatsResponseSchema>;

export const TrendPointSchema = z.object({
  label: z.string(),
  critical: z.number().int(),
  high: z.number().int(),
  medium: z.number().int(),
  score: z.number().int(),
});
export type TrendPoint = z.infer<typeof TrendPointSchema>;

export const ScannerStatusSchema = z.object({
  tool: ToolSchema,
  label: z.string(),
  category: z.string(),
  status: z.enum(['active', 'scanning', 'offline', 'error']),
  stats: z.array(
    z.object({
      label: z.string(),
      value: z.string(),
      highlight: z.enum(['red', 'orange', 'green']).optional(),
    }),
  ),
  score: z.string().optional(),
});
export type ScannerStatus = z.infer<typeof ScannerStatusSchema>;

export const ProjectSchema = z.object({
  name: z.string(),
  health: z.enum(['healthy', 'warning', 'critical', 'inactive']),
  criticalCount: z.number().int(),
  highCount: z.number().int(),
});
export type Project = z.infer<typeof ProjectSchema>;

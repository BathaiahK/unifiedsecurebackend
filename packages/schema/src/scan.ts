import { z } from 'zod';
import { ToolSchema } from './finding.js';

export const ScanStatusSchema = z.enum(['queued', 'running', 'complete', 'failed']);
export type ScanStatus = z.infer<typeof ScanStatusSchema>;

export const ScanConfigSchema = z.object({
  tool: ToolSchema,
  asset: z.string().min(1),
  options: z.record(z.unknown()).optional(),
});
export type ScanConfig = z.infer<typeof ScanConfigSchema>;

export const ScanSchema = z.object({
  id: z.string().uuid(),
  tool: ToolSchema,
  asset: z.string().min(1),
  status: ScanStatusSchema,
  startedAt: z.string().datetime(),
  completedAt: z.string().datetime().nullable(),
  findingCount: z.number().int().min(0).optional(),
});
export type Scan = z.infer<typeof ScanSchema>;

export const ScanDiffEntrySchema = z.object({
  findingId: z.string().uuid(),
  state: z.enum(['new', 'recurring', 'resolved']),
});
export type ScanDiffEntry = z.infer<typeof ScanDiffEntrySchema>;

export const ScanDiffSchema = z.object({
  currentScanId: z.string().uuid(),
  previousScanId: z.string().uuid(),
  asset: z.string(),
  entries: z.array(ScanDiffEntrySchema),
  newCount: z.number().int(),
  recurringCount: z.number().int(),
  resolvedCount: z.number().int(),
});
export type ScanDiff = z.infer<typeof ScanDiffSchema>;

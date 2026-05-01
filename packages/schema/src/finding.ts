import { z } from 'zod';

export const ToolSchema = z.enum(['blackduck', 'sysdig', '42crunch', 'sonatype']);
export type Tool = z.infer<typeof ToolSchema>;

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof SeveritySchema>;

export const FindingStatusSchema = z.enum(['open', 'suppressed', 'fixed', 'in_progress']);
export type FindingStatus = z.infer<typeof FindingStatusSchema>;

export const UnifiedFindingSchema = z.object({
  id: z.string().uuid(),
  tool: ToolSchema,
  severity: SeveritySchema,
  cvss: z.number().min(0).max(10).nullable(),
  cve: z.string().nullable(),
  cwe: z.string().nullable(),
  asset: z.string().min(1),
  status: FindingStatusSchema.default('open'),
  fixVersion: z.string().nullable(),
  firstSeen: z.string().datetime(),
  lastSeen: z.string().datetime(),
  remediationSteps: z.array(z.string()),
  evidence: z.record(z.unknown()),
  scanId: z.string().uuid(),
});

export type UnifiedFinding = z.infer<typeof UnifiedFindingSchema>;

export const MergedFindingSchema = UnifiedFindingSchema.extend({
  tools: z.array(ToolSchema),
  occurrenceCount: z.number().int().min(1),
}).omit({ tool: true });

export type MergedFinding = z.infer<typeof MergedFindingSchema>;

import { z } from 'zod';

export const ToolSchema = z.enum(['blackduck', 'sysdig', '42crunch', 'governance', 'dast', 'sca', 'git-history', 'sast', 'api-security', 'container', 'supply-chain', 'malware']);
export type Tool = z.infer<typeof ToolSchema>;

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof SeveritySchema>;

export const FindingStatusSchema = z.enum(['open', 'suppressed', 'fixed', 'in_progress']);
export type FindingStatus = z.infer<typeof FindingStatusSchema>;

export const FindingReferenceSchema = z.object({
  label: z.string(),
  url: z.string(),
});
export type FindingReference = z.infer<typeof FindingReferenceSchema>;

export const UnifiedFindingSchema = z.object({
  id: z.string().uuid(),
  tool: ToolSchema,
  severity: SeveritySchema,
  cvss: z.number().min(0).max(10).nullable(),
  cve: z.string().nullable(),
  cwe: z.string().nullable(),
  title: z.string().min(1),
  asset: z.string().min(1),
  status: FindingStatusSchema.default('open'),
  fixVersion: z.string().nullable(),
  firstSeen: z.string().datetime(),
  lastSeen: z.string().datetime(),
  remediationSteps: z.array(z.string()),
  references: z.array(FindingReferenceSchema).default([]),
  evidence: z.record(z.unknown()),
  scanId: z.string().uuid(),
});

export type UnifiedFinding = z.infer<typeof UnifiedFindingSchema>;

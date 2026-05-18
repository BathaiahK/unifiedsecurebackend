import { z } from 'zod';

const RemediationConfigSchema = z.object({
  nvdApiKey: z.string().optional(),
  nvdApiUrl: z.string().url().default('https://services.nvd.nist.gov/rest/json/cves/2.0'),
  osvApiUrl: z.string().url().default('https://api.osv.dev/v1'),
  concurrency: z.coerce.number().int().min(1).max(20).default(5),
});

export type RemediationConfig = z.infer<typeof RemediationConfigSchema>;

let _remediationConfig: RemediationConfig | null = null;

export function getRemediationConfig(): RemediationConfig {
  if (_remediationConfig) return _remediationConfig;

  const result = RemediationConfigSchema.safeParse({
    nvdApiKey: process.env['NVD_API_KEY'],
    nvdApiUrl: process.env['NVD_API_URL'],
    osvApiUrl: process.env['OSV_API_URL'],
    concurrency: process.env['REMEDIATION_CONCURRENCY'],
  });

  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  • ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`[config/remediation] Invalid environment:\n${issues}`);
  }

  _remediationConfig = result.data;
  return _remediationConfig;
}

import { z } from 'zod';

const WebConfigSchema = z.object({
  apiUrl: z.string().url().default('http://localhost:4000'),
  nodeEnv: z.enum(['development', 'production', 'test']).default('development'),
});

export type WebConfig = z.infer<typeof WebConfigSchema>;

let _webConfig: WebConfig | null = null;

export function getWebConfig(): WebConfig {
  if (_webConfig) return _webConfig;

  const result = WebConfigSchema.safeParse({
    apiUrl: process.env['NEXT_PUBLIC_API_URL'],
    nodeEnv: process.env['NODE_ENV'],
  });

  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  • ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`[config/web] Invalid environment:\n${issues}`);
  }

  _webConfig = result.data;
  return _webConfig;
}

import { z } from 'zod';

const ApiConfigSchema = z.object({
  databaseUrl: z.string().min(1).optional(),
  port: z.coerce.number().int().min(1).max(65535).default(4000),
  host: z.string().default('0.0.0.0'),
  logLevel: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  corsOrigin: z.string().default('http://localhost:3000'),
  nodeEnv: z.enum(['development', 'production', 'test']).default('development'),
});

export type ApiConfig = z.infer<typeof ApiConfigSchema>;

let _apiConfig: ApiConfig | null = null;

export function getApiConfig(): ApiConfig {
  if (_apiConfig) return _apiConfig;

  const result = ApiConfigSchema.safeParse({
    databaseUrl: process.env['DATABASE_URL'],
    port: process.env['PORT'],
    host: process.env['HOST'],
    logLevel: process.env['LOG_LEVEL'],
    corsOrigin: process.env['CORS_ORIGIN'],
    nodeEnv: process.env['NODE_ENV'],
  });

  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  • ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`[config/api] Invalid environment:\n${issues}`);
  }

  _apiConfig = result.data;
  return _apiConfig;
}

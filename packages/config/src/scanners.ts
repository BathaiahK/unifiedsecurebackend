import { z } from 'zod';

// ── Per-scanner schemas ───────────────────────────────────────────────────────

const BlackDuckSchema = z.object({
  url: z.string().url('BLACKDUCK_URL must be a valid URL'),
  apiToken: z.string().min(1, 'BLACKDUCK_API_TOKEN is required'),
});

const SysdigSchema = z.object({
  url: z.string().url('SYSDIG_URL must be a valid URL'),
  apiToken: z.string().min(1, 'SYSDIG_API_TOKEN is required'),
});

const Crunch42Schema = z.object({
  apiKey: z.string().min(1, 'CRUNCH42_API_KEY is required'),
  url: z.string().url().default('https://platform.42crunch.com'),
});

const SonatypeSchema = z.object({
  url: z.string().url().optional(), // Nexus IQ only — not needed for OSS Index
  username: z.string().min(1, 'SONATYPE_USERNAME is required'),
  password: z.string().min(1, 'SONATYPE_PASSWORD is required'),
});

const ContainerSchema = z
  .object({
    trivyPath: z.string().default('trivy'),
    registryUsername: z.string().optional(),
    registryPassword: z.string().optional(),
    registryToken: z.string().optional(),
  })
  .optional();

// ── Derived types ─────────────────────────────────────────────────────────────

export type BlackDuckScannerConfig = z.infer<typeof BlackDuckSchema>;
export type SysdigScannerConfig = z.infer<typeof SysdigSchema>;
export type Crunch42ScannerConfig = z.infer<typeof Crunch42Schema>;
export type SonatypeScannerConfig = z.infer<typeof SonatypeSchema>;
export type ContainerScannerConfig = z.infer<typeof ContainerSchema>;

export interface ScannerConfigs {
  blackduck: BlackDuckScannerConfig | null;
  sysdig: SysdigScannerConfig | null;
  crunch42: Crunch42ScannerConfig | null;
  sonatype: SonatypeScannerConfig | null;
  container: ContainerScannerConfig | null;
}

// ── Loader ────────────────────────────────────────────────────────────────────

// Use a constrained generic so TypeScript infers the OUTPUT type (post-default/transform)
function tryParse<S extends z.ZodTypeAny>(schema: S, data: unknown): z.infer<S> | null {
  const result = schema.safeParse(data);
  return result.success ? (result.data as z.infer<S>) : null;
}

let _scannerConfigs: ScannerConfigs | undefined;

export function getScannerConfigs(): ScannerConfigs {
  if (_scannerConfigs !== undefined) return _scannerConfigs;

  const configs: ScannerConfigs = {
    blackduck: tryParse(BlackDuckSchema, {
      url: process.env['BLACKDUCK_URL'],
      apiToken: process.env['BLACKDUCK_API_TOKEN'],
    }),

    sysdig: tryParse(SysdigSchema, {
      url: process.env['SYSDIG_URL'],
      apiToken: process.env['SYSDIG_API_TOKEN'],
    }),

    crunch42: tryParse(Crunch42Schema, {
      apiKey: process.env['CRUNCH42_API_KEY'],
      url: process.env['CRUNCH42_URL'],
    }),

    sonatype: tryParse(SonatypeSchema, {
      url: process.env['SONATYPE_URL'] || undefined, // empty string → undefined
      username: process.env['SONATYPE_USERNAME'],
      password: process.env['SONATYPE_PASSWORD'],
    }),

    container: tryParse(ContainerSchema, {
      trivyPath: process.env['TRIVY_PATH'],
      registryUsername: process.env['TRIVY_REGISTRY_USERNAME'],
      registryPassword: process.env['TRIVY_REGISTRY_PASSWORD'],
      registryToken: process.env['TRIVY_REGISTRY_TOKEN'],
    }),
  };

  _scannerConfigs = configs;
  return configs;
}

export function getConfiguredScanners(configs: ScannerConfigs): string[] {
  return Object.entries(configs)
    .filter(([, v]) => v !== null)
    .map(([k]) => k);
}

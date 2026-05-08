export type ApiSecuritySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface OpenApiSpec {
  openapi: string;
  info: {
    title: string;
    version: string;
    description?: string;
  };
  servers?: Array<{ url: string; description?: string }>;
  paths: Record<string, PathItem>;
  components?: {
    schemas?: Record<string, unknown>;
    securitySchemes?: Record<string, unknown>;
  };
}

export interface PathItem {
  get?: Operation;
  post?: Operation;
  put?: Operation;
  delete?: Operation;
  patch?: Operation;
  parameters?: Parameter[];
}

export interface Operation {
  operationId?: string;
  summary?: string;
  description?: string;
  security?: Array<Record<string, string[]>>;
  requestBody?: {
    content: Record<string, { schema: unknown }>;
    required?: boolean;
  };
  responses: Record<string, Response>;
}

export interface Response {
  description: string;
  content?: Record<string, { schema: unknown }>;
}

export interface Parameter {
  name: string;
  in: 'query' | 'path' | 'header' | 'cookie';
  required?: boolean;
  schema?: unknown;
}

export interface ApiSecurityFinding {
  id: string;
  category: ApiSecurityCategory;
  title: string;
  description: string;
  severity: ApiSecuritySeverity;
  cwe: string | null;
  endpoint?: string;
  method?: string;
  evidence: string;
  remediation: string[];
}

export type ApiSecurityCategory =
  | 'sensitive-data-exposure'
  | 'missing-authentication'
  | 'weak-validation'
  | 'poor-error-handling'
  | 'cors-misconfiguration'
  | 'api-versioning'
  | 'missing-rate-limiting'
  | 'overly-permissive'
  | 'schema-design-flaw'
  | 'contract-violation';

export interface ApiSecurityReport {
  scanId: string;
  specUrl: string;
  serviceUrl: string;
  specTitle: string;
  specVersion: string;
  totalEndpoints: number;
  findings: ApiSecurityFinding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  scanDurationMs: number;
}

export interface ApiSecuritySummary {
  specTitle: string;
  specVersion: string;
  totalEndpoints: number;
  totalFindings: number;
  bySeverity: { critical: number; high: number; medium: number; low: number };
  topIssues: Array<{ category: ApiSecurityCategory; count: number }>;
  scanDurationMs: number;
}

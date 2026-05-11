export { ContainerAdapter } from './adapter.js';
export { TrivyClient } from './client.js';
export { ContainerSimulator } from './simulator.js';
export { fetchEpssScores, fetchKevCatalog } from './epss-client.js';
export { buildImageContext, evaluateRules } from './runtime-rules.js';
export { generateHardeningRecommendations } from './hardening-profiles.js';
export { normalizeContainerFindings } from './normalize.js';
export type {
  ContainerAdapterConfig,
  ContainerScanReport,
  ContainerPendingScan,
  LayerDetail,
  CisCheck,
  BaseImageInfo,
  HardeningRecommendation,
  EpssEntry,
  RuntimeThreat,
  TrivyMetadata,
} from './types.js';

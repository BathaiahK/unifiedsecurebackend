export { ScaAdapter, type ScaAdapterConfig } from './adapter.js';
export { normalizeMatch } from './normalize.js';
export { scaStreamingQueue } from './streaming-queue.js';
export {
  analyzeLicenseRisk,
  aggregateLicenseRisks,
  generateLicenseReport,
} from './license-analyzer.js';
export {
  resolveTransitiveDependencies,
  buildDependencyTree,
  countTransitiveVulnerabilities,
  getTransitiveChain,
} from './transitive-resolver.js';
export {
  runSupplyChainAnalysis,
  detectUnmaintained,
  detectTyposquatting,
  detectDuplicateVersions,
  extractName,
  extractVersion,
} from './supply-chain-detector.js';
export { generateCycloneDxSbom, generateSpdxSbom } from './sbom-generator.js';
export type {
  ScanProgressEvent,
  LicenseRisk,
  TransitiveDependency,
  EnhancedFinding,
  ManifestFile,
  ParsedDependency,
  SupplyChainThreat,
  SupplyChainReport,
  SBOMComponent,
  SBOMDocument,
} from './types.js';

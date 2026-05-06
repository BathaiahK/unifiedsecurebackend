export { GitHistoryAdapter } from './adapter.js';
export type { GitHistoryReport } from './adapter.js';
export { normalizeRawSecret } from './normalize.js';
export { generateSimulatedFindings } from './simulator.js';
export { scanRepository, cleanupOrphanedTempDirs } from './scanner.js';
export { SECRET_PATTERNS, SKIP_PATHS, KNOWN_FALSE_POSITIVES, shouldSkipPath, calculateEntropy } from './patterns.js';
export type { SecretCategory } from './patterns.js';
export type { RawSecret, ScanOptions } from './scanner.js';

export type { VulnAdvisory, VulnMatch, SyncState, OsvEcosystem } from './types.js';
export { OSV_ECOSYSTEMS, PURL_ECOSYSTEM_MAP } from './types.js';
export { cvssBaseScore } from './cvss.js';
export { parseOsvEntry } from './osv-parser.js';
export { VulnStore, getVulnStore, closeVulnStore } from './store.js';
export { syncEcosystem, syncAllEcosystems } from './osv-sync.js';
export { isVersionAffected } from './semver-match.js';
export { lookupPurls } from './query.js';

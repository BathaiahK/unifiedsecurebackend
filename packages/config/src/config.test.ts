import { describe, it, expect, beforeEach } from 'vitest';
import { getScannerConfigs, getConfiguredScanners } from './scanners.js';
import { getRemediationConfig } from './remediation.js';

// Reset module-level cache between tests by re-importing via dynamic import
// Instead we directly test the logic with controlled env vars.

describe('getScannerConfigs', () => {
  it('returns null for a scanner with missing vars', () => {
    // No BLACKDUCK_URL/TOKEN set in test env → should be null
    const configs = getScannerConfigs();
    // All scanners unconfigured in test env
    expect(configs.blackduck).toBeNull();
    expect(configs.sysdig).toBeNull();
    expect(configs.crunch42).toBeNull();
    expect(configs.sonatype).toBeNull();
  });

  it('getConfiguredScanners returns empty array when none configured', () => {
    const configs = getScannerConfigs();
    expect(getConfiguredScanners(configs)).toEqual([]);
  });

  it('getConfiguredScanners lists only configured scanners', () => {
    const partial = {
      blackduck: { url: 'https://bd.example.com', apiToken: 'tok' },
      sysdig: null,
      crunch42: null,
      sonatype: null,
      container: null,
    };
    expect(getConfiguredScanners(partial)).toEqual(['blackduck']);
  });
});

describe('getRemediationConfig', () => {
  it('returns defaults when optional vars are absent', () => {
    const cfg = getRemediationConfig();
    expect(cfg.nvdApiUrl).toBe('https://services.nvd.nist.gov/rest/json/cves/2.0');
    expect(cfg.osvApiUrl).toBe('https://api.osv.dev/v1');
    expect(cfg.concurrency).toBe(5);
    expect(cfg.nvdApiKey).toBeUndefined();
  });
});

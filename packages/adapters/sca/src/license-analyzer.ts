import type { LicenseRisk } from './types.js';

// SPDX License Risk Classification
// Permissive: Can use in any project (MIT, Apache-2.0, BSD, ISC, etc)
// Copyleft: Must share derivative code (GPL, AGPL, LGPL)
// Proprietary: Restricted use
// Unknown: Requires review
const LICENSE_RISK_MAP: Record<string, LicenseRisk> = {
  // Permissive (Safe)
  'MIT': { license: 'MIT', riskLevel: 'safe', reason: 'Permissive - allows commercial use with attribution' },
  'Apache-2.0': { license: 'Apache-2.0', riskLevel: 'safe', reason: 'Permissive - allows commercial use with patent protection' },
  'Apache License 2.0': { license: 'Apache-2.0', riskLevel: 'safe', reason: 'Permissive - allows commercial use with patent protection' },
  'BSD': { license: 'BSD', riskLevel: 'safe', reason: 'Permissive - allows commercial use with attribution' },
  'BSD-2-Clause': { license: 'BSD-2-Clause', riskLevel: 'safe', reason: 'Permissive - allows commercial use' },
  'BSD-3-Clause': { license: 'BSD-3-Clause', riskLevel: 'safe', reason: 'Permissive - allows commercial use' },
  'ISC': { license: 'ISC', riskLevel: 'safe', reason: 'Permissive - allows commercial use' },
  'Unlicense': { license: 'Unlicense', riskLevel: 'safe', reason: 'Public domain - no restrictions' },
  '0BSD': { license: '0BSD', riskLevel: 'safe', reason: 'Permissive - allows commercial use' },
  'MPL-2.0': { license: 'MPL-2.0', riskLevel: 'safe', reason: 'Weak copyleft - derivative files must be open source' },
  'LGPL-2.1': { license: 'LGPL-2.1', riskLevel: 'warning', reason: 'Weak copyleft - can be used in proprietary apps with restrictions' },
  'LGPL-3.0': { license: 'LGPL-3.0', riskLevel: 'warning', reason: 'Weak copyleft - stronger restrictions than 2.1' },

  // Copyleft (Warning/Critical)
  'GPL': { license: 'GPL', riskLevel: 'critical', reason: 'Strong copyleft - entire project must be GPL' },
  'GPL-2.0': { license: 'GPL-2.0', riskLevel: 'critical', reason: 'Strong copyleft - entire project must be open source' },
  'GPL-3.0': { license: 'GPL-3.0', riskLevel: 'critical', reason: 'Strong copyleft - entire project must be open source' },
  'AGPL': { license: 'AGPL', riskLevel: 'critical', reason: 'Network copyleft - source must be shared if accessed over network' },
  'AGPL-3.0': { license: 'AGPL-3.0', riskLevel: 'critical', reason: 'Network copyleft - source sharing required for network use' },

  // Proprietary / Unknown
  'Proprietary': { license: 'Proprietary', riskLevel: 'critical', reason: 'Proprietary - commercial restrictions may apply' },
  'Commercial': { license: 'Commercial', riskLevel: 'critical', reason: 'Commercial - license required for use' },
  'Custom': { license: 'Custom', riskLevel: 'warning', reason: 'Custom license - requires legal review' },
};

export function analyzeLicenseRisk(license: string | null | undefined): LicenseRisk {
  if (!license) {
    return {
      license: 'Unknown',
      riskLevel: 'warning',
      reason: 'No license specified - review package before use',
    };
  }

  const normalized = license.trim().toUpperCase();

  // Direct lookup
  const entry = Object.entries(LICENSE_RISK_MAP).find(
    ([key]) => key.toUpperCase() === normalized || license.includes(key)
  );

  if (entry) {
    return entry[1];
  }

  // Pattern matching for common variations
  if (normalized.includes('GPL') || normalized.includes('AGPL')) {
    return {
      license: normalized,
      riskLevel: normalized.includes('AGPL') ? 'critical' : 'critical',
      reason: 'Copyleft license - requires legal review for proprietary use',
    };
  }

  if (normalized.includes('MIT') || normalized.includes('APACHE') || normalized.includes('BSD')) {
    return {
      license: normalized,
      riskLevel: 'safe',
      reason: 'Permissive license - safe for commercial use',
    };
  }

  // Default to warning for unknown
  return {
    license: license.substring(0, 50),
    riskLevel: 'warning',
    reason: 'Unknown license - requires review before use',
  };
}

export function aggregateLicenseRisks(licenses: string[]): {
  safe: number;
  warning: number;
  critical: number;
  licenses: LicenseRisk[];
} {
  const analyzed = licenses.map(analyzeLicenseRisk);
  const risks = {
    safe: 0,
    warning: 0,
    critical: 0,
    licenses: analyzed,
  };

  for (const risk of analyzed) {
    risks[risk.riskLevel]++;
  }

  return risks;
}

export function generateLicenseReport(riskSummary: { safe: number; warning: number; critical: number }): string {
  const total = riskSummary.safe + riskSummary.warning + riskSummary.critical;
  const lines: string[] = [];

  lines.push(`License Analysis: ${total} dependencies`);
  lines.push(`  Safe: ${riskSummary.safe}`);
  if (riskSummary.warning > 0) {
    lines.push(`  ⚠️ Warning: ${riskSummary.warning} (copyleft licenses requiring review)`);
  }
  if (riskSummary.critical > 0) {
    lines.push(`  🚩 Critical: ${riskSummary.critical} (strong copyleft, proprietary, or commercial)`);
  }

  if (riskSummary.warning > 0 || riskSummary.critical > 0) {
    lines.push(`\nRecommendation: Review license compatibility before deployment`);
  }

  return lines.join('\n');
}

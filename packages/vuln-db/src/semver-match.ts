import semver from 'semver';
import type { VulnAdvisory } from './types.js';

/** Returns true if the given version falls within any vulnerable range of the advisory. */
export function isVersionAffected(version: string, advisory: VulnAdvisory): boolean {
  const coerced = semver.coerce(version);
  if (!coerced) return false;
  const v = coerced.version;

  // Check semver ranges [introduced, fixed)
  for (const range of advisory.ranges) {
    const introduced =
      range.introduced === '0' || range.introduced === '' ? null : range.introduced;
    const fixed = range.fixed;

    const afterIntroduced = introduced
      ? semver.gte(v, semver.coerce(introduced)?.version ?? introduced)
      : true;

    const beforeFixed = fixed ? semver.lt(v, semver.coerce(fixed)?.version ?? fixed) : true;

    if (afterIntroduced && beforeFixed) return true;
  }

  // Fall back to exact version list
  if (advisory.affectedVersions.length > 0) {
    return advisory.affectedVersions.some((av) => {
      const coercedAv = semver.coerce(av);
      return coercedAv ? semver.eq(v, coercedAv.version) : av === version;
    });
  }

  return false;
}

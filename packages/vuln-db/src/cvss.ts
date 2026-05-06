/** CVSS v3.0/v3.1 base score calculator — no external dependencies */

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_US: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CS: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

function roundUp(x: number): number {
  const i = Math.ceil(x * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

/**
 * Parse a CVSS v3 vector string and return the base score (0.0–10.0),
 * or null if the vector is malformed or missing required metrics.
 *
 * Accepts both CVSS:3.0/... and CVSS:3.1/... prefixes.
 */
export function cvssBaseScore(vector: string): number | null {
  const parts = vector.replace(/^CVSS:3\.[01]\//, '').split('/');
  const m: Record<string, string> = {};
  for (const part of parts) {
    const [k, v] = part.split(':');
    if (k && v) m[k] = v;
  }

  const av = AV[m['AV'] ?? ''];
  const ac = AC[m['AC'] ?? ''];
  const scope = m['S'];
  const prMap = scope === 'C' ? PR_CS : PR_US;
  const pr = prMap[m['PR'] ?? ''];
  const ui = UI[m['UI'] ?? ''];
  const c = CIA[m['C'] ?? ''];
  const i = CIA[m['I'] ?? ''];
  const a = CIA[m['A'] ?? ''];

  if (av === undefined || ac === undefined || pr === undefined || ui === undefined ||
      c === undefined || i === undefined || a === undefined) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  let impact: number;
  if (scope === 'U') {
    impact = 3.591 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  if (impact <= 0) return 0;

  const exploitability = 8.22 * av * ac * pr * ui;

  let baseScore: number;
  if (scope === 'U') {
    baseScore = roundUp(Math.min(impact + exploitability, 10));
  } else {
    baseScore = roundUp(Math.min(1.08 * (impact + exploitability), 10));
  }

  return Math.round(baseScore * 10) / 10;
}

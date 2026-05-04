// Parse dependency lock files / manifests and emit PackageURL (purl) coordinates.
//
// Supported formats:
//   package-lock.json  npm v1 (dependencies) and v2/v3 (packages)
//   yarn.lock          yarn v1 classic and v2/berry
//   pnpm-lock.yaml     pnpm v6 and v9
//   package.json       npm (fallback — version ranges, used only when no lock file present)
//   pom.xml            Maven
//   build.gradle       Gradle (basic implementation block only)
//   requirements.txt   pip
//   Pipfile.lock       pipenv
//   go.sum             Go modules
//   Gemfile.lock       Bundler (Ruby)
//   Cargo.lock         Cargo (Rust)

import type { FetchedFile } from './repo-fetcher.js';

// ── Public API ────────────────────────────────────────────────────────────────

export function extractPurls(files: FetchedFile[]): string[] {
  const purls = new Set<string>();

  const npmLockFiles = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']);
  const hasNpmLock   = files.some((f) => npmLockFiles.has(f.path));

  for (const file of files) {
    // Skip package.json when a more precise npm lock file is present
    if (file.path === 'package.json' && hasNpmLock) continue;

    try {
      switch (file.path) {
        case 'package-lock.json': extractPackageLock(file.content, purls); break;
        case 'yarn.lock':         extractYarnLock(file.content, purls);    break;
        case 'pnpm-lock.yaml':    extractPnpmLock(file.content, purls);    break;
        case 'package.json':      extractPackageJson(file.content, purls); break;
        case 'pom.xml':           extractPomXml(file.content, purls);      break;
        case 'build.gradle':      extractGradle(file.content, purls);      break;
        case 'requirements.txt':  extractRequirements(file.content, purls);break;
        case 'Pipfile.lock':      extractPipfileLock(file.content, purls); break;
        case 'go.sum':            extractGoSum(file.content, purls);       break;
        case 'Gemfile.lock':      extractGemfileLock(file.content, purls); break;
        case 'Cargo.lock':        extractCargoLock(file.content, purls);   break;
      }
    } catch {
      // Malformed file — skip and continue with others
    }
  }

  return [...purls];
}

// ── npm / Node.js ─────────────────────────────────────────────────────────────

function extractPackageLock(content: string, purls: Set<string>) {
  const lock = JSON.parse(content) as Record<string, unknown>;

  // v2/v3 — flat "packages" map is the authoritative resolved list
  if (lock['packages'] && typeof lock['packages'] === 'object') {
    const packages = lock['packages'] as Record<string, { version?: string }>;
    for (const [key, pkg] of Object.entries(packages)) {
      if (!key) continue; // skip root entry ("")
      // key: "node_modules/lodash" or "node_modules/@scope/name" or nested "a/node_modules/b"
      // Split on "node_modules/" (no leading slash) so top-level entries are also handled.
      // Last segment after the final "node_modules/" occurrence is the actual package name.
      const segments = key.split('node_modules/');
      const raw  = segments[segments.length - 1] ?? '';
      // Decode percent-encoding: some npm versions write %40scope instead of @scope
      const name = decodeURIComponent(raw);
      if (name && pkg.version) {
        purls.add(`pkg:npm/${name}@${pkg.version}`);
      }
    }
    return;
  }

  // v1 — recursive "dependencies" tree
  if (lock['dependencies'] && typeof lock['dependencies'] === 'object') {
    walkNpmDependencies(lock['dependencies'] as Record<string, unknown>, purls);
  }
}

function walkNpmDependencies(deps: Record<string, unknown>, purls: Set<string>) {
  for (const [name, dep] of Object.entries(deps)) {
    if (!dep || typeof dep !== 'object') continue;
    const d = dep as Record<string, unknown>;
    if (typeof d['version'] === 'string') {
      purls.add(`pkg:npm/${name}@${d['version']}`);
    }
    if (d['dependencies'] && typeof d['dependencies'] === 'object') {
      walkNpmDependencies(d['dependencies'] as Record<string, unknown>, purls);
    }
  }
}

function extractYarnLock(content: string, purls: Set<string>) {
  const lines = content.split('\n');
  let pendingNames: string[] = [];

  for (const line of lines) {
    if (line.startsWith('#') || line.trim() === '' || line.startsWith('__metadata')) continue;

    // Package header — not indented, ends with ":", contains "@"
    if (!line.startsWith(' ') && !line.startsWith('\t') && line.endsWith(':') && line.includes('@')) {
      pendingNames = parseYarnHeader(line);
      continue;
    }

    // Version line: '  version "4.17.21"' (v1) or '  version: 4.17.21' (v2)
    const version = line.match(/^\s+version[: ]+"?(\d[^"\s]*)"?/)?.[1];
    if (version && pendingNames.length > 0) {
      for (const name of pendingNames) {
        purls.add(`pkg:npm/${name}@${version}`);
      }
      pendingNames = [];
    }
  }
}

function parseYarnHeader(line: string): string[] {
  // Examples:
  //   "lodash@^4.17.20":                  → lodash
  //   "@types/node@^18.0.0":              → @types/node
  //   "lodash@npm:^4.17.20":              → lodash
  //   "a@^1.0, a@^1.1":                   → a  (de-duplicated)
  const names = new Set<string>();

  for (const part of line.split(', ')) {
    const cleaned = part.replace(/^["']|["':]*\s*$/g, '').replace(/@npm:/, '@').trim();
    // Find the version-separating @ — skip index 0 because scoped packages start with @
    const atIdx = cleaned.indexOf('@', 1);
    if (atIdx === -1) continue;
    const name = cleaned.slice(0, atIdx);
    if (name) names.add(name);
  }

  return [...names];
}

function extractPnpmLock(content: string, purls: Set<string>) {
  // v6:  "  /lodash@4.17.21:"  or  "  /@types/node@18.0.0:"
  // v9:  "  lodash@4.17.21:"   or  "  '@types/node@18.0.0':"
  const re = /^\s+\/?'?(@?[^@\s'"/]+(?:\/[^@\s'"]+)?)@(\d[^':\s]*)['"]?:/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    purls.add(`pkg:npm/${m[1]}@${m[2]}`);
  }
}

function extractPackageJson(content: string, purls: Set<string>) {
  const pkg = JSON.parse(content) as Record<string, unknown>;
  const deps = {
    ...(pkg['dependencies']    as Record<string, string> | undefined ?? {}),
    ...(pkg['devDependencies'] as Record<string, string> | undefined ?? {}),
  };
  for (const [name, range] of Object.entries(deps)) {
    // Strip common range prefixes: ^ ~ >= > = to get a bare version
    const version = String(range).replace(/^[\^~>=<*]+/, '').trim();
    if (version && /^\d/.test(version) && !version.includes(' ')) {
      purls.add(`pkg:npm/${name}@${version}`);
    }
  }
}

// ── JVM ───────────────────────────────────────────────────────────────────────

function extractPomXml(content: string, purls: Set<string>) {
  const depBlocks = content.match(/<dependency>[\s\S]*?<\/dependency>/g) ?? [];
  for (const block of depBlocks) {
    const groupId    = block.match(/<groupId>([^<]+)<\/groupId>/)?.[1]?.trim();
    const artifactId = block.match(/<artifactId>([^<]+)<\/artifactId>/)?.[1]?.trim();
    const version    = block.match(/<version>([^<${}]+)<\/version>/)?.[1]?.trim();
    if (groupId && artifactId && version && /^\d/.test(version)) {
      purls.add(`pkg:maven/${groupId}/${artifactId}@${version}`);
    }
  }
}

function extractGradle(content: string, purls: Set<string>) {
  // Match: implementation 'group:artifact:version' or implementation("group:artifact:version")
  const re = /(?:implementation|api|compileOnly|runtimeOnly)\s*[("']([^"'()]+)[)"']/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const parts = m[1].split(':');
    if (parts.length === 3) {
      const [group, artifact, version] = parts;
      if (/^\d/.test(version)) {
        purls.add(`pkg:maven/${group}/${artifact}@${version}`);
      }
    }
  }
}

// ── Python ────────────────────────────────────────────────────────────────────

function extractRequirements(content: string, purls: Set<string>) {
  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    // "Flask==2.3.0", "requests>=2.28.0", "numpy~=1.24.0", "package[extra]==1.0"
    const m = line.match(/^([A-Za-z0-9_\-.]+)(?:\[[^\]]*\])?[=~!><]+(\d[^\s;#,]*)/);
    if (m) {
      // Normalise name: lowercase, replace _ and - with -
      const name = m[1].toLowerCase().replace(/[-_]+/g, '-');
      purls.add(`pkg:pypi/${name}@${m[2]}`);
    }
  }
}

function extractPipfileLock(content: string, purls: Set<string>) {
  // Pipfile.lock is JSON: { "default": { "flask": { "version": "==2.3.0" }, ... }, "develop": {...} }
  const lock = JSON.parse(content) as Record<string, Record<string, { version?: string }>>;
  for (const section of ['default', 'develop']) {
    const pkgs = lock[section] ?? {};
    for (const [name, meta] of Object.entries(pkgs)) {
      if (name === '_meta') continue;
      const version = meta.version?.replace(/^==/, '');
      if (version && /^\d/.test(version)) {
        purls.add(`pkg:pypi/${name.toLowerCase()}@${version}`);
      }
    }
  }
}

// ── Go ────────────────────────────────────────────────────────────────────────

function extractGoSum(content: string, purls: Set<string>) {
  const seen = new Set<string>();
  for (const line of content.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 2) continue;
    const [module, rawVersion] = parts;
    if (!rawVersion?.startsWith('v') || rawVersion.endsWith('/go.mod')) continue;
    const key = `${module}@${rawVersion}`;
    if (!seen.has(key)) {
      seen.add(key);
      purls.add(`pkg:golang/${module}@${rawVersion}`);
    }
  }
}

// ── Ruby ──────────────────────────────────────────────────────────────────────

function extractGemfileLock(content: string, purls: Set<string>) {
  // Specs section starts after "GEM\n  remote: ...\n  specs:" and ends at blank line
  const specsMatch = content.match(/\bspecs:\n([\s\S]*?)(?:\n\n|\nBUNDLED|$)/);
  if (!specsMatch) return;
  for (const line of specsMatch[1].split('\n')) {
    // 4-space indent = direct gem: "    rails (7.0.0)"
    const m = line.match(/^    ([a-zA-Z0-9_\-.]+) \(([^)]+)\)/);
    if (m) {
      purls.add(`pkg:gem/${m[1]}@${m[2]}`);
    }
  }
}

// ── Rust ──────────────────────────────────────────────────────────────────────

function extractCargoLock(content: string, purls: Set<string>) {
  // TOML format: [[package]] blocks with name = "..." and version = "..."
  const blocks = content.split(/\[\[package\]\]/);
  for (const block of blocks) {
    const name    = block.match(/name\s*=\s*"([^"]+)"/)?.[1];
    const version = block.match(/version\s*=\s*"([^"]+)"/)?.[1];
    if (name && version) {
      purls.add(`pkg:cargo/${name}@${version}`);
    }
  }
}

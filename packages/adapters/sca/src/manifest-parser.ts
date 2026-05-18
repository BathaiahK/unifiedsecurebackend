import { promises as fs } from 'node:fs';
import { join } from 'node:path';

export interface ParsedDependency {
  name: string;
  version: string;
  isDirect: boolean;
}

export async function parseDependencies(repoPath: string): Promise<string[]> {
  const purls: string[] = [];

  // Read all manifest files concurrently
  const manifestPaths = {
    packageJson: join(repoPath, 'package.json'),
    requirements: join(repoPath, 'requirements.txt'),
    pyproject: join(repoPath, 'pyproject.toml'),
    gemfile: join(repoPath, 'Gemfile'),
    gomod: join(repoPath, 'go.mod'),
    pom: join(repoPath, 'pom.xml'),
  };

  const results = await Promise.allSettled([
    fs.readFile(manifestPaths.packageJson, 'utf-8'),
    fs.readFile(manifestPaths.requirements, 'utf-8'),
    fs.readFile(manifestPaths.pyproject, 'utf-8'),
    fs.readFile(manifestPaths.gemfile, 'utf-8'),
    fs.readFile(manifestPaths.gomod, 'utf-8'),
    fs.readFile(manifestPaths.pom, 'utf-8'),
  ]);

  const [
    packageJsonResult,
    requirementsResult,
    pyprojectResult,
    gemfileResult,
    gomodResult,
    pomResult,
  ] = results;

  // Parse package.json (npm/yarn/pnpm)
  if (packageJsonResult.status === 'fulfilled') {
    try {
      const pkg = JSON.parse(packageJsonResult.value);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      for (const [name, version] of Object.entries(deps)) {
        const cleanVersion = extractVersionString(version as string);
        purls.push(`pkg:npm/${name}@${cleanVersion}`);
      }
    } catch (err) {
      console.error(`Failed to parse package.json: ${err}`);
    }
  }

  // Parse requirements.txt (Python pip)
  if (requirementsResult.status === 'fulfilled') {
    try {
      const lines = requirementsResult.value.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        const match = trimmed.match(/^([a-zA-Z0-9\-_.]+)(?:[=<>!~;\\s]*)?([0-9.]+)?/);
        if (match) {
          const name = match[1];
          const version = match[2] || '*';
          purls.push(`pkg:pypi/${name}@${version}`);
        }
      }
    } catch (err) {
      console.error(`Failed to parse requirements.txt: ${err}`);
    }
  }

  // Parse pyproject.toml (Python poetry/pipenv)
  if (pyprojectResult.status === 'fulfilled') {
    try {
      const content = pyprojectResult.value;
      const depMatch = content.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\[|$)/);

      if (depMatch) {
        const depsSection = depMatch[1];
        const lines = depsSection.split('\n');

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('[')) continue;

          const match = trimmed.match(/^([a-zA-Z0-9\-_.]+)\s*=\s*["\']?([0-9.^~*]+)?/);
          if (match) {
            const name = match[1];
            const version = match[2] || '*';
            purls.push(`pkg:pypi/${name}@${version}`);
          }
        }
      }
    } catch (err) {
      console.error(`Failed to parse pyproject.toml: ${err}`);
    }
  }

  // Parse Gemfile (Ruby)
  if (gemfileResult.status === 'fulfilled') {
    try {
      const lines = gemfileResult.value.split('\n');
      for (const line of lines) {
        const match = line.match(
          /^\s*gem\s+['"]([a-zA-Z0-9\-_.]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/,
        );
        if (match) {
          const name = match[1];
          const version = match[2] || '*';
          purls.push(`pkg:gem/${name}@${version}`);
        }
      }
    } catch (err) {
      console.error(`Failed to parse Gemfile: ${err}`);
    }
  }

  // Parse go.mod (Go)
  if (gomodResult.status === 'fulfilled') {
    try {
      const lines = gomodResult.value.split('\n');
      let inRequire = false;

      for (const line of lines) {
        const trimmed = line.trim();

        if (trimmed.startsWith('require')) {
          inRequire = true;
          if (trimmed !== 'require (') {
            const match = trimmed.match(/require\s+([^\s]+)\s+([^\s]+)/);
            if (match) {
              purls.push(`pkg:golang/${match[1]}@${match[2]}`);
            }
          }
          continue;
        }

        if (inRequire) {
          if (trimmed === ')') {
            inRequire = false;
            continue;
          }

          const match = trimmed.match(/^([^\s]+)\s+([^\s]+)/);
          if (match) {
            purls.push(`pkg:golang/${match[1]}@${match[2]}`);
          }
        }
      }
    } catch (err) {
      console.error(`Failed to parse go.mod: ${err}`);
    }
  }

  // Parse pom.xml (Maven/Java)
  if (pomResult.status === 'fulfilled') {
    try {
      const content = pomResult.value;
      const depMatches = content.matchAll(
        /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>/g,
      );

      for (const match of depMatches) {
        const groupId = match[1];
        const artifactId = match[2];
        const version = match[3];
        purls.push(`pkg:maven/${groupId}/${artifactId}@${version}`);
      }
    } catch (err) {
      console.error(`Failed to parse pom.xml: ${err}`);
    }
  }

  return purls;
}

function extractVersionString(versionSpec: string): string {
  if (!versionSpec) return '*';

  const match = versionSpec.match(/[\d.]+/);
  if (match) return match[0];

  return '*';
}

export function generateSimulatedPurls(): string[] {
  return [
    'pkg:npm/@babel/core@7.29.0',
    'pkg:npm/@babel/types@7.29.0',
    'pkg:npm/@colors/colors@1.6.0',
    'pkg:npm/@eslint/eslintrc@2.1.4',
    'pkg:npm/@eslint/js@8.57.1',
    'pkg:npm/@hapi/hoek@9.3.0',
    'pkg:npm/@jest/console@29.7.0',
    'pkg:npm/react@19.0.0',
    'pkg:npm/lodash@4.17.21',
    'pkg:npm/express@4.18.2',
  ];
}

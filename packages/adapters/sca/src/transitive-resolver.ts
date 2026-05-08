import type { TransitiveDependency } from './types.js';

interface DepGraph {
  [key: string]: {
    version: string;
    dependencies?: Record<string, string>;
  };
}

/**
 * Parse package-lock.json or similar lock files to resolve transitive dependencies
 */
export function resolveTransitiveDependencies(
  lockFileContent: string,
  manifestType: 'package-lock.json' | 'yarn.lock' | 'pnpm-lock.yaml' | string,
): TransitiveDependency[] {
  const deps: TransitiveDependency[] = [];

  try {
    if (manifestType === 'package-lock.json') {
      return resolveNpmTransitives(JSON.parse(lockFileContent));
    }
    // Other lock file formats can be added here
  } catch (err) {
    console.error('[SCA] Failed to parse lock file:', err);
  }

  return deps;
}

/**
 * Parse npm package-lock.json format
 * Structure:
 * {
 *   "packages": {
 *     "": { "dependencies": { "express": "4.18.0" } },
 *     "node_modules/express": { "version": "4.18.0", "dependencies": {...} }
 *   }
 * }
 */
function resolveNpmTransitives(lockData: any): TransitiveDependency[] {
  const deps: TransitiveDependency[] = [];
  const seen = new Set<string>();

  if (!lockData.packages) return deps;

  const packages = lockData.packages as Record<string, any>;

  // Iterate through all packages
  for (const [path, pkg] of Object.entries(packages)) {
    if (!pkg.version) continue;

    // Extract package name and version from path
    // e.g., "node_modules/express" -> "express"
    // e.g., "node_modules/@babel/core" -> "@babel/core"
    const name = extractPackageName(path);
    if (!name || seen.has(`${name}@${pkg.version}`)) continue;

    seen.add(`${name}@${pkg.version}`);

    const depth = calculateDepth(path);
    const ecosystem = 'npm';
    const parent = depth > 0 ? extractParentName(path) : undefined;

    const dep: TransitiveDependency = {
      name,
      version: pkg.version,
      ecosystem,
      depth,
      vulnerabilities: 0, // Will be set by adapter
    };
    if (parent) {
      dep.parent = parent;
    }

    deps.push(dep);
  }

  return deps;
}

function extractPackageName(path: string): string | undefined {
  // Handle @scoped packages: node_modules/@babel/core -> @babel/core
  const match = path.match(/node_modules\/((?:@[^/]+\/)?[^/]+)$/);
  return match ? match[1] : undefined;
}

function extractParentName(path: string): string | undefined {
  // For nested deps: node_modules/express/node_modules/body-parser
  // Parent is "express"
  const parts = path.split('/node_modules/');
  if (parts.length >= 2) {
    const parentPath = parts[parts.length - 2];
    if (parentPath) {
      const match = parentPath.match(/((?:@[^/]+\/)?[^/]+)$/);
      return match ? match[1] : undefined;
    }
  }
  return undefined;
}

function calculateDepth(path: string): number {
  // Count occurrences of "node_modules/"
  // "" = root (depth 0)
  // "node_modules/express" = depth 1
  // "node_modules/express/node_modules/body-parser" = depth 2
  const matches = path.match(/node_modules/g);
  return matches ? matches.length - 1 : 0;
}

/**
 * Build a simplified dependency tree showing relationships
 */
export function buildDependencyTree(deps: TransitiveDependency[]): Record<string, any> {
  const root: Record<string, any> = {};

  // Group by depth for easy visualization
  const byDepth = new Map<number, TransitiveDependency[]>();
  for (const dep of deps) {
    if (!byDepth.has(dep.depth)) {
      byDepth.set(dep.depth, []);
    }
    byDepth.get(dep.depth)!.push(dep);
  }

  // Build tree structure
  const directDeps = byDepth.get(0) ?? [];
  for (const dep of directDeps) {
    root[dep.name] = {
      version: dep.version,
      depth: 0,
      vulnerabilities: dep.vulnerabilities,
      children: [] as any[],
    };
  }

  // Add transitive deps under their parents
  for (let depth = 1; depth <= 10; depth++) {
    const levelDeps = byDepth.get(depth);
    if (!levelDeps) break;

    for (const dep of levelDeps) {
      if (!dep.parent) continue;

      // Find parent node
      let parentNode = findNodeByName(root, dep.parent);
      if (!parentNode) continue;

      if (!parentNode.children) {
        parentNode.children = [];
      }

      parentNode.children.push({
        name: dep.name,
        version: dep.version,
        depth,
        vulnerabilities: dep.vulnerabilities,
        children: [],
      });
    }
  }

  return root;
}

function findNodeByName(tree: Record<string, any>, name: string): any {
  for (const node of Object.values(tree)) {
    if (node.name === name) return node;
    if (node.children) {
      const found = searchNodeInChildren(node.children, name);
      if (found) return found;
    }
  }
  return null;
}

function searchNodeInChildren(children: any[], name: string): any {
  for (const child of children) {
    if (child.name === name) return child;
    if (child.children) {
      const found = searchNodeInChildren(child.children, name);
      if (found) return found;
    }
  }
  return null;
}

/**
 * Get all transitive parents of a package (the chain back to root)
 */
export function getTransitiveChain(deps: TransitiveDependency[], targetName: string): string[] {
  const chain: string[] = [];
  let current = targetName;

  // Find the dep
  let dep = deps.find((d) => d.name === current);
  if (!dep) return chain;

  while (dep?.parent) {
    chain.unshift(dep.parent);
    dep = deps.find((d) => d.name === dep!.parent);
  }

  chain.push(targetName);
  return chain;
}

/**
 * Count vulnerabilities in the transitive tree
 */
export function countTransitiveVulnerabilities(deps: TransitiveDependency[]): {
  direct: number;
  transitive: number;
  total: number;
} {
  const directVulns = deps
    .filter((d) => d.depth === 0)
    .reduce((sum, d) => sum + d.vulnerabilities, 0);

  const transitiveVulns = deps
    .filter((d) => d.depth > 0)
    .reduce((sum, d) => sum + d.vulnerabilities, 0);

  return {
    direct: directVulns,
    transitive: transitiveVulns,
    total: directVulns + transitiveVulns,
  };
}

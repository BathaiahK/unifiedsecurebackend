import type { SupplyChainReport, SupplyChainThreat } from './types.js';

const TOP_300_NPM_PACKAGES = new Set([
  'react', 'vue', 'angular', 'jquery', 'lodash', 'express', 'webpack', 'babel', 'typescript', 'eslint', 'prettier',
  'jest', 'vitest', 'mocha', 'chai', 'axios', 'fetch', 'node-fetch', 'qs', 'next', 'nuxt', 'svelte', 'sass', 'less',
  'tailwindcss', 'bootstrap', 'material-ui', 'antd', 'moment', 'dayjs', 'date-fns', 'uuid', 'nanoid', 'crypto-js',
  'dotenv', 'cors', 'helmet', 'joi', 'yup', 'zod', 'class-validator', 'sequelize', 'typeorm', 'mongoose', 'prisma',
  'knex', 'pg', 'mongodb', 'redis', 'ioredis', 'bullmq', 'kafka-node', 'amqplib', 'ws', 'fastify', 'koa', 'hapi',
  'restify', 'connect', 'body-parser', 'multer', 'compression', 'serve-static', 'cookie-parser', 'express-session',
  'jsonwebtoken', 'passport', 'bcryptjs', 'bcrypt', 'argon2', 'nodemon', 'pm2', 'forever', 'cluster', 'worker_threads',
  'path', 'fs-extra', 'rimraf', 'mkdirp', 'glob', 'minimatch', 'chalk', 'colors', 'inquirer', 'yargs', 'commander',
  'oclif', 'winston', 'bunyan', 'pino', 'debug', 'log4js', 'supertest', 'sinon', 'nock', 'faker', 'casual', 'semver',
  'semver-compare', 'version-compare', 'npm', 'yarn', 'pnpm', 'lerna', 'monorepo', 'got', 'superagent', 'ky', 'sharp',
  'jimp', 'canvas', 'puppeteer', 'playwright', 'cheerio', 'jsdom', 'html-parser', 'xml2js', 'http', 'https', 'fs',
  'stream', 'util', 'crypto', 'os', 'path', 'events', 'buffer', 'querystring', 'url', 'zlib', 'net', 'dgram', 'dns',
  'tls', 'child_process', 'cluster', 'assert', 'async', 'promise', 'q', 'bluebird', 'co', 'when', 'deferred', 'async-await',
  'request', 'http-request', 'rest', 'restify-client', 'soap', 'xml-rpc', 'grpc', 'protobuf', 'thrift', 'avro', 'msgpack',
  'json-stringify', 'serialize-javascript', 'cookie', 'set-cookie', 'jwt', 'oauth', 'oauth2', 'openid', 'saml', 'ldap',
  'kerberos', 'ntlm', 'digest', 'basic-auth', 'bearer', 'api-key', 'scopes', 'permissions', 'acl', 'rbac', 'abac',
  'rate-limit', 'throttle', 'queue', 'deque', 'stack', 'heap', 'tree', 'graph', 'trie', 'linkedlist', 'skiplist',
  'btree', 'bst', 'avl', 'red-black', 'splay', 'segment-tree', 'fenwick', 'union-find', 'bloom-filter', 'hyperloglog',
  'array', 'object', 'map', 'set', 'weakmap', 'weakset', 'proxy', 'reflect', 'promise', 'generator', 'iterator', 'symbol',
  'datastructures', 'algorithms', 'sort', 'search', 'graph-algorithms', 'dynamic-programming', 'greedy', 'divide-conquer',
  'backtracking', 'recursion', 'memoization', 'caching', 'lru-cache', 'ttl-cache', 'memory-cache', 'redis-cache',
  'memcached', 'etcd', 'consul', 'zookeeper', 'cassandra', 'hbase', 'elasticsearch', 'solr', 'lucene', 'whoosh',
  'algolia', 'meilisearch', 'typesense', 'qdrant', 'weaviate', 'pinecone', 'faiss', 'chromadb', 'milvus', 'vespa',
  'tensorflow', 'pytorch', 'keras', 'scikit-learn', 'pandas', 'numpy', 'scipy', 'matplotlib', 'seaborn', 'plotly',
  'bokeh', 'dash', 'flask', 'django', 'fastapi', 'tornado', 'twisted', 'aiohttp', 'sanic', 'starlette', 'falcon',
  'bottle', 'pyramid', 'cherrypy', 'web2py', 'turbogears', 'sqlalchemy', 'peewee', 'tortoise', 'motor', 'asyncpg',
  'psycopg2', 'pymongo', 'pymysql', 'redis-py', 'elasticsearch-py', 'click', 'argparse', 'optparse', 'docopt', 'fire',
  'typer', 'poetry', 'pipenv', 'conda', 'virtualenv', 'venv', 'pyenv', 'poetry-lock', 'pip-tools', 'setup-tools',
  'setuptools-scm', 'wheel', 'twine', 'build', 'flit', 'hatchling', 'pdm', 'poetry-core', 'distutils', 'pkgutil'
]);

export function extractName(purl: string): string | undefined {
  try {
    const match = purl.match(/^pkg:npm\/((@[^\/]+\/)?[^@]+)/);
    return match ? match[1] : undefined;
  } catch {
    return undefined;
  }
}

export function extractVersion(purl: string): string | undefined {
  try {
    const match = purl.match(/@([^#?]+)(?:#|$|\?)/);
    return match ? match[1] : undefined;
  } catch {
    return undefined;
  }
}

function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp = Array(m + 1)
    .fill(null)
    .map(() => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i]![0] = i;
  for (let j = 0; j <= n; j++) dp[0]![j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i]![j] = Math.min(
        dp[i - 1]![j]! + 1,
        dp[i]![j - 1]! + 1,
        dp[i - 1]![j - 1]! + cost
      );
    }
  }

  return dp[m]![n]!;
}

function homoglyphDistance(a: string, b: string): number {
  const homoglyphs: Record<string, Set<string>> = {
    'l': new Set(['1', 'i', '|']),
    'o': new Set(['0']),
    'r': new Set(['n']),
    's': new Set(['5', '$']),
    'z': new Set(['2']),
  };

  let distance = levenshteinDistance(a, b);

  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) {
      const homoglyph = homoglyphs[a[i]!.toLowerCase()];
      if (homoglyph && homoglyph.has(b[i]!.toLowerCase())) {
        distance -= 0.5;
      }
    }
  }

  return Math.max(0, distance);
}

export function detectTyposquatting(purls: string[]): SupplyChainThreat[] {
  const threats: SupplyChainThreat[] = [];
  const seen = new Set<string>();

  for (const purl of purls) {
    const name = extractName(purl);
    const version = extractVersion(purl);

    if (!name || !version || seen.has(name)) continue;

    const innerName = name.includes('/') ? name.split('/')[1]! : name;

    for (const topPkg of Array.from(TOP_300_NPM_PACKAGES)) {
      const levenDist = levenshteinDistance(innerName.toLowerCase(), topPkg.toLowerCase());
      const homoDist = homoglyphDistance(innerName.toLowerCase(), topPkg.toLowerCase());
      const distance = Math.min(levenDist, homoDist);

      if (distance <= 2 && distance > 0) {
        threats.push({
          packageName: name,
          version,
          purl,
          threatType: 'typosquatting',
          severity: distance === 1 ? 'high' : 'medium',
          confidence: 'HIGH',
          description: `Package name resembles popular package "${topPkg}" (edit distance: ${Math.round(distance * 10) / 10})`,
          suspectedTargetPackage: topPkg,
          editDistance: Math.round(distance * 10) / 10,
        });
        seen.add(name);
        break;
      }
    }
  }

  return threats;
}

export function detectDependencyConfusion(purls: string[]): SupplyChainThreat[] {
  const threats: SupplyChainThreat[] = [];
  const seen = new Set<string>();

  for (const purl of purls) {
    const name = extractName(purl);
    const version = extractVersion(purl);

    if (!name || !version || seen.has(name)) continue;

    if (name.startsWith('@')) {
      const [scope, pkgName] = name.split('/');
      if (scope && pkgName && pkgName.length > 0) {
        const unscoped = pkgName;

        threats.push({
          packageName: name,
          version,
          purl,
          threatType: 'dependency-confusion',
          severity: 'high',
          confidence: 'MEDIUM',
          description: `Scoped package uses scope "${scope}". Verify scope ownership to prevent dependency confusion attacks where unscoped "${unscoped}" published publicly could be installed instead.`,
          visiblyExposedPublicly: false,
        });
        seen.add(name);
      }
    } else if (name.includes('-company-') || name.includes('-internal-') || name.includes('-private-')) {
      threats.push({
        packageName: name,
        version,
        purl,
        threatType: 'dependency-confusion',
        severity: 'medium',
        confidence: 'MEDIUM',
        description: `Package name "${name}" appears to be internal (contains internal markers). If this package is not published on npm, a public package with the same name could trigger dependency confusion. Use scoped packages (@company/name) for internal dependencies.`,
        visiblyExposedPublicly: false,
      });
      seen.add(name);
    }
  }

  return threats;
}

export function detectUnmaintained(purls: string[]): SupplyChainThreat[] {
  const threats: SupplyChainThreat[] = [];
  const seen = new Set<string>();

  const knownAbandoned: Record<string, { lastPublish: string; daysSince: number }> = {
    'request': { lastPublish: '2020-02-04', daysSince: 2200 },
    'node-uuid': { lastPublish: '2015-08-10', daysSince: 3300 },
    'har-validator': { lastPublish: '2021-05-24', daysSince: 1375 },
    'left-pad': { lastPublish: '2016-03-27', daysSince: 3200 },
    'event-stream': { lastPublish: '2018-11-27', daysSince: 2200 },
  };

  for (const purl of purls) {
    const name = extractName(purl);
    const version = extractVersion(purl);

    if (!name || !version || seen.has(name)) continue;
    seen.add(name);

    if (knownAbandoned[name]) {
      const { lastPublish, daysSince } = knownAbandoned[name]!;
      const severity = daysSince >= 1095 ? 'high' : 'medium';

      threats.push({
        packageName: name,
        version,
        purl,
        threatType: 'unmaintained',
        severity,
        confidence: 'HIGH',
        description: `Package not maintained since ${lastPublish} (${daysSince} days ago). Consider using an actively maintained alternative.`,
        lastPublishDate: lastPublish,
        daysSinceLastPublish: daysSince,
      });
    }
  }

  return threats;
}

export function detectMaliciousAdvisories(purls: string[]): SupplyChainThreat[] {
  const threats: SupplyChainThreat[] = [];
  const seen = new Set<string>();

  const knownMalicious: Record<string, { advisoryId: string; description: string }> = {
    'example-malware-pkg': { advisoryId: 'GHSA-xxxx-yyyy-zzzz', description: 'Known malicious package detected in advisories' },
  };

  for (const purl of purls) {
    const name = extractName(purl);
    const version = extractVersion(purl);

    if (!name || !version || seen.has(name)) continue;

    if (knownMalicious[name]) {
      const { advisoryId, description } = knownMalicious[name]!;
      threats.push({
        packageName: name,
        version,
        purl,
        threatType: 'malicious-advisory',
        severity: 'critical',
        confidence: 'HIGH',
        description,
        advisoryId,
        advisoryUrl: `https://github.com/advisories/${advisoryId}`,
      });
      seen.add(name);
    }
  }

  return threats;
}

export function runSupplyChainAnalysis(purls: string[]): SupplyChainReport {
  const typosquatting = detectTyposquatting(purls);
  const dependencyConfusion = detectDependencyConfusion(purls);
  const unmaintained = detectUnmaintained(purls);
  const maliciousAdvisories = detectMaliciousAdvisories(purls);

  const threats = [...typosquatting, ...dependencyConfusion, ...unmaintained, ...maliciousAdvisories];

  return {
    generatedAt: new Date().toISOString(),
    totalPackagesAnalyzed: new Set(purls.map((p) => extractName(p))).size,
    threats,
    typosquattingCount: typosquatting.length,
    dependencyConfusionCount: dependencyConfusion.length,
    unmaintainedCount: unmaintained.length,
    maliciousAdvisoryCount: maliciousAdvisories.length,
    namespaceJackingCount: 0,
  };
}

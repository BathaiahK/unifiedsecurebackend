// Fetch raw dependency files from a remote git repository.
//
// Supports GitHub, GitLab (cloud + self-hosted), and Bitbucket by constructing
// the appropriate raw-file URL for each host. No git clone is performed — we
// make plain HTTPS requests to the raw content endpoints.
//
// Auth (optional — required for private repos):
//   GITHUB_TOKEN      → sent as "Authorization: Bearer <token>"
//   GITLAB_TOKEN      → sent as "PRIVATE-TOKEN: <token>"
//   BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD → Basic auth

export interface FetchedFile {
  path: string;
  content: string;
}

// Ordered by parse precision: lock files first, manifests last.
export const DEPENDENCY_FILES = [
  'package-lock.json', // npm  (v1/v2/v3)
  'yarn.lock', // yarn (v1/berry)
  'pnpm-lock.yaml', // pnpm (v6/v9)
  'package.json', // npm  (fallback — ranges only, used when no lock file)
  'pom.xml', // Maven
  'build.gradle', // Gradle (basic support)
  'requirements.txt', // pip
  'Pipfile.lock', // pipenv
  'go.sum', // Go modules
  'Gemfile.lock', // Bundler (Ruby)
  'Cargo.lock', // Cargo (Rust)
] as const;

// ── URL parsing ───────────────────────────────────────────────────────────────

type GitHost = 'github' | 'gitlab' | 'bitbucket' | 'gitlab-self-hosted';

interface ParsedRepo {
  host: GitHost;
  ownerRepo: string; // "owner/repo"
  baseUrl: string; // "https://github.com" etc.
}

function parseRepoUrl(raw: string): ParsedRepo {
  // Normalise SSH → HTTPS and strip trailing .git + /tree/... suffixes
  const url = raw
    .replace(/^git@github\.com:(.+)/, 'https://github.com/$1')
    .replace(/^git@gitlab\.com:(.+)/, 'https://gitlab.com/$1')
    .replace(/^git@bitbucket\.org:(.+)/, 'https://bitbucket.org/$1')
    .replace(/\.git$/, '')
    .replace(/\/(?:tree|blob|src)\/.*$/, '');

  const githubRe = /^(https?:\/\/github\.com)\/([^/]+\/[^/?#]+)/;
  const gitlabRe = /^(https?:\/\/gitlab\.com)\/([^/]+\/[^/?#]+)/;
  const bitbucketRe = /^(https?:\/\/bitbucket\.org)\/([^/]+\/[^/?#]+)/;
  const selfGlRe = /^(https?:\/\/[^/]+)\/([^/]+\/[^/?#]+)/;

  let m: RegExpMatchArray | null;

  if ((m = url.match(githubRe)) && m[1] && m[2])
    return { host: 'github', ownerRepo: m[2], baseUrl: m[1] };
  if ((m = url.match(gitlabRe)) && m[1] && m[2])
    return { host: 'gitlab', ownerRepo: m[2], baseUrl: m[1] };
  if ((m = url.match(bitbucketRe)) && m[1] && m[2])
    return { host: 'bitbucket', ownerRepo: m[2], baseUrl: m[1] };
  if ((m = url.match(selfGlRe)) && m[1] && m[2])
    return { host: 'gitlab-self-hosted', ownerRepo: m[2], baseUrl: m[1] };

  throw new Error(`Unrecognised git URL format: ${raw}`);
}

function rawFileUrl(parsed: ParsedRepo, branch: string, filePath: string): string {
  const { host, ownerRepo, baseUrl } = parsed;
  switch (host) {
    case 'github':
      // GitHub serves raw files at a separate domain
      return `https://raw.githubusercontent.com/${ownerRepo}/${branch}/${filePath}`;
    case 'gitlab':
    case 'gitlab-self-hosted':
      return `${baseUrl}/${ownerRepo}/-/raw/${branch}/${filePath}`;
    case 'bitbucket':
      return `${baseUrl}/${ownerRepo}/raw/${branch}/${filePath}`;
  }
}

function authHeaders(host: GitHost, projectToken?: string): Record<string, string> {
  const h: Record<string, string> = {};

  // Project-level token takes priority over global env vars
  if (projectToken) {
    if (host === 'gitlab' || host === 'gitlab-self-hosted') {
      h['PRIVATE-TOKEN'] = projectToken;
    } else {
      h['Authorization'] = `Bearer ${projectToken}`;
    }
    return h;
  }

  // Fall back to environment-level tokens
  const ghToken = process.env['GITHUB_TOKEN'];
  const glToken = process.env['GITLAB_TOKEN'];
  const bbUser = process.env['BITBUCKET_USERNAME'];
  const bbPass = process.env['BITBUCKET_APP_PASSWORD'];

  if (host === 'github' && ghToken) {
    h['Authorization'] = `Bearer ${ghToken}`;
  } else if ((host === 'gitlab' || host === 'gitlab-self-hosted') && glToken) {
    h['PRIVATE-TOKEN'] = glToken;
  } else if (host === 'bitbucket' && bbUser && bbPass) {
    h['Authorization'] = `Basic ${Buffer.from(`${bbUser}:${bbPass}`).toString('base64')}`;
  }

  return h;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Fetch whichever dependency files exist in the repo.
 * Missing files (404) are silently skipped.
 * Network / parse errors are surfaced so callers can decide whether to abort.
 */
export async function fetchRepoFiles(
  repoUrl: string,
  branch: string,
  filePaths: readonly string[] = DEPENDENCY_FILES,
  projectToken?: string,
): Promise<FetchedFile[]> {
  const parsed = parseRepoUrl(repoUrl);
  const headers = authHeaders(parsed.host, projectToken);
  const timeout = 12_000; // ms per request

  const settled = await Promise.allSettled(
    filePaths.map(async (filePath): Promise<FetchedFile | null> => {
      const url = rawFileUrl(parsed, branch, filePath);
      const res = await fetch(url, {
        headers,
        signal: AbortSignal.timeout(timeout),
      });
      if (!res.ok) return null; // 404 = file not in repo
      const content = await res.text();
      return { path: filePath, content };
    }),
  );

  return settled
    .filter(
      (r): r is PromiseFulfilledResult<FetchedFile> => r.status === 'fulfilled' && r.value !== null,
    )
    .map((r) => r.value);
}

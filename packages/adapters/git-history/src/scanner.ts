import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { simpleGit } from 'simple-git';
import { SECRET_PATTERNS, SKIP_PATHS, KNOWN_FALSE_POSITIVES, shouldSkipPath, calculateEntropy, type SecretCategory } from './patterns.js';

export interface ScanOptions {
  repoUrl: string;
  branch: string;
  depth: number;
  cloneDir: string;
  onProgress?: (processed: number, total: number) => void;
}

export interface RawSecret {
  patternId: string;
  patternName: string;
  severity: 'critical' | 'high' | 'medium';
  secretCategory: SecretCategory;
  commitHash: string;
  commitDate: string;
  authorName: string;
  authorEmail: string;
  filePath: string;
  lineNumber: number;
  matchedValue: string;
  fullMatchedValue: string;
  contextLines: string[];
  dedupeKey: string;
}

function redactSecret(value: string): string {
  if (value.length <= 12) return '***';
  return value.slice(0, 6) + '...' + value.slice(-4);
}

function makeDedupeKey(patternId: string, value: string): string {
  return createHash('sha256')
    .update(patternId + ':' + value)
    .digest('hex')
    .slice(0, 16);
}

function isKnownFalsePositive(value: string): boolean {
  return KNOWN_FALSE_POSITIVES.has(value.toLowerCase());
}

export async function scanRepository(opts: ScanOptions): Promise<RawSecret[]> {
  const findings: RawSecret[] = [];
  const seen = new Set<string>();

  const cloneDir = opts.cloneDir;

  try {
    // ──────────────────────────────────────────────────────────────
    // Step 1: Clone repository
    // ──────────────────────────────────────────────────────────────

    const git = simpleGit();
    await git.clone(opts.repoUrl, cloneDir, [
      `--depth=${opts.depth}`,
      `--branch=${opts.branch}`,
      '--single-branch',
      '--quiet',
    ]);

    const repoGit = simpleGit(cloneDir);

    // ──────────────────────────────────────────────────────────────
    // Step 2: Get total commit count for progress
    // ──────────────────────────────────────────────────────────────

    const countResult = await repoGit.log(['-1', '--format=%H']);
    let totalCommits = 1;
    try {
      const logResult = await repoGit.log([]);
      totalCommits = logResult.total || 1;
    } catch {
      totalCommits = 1;
    }

    // ──────────────────────────────────────────────────────────────
    // Step 3: Run git log -p and parse output line by line
    // ──────────────────────────────────────────────────────────────

    let processed = 0;

    const child = spawn('git', ['log', '-p', '--all', '--format=COMMIT:%H %ae %an %aI', '--no-merges'], {
      cwd: cloneDir,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const rl = createInterface({
      input: child.stdout,
      crlfDelay: Infinity,
    });

    let currentCommitHash = '';
    let currentAuthorEmail = '';
    let currentAuthorName = '';
    let currentCommitDate = '';
    let currentFilePath = '';
    let currentLineNumber = 0;
    let isBinaryFile = false;
    let shouldSkipCurrentFile = false;

    // Track context lines for each finding
    const contextBuffer: string[] = [];
    const CONTEXT_SIZE = 2;

    for await (const line of rl) {
      // Parse commit line
      if (line.startsWith('COMMIT:')) {
        const parts = line.slice(7).split(' ');
        if (parts.length >= 4) {
          currentCommitHash = parts[0] ?? '';
          currentAuthorEmail = parts[1] ?? '';
          currentAuthorName = parts[2] ?? '';
          currentCommitDate = parts[3] ?? '';
          processed++;
          if (opts.onProgress) {
            opts.onProgress(processed, totalCommits);
          }
        }
        continue;
      }

      // Parse file path
      if (line.startsWith('diff --git a/')) {
        const match = /^diff --git a\/(.*) b\//.exec(line);
        if (match?.[1]) {
          currentFilePath = match[1];
          isBinaryFile = false;
          shouldSkipCurrentFile = shouldSkipPath(currentFilePath);
          contextBuffer.length = 0;
        }
        continue;
      }

      // Check for binary files
      if (line.includes('Binary files')) {
        isBinaryFile = true;
        continue;
      }

      // Skip binary and excluded files
      if (isBinaryFile || shouldSkipCurrentFile) {
        continue;
      }

      // Parse line numbers from hunk header
      if (line.startsWith('@@')) {
        const match = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(line);
        if (match?.[1]) {
          currentLineNumber = parseInt(match[1], 10);
        }
        contextBuffer.length = 0;
        continue;
      }

      // Only process added lines (starting with +, not +++)
      if (line.startsWith('+') && !line.startsWith('+++')) {
        const addedLine = line.slice(1);
        currentLineNumber++;

        // Add to context buffer
        contextBuffer.push(addedLine);
        if (contextBuffer.length > CONTEXT_SIZE) {
          contextBuffer.shift();
        }

        // Keyword pre-filter
        const lineLower = addedLine.toLowerCase();
        const matchingPatterns = SECRET_PATTERNS.filter(pattern =>
          pattern.keywords.some(keyword => lineLower.includes(keyword))
        );

        // Run patterns
        for (const pattern of matchingPatterns) {
          const match = pattern.regex.exec(addedLine);
          if (!match?.[1]) continue;

          let secretValue: string = match[1] ?? '';

          // For entropy-based patterns, validate entropy
          if (pattern.entropyThreshold !== undefined) {
            const entropy = calculateEntropy(secretValue);
            if (entropy < pattern.entropyThreshold) {
              continue;
            }
          }

          // Filter out known false positives
          if (isKnownFalsePositive(secretValue)) {
            continue;
          }

          // Deduplicate
          const dedupeKey = makeDedupeKey(pattern.id, secretValue);
          if (seen.has(dedupeKey)) {
            continue;
          }
          seen.add(dedupeKey);

          // Build context (with secrets stripped)
          const contextLines = contextBuffer.slice().map(line => {
            // Redact any secrets from context
            for (const p of SECRET_PATTERNS) {
              line = line.replace(p.regex, '[REDACTED]');
            }
            return line;
          });

          findings.push({
            patternId: pattern.id,
            patternName: pattern.name,
            severity: pattern.severity,
            secretCategory: pattern.secretCategory,
            commitHash: currentCommitHash,
            commitDate: currentCommitDate,
            authorName: currentAuthorName,
            authorEmail: currentAuthorEmail,
            filePath: currentFilePath,
            lineNumber: currentLineNumber,
            matchedValue: redactSecret(secretValue),
            fullMatchedValue: secretValue,
            contextLines,
            dedupeKey,
          });
        }
      } else if (line.startsWith('-') && !line.startsWith('---')) {
        // Removed lines: still track context
        currentLineNumber--;
      } else if (!line.startsWith('-') && !line.startsWith('+')) {
        // Context lines
        currentLineNumber++;
        contextBuffer.push(line);
        if (contextBuffer.length > CONTEXT_SIZE * 2) {
          contextBuffer.shift();
        }
      }
    }

    return findings;
  } finally {
    // Cleanup
    try {
      await fs.rm(cloneDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  }
}

// Startup cleanup: remove orphaned tmp directories
export async function cleanupOrphanedTempDirs(): Promise<void> {
  try {
    const tmpDir = os.tmpdir();
    const entries = await fs.readdir(tmpDir);
    const now = Date.now();
    const oneHourAgo = now - 3600000; // 1 hour

    for (const entry of entries) {
      if (!entry.startsWith('usp-git-')) continue;
      const fullPath = path.join(tmpDir, entry);
      try {
        const stat = await fs.stat(fullPath);
        if (stat.mtimeMs < oneHourAgo && stat.isDirectory()) {
          await fs.rm(fullPath, { recursive: true, force: true });
        }
      } catch {
        // Skip if can't stat or remove
      }
    }
  } catch {
    // Ignore cleanup errors
  }
}

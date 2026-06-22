// githubService.js
// Responsible for ALL communication with the GitHub REST API.
// No business logic here — pure data fetching and transformation.
// All functions throw AppError on failure so the pipeline
// can handle errors consistently.

import axios from 'axios';
import { config } from '../config/index.js';
import { AppError } from '../utils/AppError.js';

// ─────────────────────────────────────────────
// 1. AXIOS INSTANCE
// Configured once, used for every GitHub API call.
// ─────────────────────────────────────────────

const githubClient = axios.create({
  baseURL: 'https://api.github.com',

  // Timeout: 10 seconds per request.
  // Without this, a slow GitHub response hangs your pipeline forever.
  // 10s is generous — most GitHub API calls resolve in <500ms.
  timeout: 10000,

  headers: {
    // GitHub requires Accept header for their REST API v3
    'Accept': 'application/vnd.github+json',

    // Authentication: Personal Access Token
    // Gives us 5,000 requests/hour instead of 60
    'Authorization': `Bearer ${config.githubToken}`,

    // Recommended by GitHub to specify API version
    'X-GitHub-Api-Version': '2022-11-28',
  }
});

// ─────────────────────────────────────────────
// 2. RESPONSE INTERCEPTOR — Error Normalization
// Transforms GitHub API errors into our AppError format
// before they reach the service functions.
// ─────────────────────────────────────────────

githubClient.interceptors.response.use(
  // Success handler — pass through unchanged
  (response) => response,

  // Error handler — normalize GitHub errors
  (error) => {
    // No response at all = network error or timeout
    if (!error.response) {
      throw new AppError(
        'Failed to connect to GitHub API. Please try again.',
        503,
        'GITHUB_UNREACHABLE'
      );
    }

    const { status, data } = error.response;

    // 401 — Bad or expired token (our problem, not user's)
    if (status === 401) {
      throw new AppError(
        'GitHub API authentication failed. Please check server configuration.',
        500,
        'GITHUB_AUTH_FAILED'
      );
    }

    // 403 — Could be rate limit OR permission denied
    if (status === 403) {
      // GitHub rate limit returns 403 with this specific message
      if (data?.message?.includes('rate limit')) {
        throw new AppError(
          'GitHub API rate limit exceeded. Please try again later.',
          429,
          'GITHUB_RATE_LIMITED'
        );
      }
      // Otherwise it's an access/permission issue
      throw new AppError(
        'Access to this repository is forbidden. It may be private.',
        403,
        'GITHUB_ACCESS_DENIED'
      );
    }

    // 404 — Repo or resource doesn't exist
    if (status === 404) {
      throw new AppError(
        'Repository not found. Please check the URL and ensure the repository is public.',
        404,
        'REPO_NOT_FOUND'
      );
    }

    // 422 — Unprocessable (often means tree is too large)
    if (status === 422) {
      throw new AppError(
        'Repository structure could not be processed. It may be too large.',
        422,
        'REPO_UNPROCESSABLE'
      );
    }

    // All other GitHub errors
    throw new AppError(
      `GitHub API error: ${data?.message || 'Unknown error'}`,
      status || 500,
      'GITHUB_API_ERROR'
    );
  }
);

// ─────────────────────────────────────────────
// 3. RETRY UTILITY
// Retries a function with exponential backoff.
// Only retries on transient/server errors.
// ─────────────────────────────────────────────

const RETRYABLE_CODES = ['GITHUB_UNREACHABLE'];
const MAX_RETRIES = 3;

async function withRetry(fn, retries = MAX_RETRIES) {
  try {
    return await fn();
  } catch (err) {
    // Only retry if it's a transient error AND we have retries left
    const isRetryable = RETRYABLE_CODES.includes(err.code);
    const hasRetriesLeft = retries > 0;

    if (isRetryable && hasRetriesLeft) {
      // Exponential backoff: 1s, 2s, 4s
      const delay = Math.pow(2, MAX_RETRIES - retries) * 1000;
      console.log(`[github] Retrying in ${delay}ms... (${retries} attempts left)`);
      await new Promise(resolve => setTimeout(resolve, delay));
      return withRetry(fn, retries - 1);
    }

    // Not retryable or out of retries — rethrow
    throw err;
  }
}

// ─────────────────────────────────────────────
// 4. BATCH CONCURRENCY UTILITY
// Processes an array in chunks of `batchSize`,
// executing each chunk concurrently.
// Prevents hammering GitHub with 150 simultaneous requests.
// ─────────────────────────────────────────────

async function processBatch(items, batchSize, asyncFn) {
  const results = [];

  for (let i = 0; i < items.length; i += batchSize) {
    // Slice out the current batch
    const batch = items.slice(i, i + batchSize);

    // Run all items in this batch concurrently
    const batchResults = await Promise.all(batch.map(asyncFn));
    results.push(...batchResults);

    console.log(`[github] Fetched batch ${Math.ceil((i + batchSize) / batchSize)} — ${results.length}/${items.length} files`);
  }

  return results;
}

// ─────────────────────────────────────────────
// 5. SERVICE FUNCTIONS
// Each function maps to one GitHub API endpoint.
// Each is independently callable and testable.
// ─────────────────────────────────────────────

/**
 * Fetches repository metadata.
 * Used to validate the repo exists and get the default branch.
 *
 * @param {string} owner
 * @param {string} repo
 * @returns {{ defaultBranch: string, fullName: string, description: string }}
 */
export async function getRepoMetadata(owner, repo) {
  console.log(`[github] Fetching metadata for ${owner}/${repo}`);

  const response = await withRetry(() =>
    githubClient.get(`/repos/${owner}/${repo}`)
  );

  const { data } = response;

  // Extract only what we need — don't pass the entire
  // GitHub response object downstream (it's huge and
  // contains fields we'll never use)
  return {
    defaultBranch: data.default_branch,
    fullName: data.full_name,          // "facebook/react"
    description: data.description,
    isPrivate: data.private,
    stars: data.stargazers_count,
    language: data.language,           // primary language
  };
}

/**
 * Fetches the root tree SHA for a given branch.
 * This SHA is the entry point for the recursive tree fetch.
 *
 * @param {string} owner
 * @param {string} repo
 * @param {string} branch
 * @returns {string} — the root tree SHA
 */
export async function getTreeSha(owner, repo, branch) {
  console.log(`[github] Fetching tree SHA for branch: ${branch}`);

  const response = await withRetry(() =>
    githubClient.get(`/repos/${owner}/${repo}/branches/${branch}`)
  );

  // Navigation: branch → commit → tree → sha
  // This nested path reflects GitHub's actual response structure
  const treeSha = response.data?.commit?.commit?.tree?.sha;

  if (!treeSha) {
    throw new AppError(
      'Could not resolve repository tree. Branch data is malformed.',
      500,
      'TREE_SHA_NOT_FOUND'
    );
  }

  return treeSha;
}

/**
 * Fetches the complete recursive file tree of the repository.
 * Returns a flat array of all tree nodes (files and folders).
 *
 * @param {string} owner
 * @param {string} repo
 * @param {string} treeSha
 * @returns {Array<{ path: string, type: string, sha: string, size: number }>}
 */
export async function getRepoTree(owner, repo, treeSha) {
  console.log(`[github] Fetching full repository tree (sha: ${treeSha})`);

  const response = await withRetry(() =>
    githubClient.get(`/repos/${owner}/${repo}/git/trees/${treeSha}`, {
      params: { recursive: '1' }
      // Using params object instead of query string in URL —
      // axios handles encoding, preventing injection via URL
    })
  );

  const { tree, truncated } = response.data;

  // CRITICAL: Truncated means we did NOT receive the full tree.
  // A security tool that silently analyzes partial code is
  // worse than one that refuses — it gives false confidence.
  if (truncated) {
    throw new AppError(
      'Repository is too large to scan. The file tree exceeds GitHub\'s limits.',
      422,
      'REPO_TOO_LARGE'
    );
  }

  console.log(`[github] Tree fetched: ${tree.length} total entries`);

  return tree;
  // Each entry shape:
  // { path: "src/app.js", type: "blob", sha: "abc123", size: 1205 }
  // { path: "src",        type: "tree", sha: "def456" }
}

/**
 * Fetches the decoded content of a single file blob.
 *
 * @param {string} owner
 * @param {string} repo
 * @param {string} sha - The blob SHA from the tree
 * @param {string} path - File path (for logging only)
 * @returns {string} — decoded file content
 */
export async function getFileContent(owner, repo, sha, path) {
  const response = await withRetry(() =>
    githubClient.get(`/repos/${owner}/${repo}/git/blobs/${sha}`)
  );

  const { content, encoding } = response.data;

  // GitHub always returns blob content as base64
  if (encoding !== 'base64') {
    throw new AppError(
      `Unexpected blob encoding: ${encoding}`,
      500,
      'UNEXPECTED_ENCODING'
    );
  }

  // Decode base64 → UTF-8 string
  // Buffer is a Node.js built-in — no import needed
  const decoded = Buffer.from(content, 'base64').toString('utf-8');

  return decoded;
}

/**
 * Fetches content for multiple files using batched concurrency.
 * This is the bulk operation — called with the filtered file list.
 *
 * @param {string} owner
 * @param {string} repo
 * @param {Array<{ path: string, sha: string }>} files
 * @returns {Array<{ path: string, content: string }>}
 */
export async function getBulkFileContents(owner, repo, files) {
  console.log(`[github] Fetching content for ${files.length} files (batch size: 10)`);

  const results = await processBatch(files, 10, async (file) => {
    try {
      const content = await getFileContent(owner, repo, file.sha, file.path);
      return { path: file.path, content };
    } catch (err) {
      // Individual file failure should NOT abort the entire scan.
      // Log it and return null — the pipeline will filter these out.
      console.warn(`[github] Failed to fetch ${file.path}: ${err.message}`);
      return null;
    }
  });

  // Filter out files that failed to fetch
  const successful = results.filter(Boolean);
  console.log(`[github] Successfully fetched ${successful.length}/${files.length} files`);

  return successful;
}
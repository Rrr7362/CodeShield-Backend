// urlParser.js
// Pure function — takes a string, returns { owner, repo }
// or throws an AppError.
//
// "Pure" means:
//   - No side effects (no API calls, no logging, no DB writes)
//   - Same input always produces same output
//   - Independently unit testable without mocking anything

import { AppError } from './AppError.js';

// The list of valid error codes for this module.
// Defined as constants — never use magic strings.
const ERROR_CODES = {
  MISSING_URL:         'MISSING_URL',
  INVALID_GITHUB_URL:  'INVALID_GITHUB_URL',
  MISSING_REPO_PATH:   'MISSING_REPO_PATH',
};

// /**
//  * Parses a GitHub repository URL and extracts owner and repo name.
//  *
//  * @param {string} rawUrl - The raw URL string from the user
//  * @returns {{ owner: string, repo: string }}
//  * @throws {AppError} if the URL is invalid or not a GitHub repo URL
//  */
export function parseGithubUrl(rawUrl) {

  // --- Step 1: Presence check ---
  // Check for null, undefined, empty string, whitespace-only
  if (!rawUrl || typeof rawUrl !== 'string' || !rawUrl.trim()) {
    throw new AppError(
      'GitHub URL is required.',
      400,
      ERROR_CODES.MISSING_URL
    );
  }

  // Normalize: trim whitespace from both ends
  // Handles the case where users paste URLs with leading/trailing spaces
  const trimmedUrl = rawUrl.trim();

  // --- Step 2: Structural parsing ---
  // Use the URL constructor for semantic parsing.
  // This handles protocol validation, hostname extraction, and
  // pathname parsing correctly without fragile regex.
  let parsedUrl;
  try {
    parsedUrl = new URL(trimmedUrl);
  } catch {
    // URL constructor throws if the string is not a valid URL at all
    throw new AppError(
      'The provided string is not a valid URL.',
      400,
      ERROR_CODES.INVALID_GITHUB_URL
    );
  }

  // --- Step 3: Domain validation ---
  // We only accept github.com — not gitlab, bitbucket,
  // or GitHub Enterprise instances (scope decision for v1)
  if (parsedUrl.hostname !== 'github.com') {
    throw new AppError(
      'Only GitHub repositories are supported. Please provide a github.com URL.',
      400,
      ERROR_CODES.INVALID_GITHUB_URL
    );
  }

  // --- Step 4: Path segmentation ---
  // parsedUrl.pathname for "https://github.com/facebook/react/tree/main"
  // is "/facebook/react/tree/main"
  //
  // Split on "/" gives: ["", "facebook", "react", "tree", "main"]
  // Index 0 is always "" (the leading slash)
  // Index 1 is owner
  // Index 2 is repo (may have .git suffix)
  // Index 3+ is extra path we ignore
  const segments = parsedUrl.pathname
    .split('/')
    .filter(segment => segment.length > 0);
  // filter removes the empty string from the leading slash
  // Result: ["facebook", "react", "tree", "main"]

  // --- Step 5: Owner and repo extraction ---
  const owner = segments[0];
  let repo  = segments[1];

  // Must have both owner and repo
  if (!owner || !repo) {
    throw new AppError(
      'URL must point to a specific repository (e.g. https://github.com/owner/repo).',
      400,
      ERROR_CODES.MISSING_REPO_PATH
    );
  }

  // --- Step 6: Clean the repo name ---
  // Remove .git suffix: "react.git" → "react"
  // Some tools and users append .git when copying clone URLs
  repo = repo.replace(/\.git$/, '');

  // At this point we have clean, validated owner and repo strings.
  // Everything after segments[1] (branch names, file paths,
  // issue numbers) is intentionally discarded.

  return { owner, repo };
}
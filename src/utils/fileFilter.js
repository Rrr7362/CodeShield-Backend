// fileFilter.js
// Responsible for:
//   1. Extension-based allow listing
//   2. Path-based exclusion (node_modules, dist, etc.)
//   3. File size limiting
//   4. Token budget enforcement
//   5. Security-priority ordering

// ─────────────────────────────────────────────
// CONFIGURATION CONSTANTS
// All thresholds in one place for easy tuning
// ─────────────────────────────────────────────

// Approximate token budget for file content
// Total Gemini context: 1,000,000 tokens
// Reserved for prompt + response: ~13,000 tokens
// Available for code: ~987,000 — we target 800,000 (safe buffer)
const TOKEN_BUDGET = 800_000;

// Approximate chars per token (industry standard approximation)
const CHARS_PER_TOKEN = 4;

// Max characters per individual file before truncation
// 10,000 chars ≈ 2,500 tokens — enough for most source files
const MAX_FILE_CHARS = 10_000;

// Max number of files to include regardless of token budget
// Prevents extremely large repos from processing indefinitely
const MAX_FILE_COUNT = 100;

// ─────────────────────────────────────────────
// ALLOW LIST — Extensions we actively want
// Organized by priority tier for sorting later
// ─────────────────────────────────────────────

const PRIORITY = {
  CRITICAL: 1,   // Security-sensitive config files
  HIGH: 2,       // Core source code
  MEDIUM: 3,     // Supporting files
  LOW: 4,        // Documentation etc.
};

// Maps extension → priority tier
const ALLOWED_EXTENSIONS = {
  // ── Tier 1: Security-critical config files ──
  '.env':          PRIORITY.CRITICAL,
  '.env.example':  PRIORITY.CRITICAL,  // reveals expected secret names
  '.env.sample':   PRIORITY.CRITICAL,

  // ── Tier 2: Core source code ──
  '.js':           PRIORITY.HIGH,
  '.jsx':          PRIORITY.HIGH,
  '.ts':           PRIORITY.HIGH,
  '.tsx':          PRIORITY.HIGH,
  '.py':           PRIORITY.HIGH,
  '.java':         PRIORITY.HIGH,
  '.go':           PRIORITY.HIGH,
  '.rb':           PRIORITY.HIGH,
  '.php':          PRIORITY.HIGH,
  '.cs':           PRIORITY.HIGH,      // C#
  '.cpp':          PRIORITY.HIGH,      // C++
  '.c':            PRIORITY.HIGH,
  '.rs':           PRIORITY.HIGH,      // Rust
  '.swift':        PRIORITY.HIGH,
  '.kt':           PRIORITY.HIGH,      // Kotlin
  '.scala':        PRIORITY.HIGH,

  // ── Tier 3: Configuration & infrastructure ──
  '.json':         PRIORITY.MEDIUM,
  '.yaml':         PRIORITY.MEDIUM,
  '.yml':          PRIORITY.MEDIUM,
  '.xml':          PRIORITY.MEDIUM,
  '.toml':         PRIORITY.MEDIUM,
  '.ini':          PRIORITY.MEDIUM,
  '.cfg':          PRIORITY.MEDIUM,
  '.conf':         PRIORITY.MEDIUM,
  '.config':       PRIORITY.MEDIUM,
  '.sh':           PRIORITY.MEDIUM,    // shell scripts
  '.bash':         PRIORITY.MEDIUM,
  '.zsh':          PRIORITY.MEDIUM,
  '.dockerfile':   PRIORITY.MEDIUM,
  '.sql':          PRIORITY.MEDIUM,    // raw SQL = injection risk

  // ── Tier 4: Documentation ──
  '.md':           PRIORITY.LOW,
  '.txt':          PRIORITY.LOW,
};

// ─────────────────────────────────────────────
// DENY LIST — Path patterns to always exclude
// Even if extension is in allow list
// ─────────────────────────────────────────────

// These are checked as substring matches against the full file path
const EXCLUDED_PATH_SEGMENTS = [
  'node_modules/',
  '.git/',
  'dist/',
  'build/',
  '.next/',
  '.nuxt/',
  'coverage/',
  '__snapshots__/',
  '.cache/',
  'vendor/',
  '.gradle/',
  'target/',          // Java/Maven build output
  '__pycache__/',     // Python bytecode
  '.pytest_cache/',
  'venv/',            // Python virtual environment
  'env/',             // Python virtual environment (common alias)
  '.venv/',
];

// Specific filenames to exclude regardless of path
const EXCLUDED_FILENAMES = [
  'package-lock.json',  // 50k+ lines, zero security signal
  'yarn.lock',
  'pnpm-lock.yaml',
  'composer.lock',      // PHP
  'Gemfile.lock',       // Ruby
  'poetry.lock',        // Python
  'go.sum',             // Go
  'Cargo.lock',         // Rust
];

// File patterns to exclude (checked against filename)
const EXCLUDED_FILENAME_PATTERNS = [
  /\.min\.(js|css)$/,   // minified files
  /\.bundle\.js$/,      // webpack bundles
  /\.map$/,             // source maps
  /\.chunk\.js$/,       // code-split chunks
];

// ─────────────────────────────────────────────
// CORE FILTER FUNCTIONS
// ─────────────────────────────────────────────

/**
 * Determines if a tree node should be included in the scan.
 * Returns true if the file passes all filter criteria.
 *
 * @param {{ path: string, type: string }} node - GitHub tree node
 * @returns {boolean}
 */
function shouldIncludeFile(node) {
  // Only process blobs (files), not trees (directories)
  if (node.type !== 'blob') return false;

  const filePath = node.path.toLowerCase();
  const fileName = filePath.split('/').pop();

  // ── Check 1: Excluded path segments ──
  // If any excluded segment appears anywhere in the path, reject
  for (const segment of EXCLUDED_PATH_SEGMENTS) {
    if (filePath.includes(segment)) return false;
  }

  // ── Check 2: Excluded filenames ──
  if (EXCLUDED_FILENAMES.includes(fileName)) return false;

  // ── Check 3: Excluded filename patterns ──
  for (const pattern of EXCLUDED_FILENAME_PATTERNS) {
    if (pattern.test(fileName)) return false;
  }

  // ── Check 4: Extension allow list ──
  // Get the extension from the original path (not lowercased,
  // for case-sensitive matching on the allow list lookup,
  // though we lowercase the key for comparison)
  const ext = getExtension(node.path);

  // Special case: files starting with dot are their own "extension"
  // e.g. ".env", ".gitignore", "Dockerfile" (no extension)
  const lookupKey = ext.toLowerCase();

  // Check if this extension is in our allow list
  if (!ALLOWED_EXTENSIONS.hasOwnProperty(lookupKey)) {
    // Special case: Dockerfile has no extension
    // Check the filename itself
    if (fileName === 'dockerfile') return true;
    return false;
  }

  return true;
}

/**
 * Gets the priority tier of a file for sorting.
 * Lower number = higher priority = processed first.
 *
 * @param {string} filePath
 * @returns {number}
 */
function getFilePriority(filePath) {
  const ext = getExtension(filePath).toLowerCase();
  return ALLOWED_EXTENSIONS[ext] || PRIORITY.LOW;
}

/**
 * Extracts file extension from path.
 * Handles dotfiles like .env correctly.
 *
 * @param {string} filePath
 * @returns {string}
 */
function getExtension(filePath) {
  const filename = filePath.split('/').pop();
  const dotIndex = filename.lastIndexOf('.');

  if (dotIndex <= 0) {
    // No extension, or dotfile like ".env"
    if (filename.startsWith('.')) return filename;
    return '';
  }

  return filename.slice(dotIndex);
}

// ─────────────────────────────────────────────
// MAIN EXPORT
// ─────────────────────────────────────────────

/**
 * Filters a GitHub repository tree to a prioritized list
 * of scannable source files.
 *
 * Pipeline:
 *   1. Filter by extension allow list + path deny list
 *   2. Sort by security priority (critical files first)
 *   3. Cap at MAX_FILE_COUNT
 *   4. Return filtered list (content not loaded yet)
 *
 * Note: Token budget enforcement happens in tokenOptimizer.js
 * AFTER content is loaded — because we need content length
 * to count tokens accurately.
 *
 * @param {Array<{ path: string, type: string, sha: string }>} tree
 * @returns {Array<{ path: string, sha: string, priority: number }>}
 */
export function filterFiles(tree) {
  // Step 1: Apply all filter criteria
  const eligible = tree.filter(shouldIncludeFile);

  console.log(`[filter] ${tree.length} total entries → ${eligible.length} eligible files`);

  // Step 2: Sort by priority (security-critical files first)
  // Within same priority, sort alphabetically for determinism
  const sorted = eligible.sort((a, b) => {
    const priorityA = getFilePriority(a.path);
    const priorityB = getFilePriority(b.path);

    if (priorityA !== priorityB) return priorityA - priorityB;
    return a.path.localeCompare(b.path);
  });

  // Step 3: Cap at MAX_FILE_COUNT
  // We take the highest priority files up to the limit
  const capped = sorted.slice(0, MAX_FILE_COUNT);

  if (sorted.length > MAX_FILE_COUNT) {
    console.log(
      `[filter] Capped at ${MAX_FILE_COUNT} files ` +
      `(${sorted.length - MAX_FILE_COUNT} lower-priority files excluded)`
    );
  }

  return capped;
}

// ─────────────────────────────────────────────
// TOKEN OPTIMIZER — Applied after content loaded
// ─────────────────────────────────────────────

/**
 * Applies token budget enforcement and per-file truncation
 * to the files array AFTER content has been downloaded.
 *
 * This is a separate step from filterFiles() because:
 *   filterFiles() works on tree nodes (no content yet)
 *   optimizeTokens() works on file content (after download)
 *
 * @param {Array<{ path: string, extension: string, content: string }>} files
 * @returns {Array<{ path: string, extension: string, content: string }>}
 */
export function optimizeTokens(files) {
  const results = [];
  let totalTokens = 0;

  for (const file of files) {
    // Step 1: Per-file truncation
    let content = file.content;

    if (content.length > MAX_FILE_CHARS) {
      console.log(
        `[tokens] Truncating ${file.path}: ` +
        `${content.length} → ${MAX_FILE_CHARS} chars`
      );
      content = content.slice(0, MAX_FILE_CHARS) +
        '\n// [CODESHIELD: File truncated due to size limit]';
    }

    // Step 2: Token budget check
    const fileTokens = Math.ceil(content.length / CHARS_PER_TOKEN);

    if (totalTokens + fileTokens > TOKEN_BUDGET) {
      console.log(
        `[tokens] Budget reached at ${totalTokens} tokens. ` +
        `Skipping remaining ${files.length - results.length} files.`
      );
      break;
    }

    totalTokens += fileTokens;
    results.push({ ...file, content });
  }

  console.log(
    `[tokens] Final: ${results.length} files, ` +
    `~${totalTokens.toLocaleString()} tokens ` +
    `(budget: ${TOKEN_BUDGET.toLocaleString()})`
  );

  return results;
  // new code for logggg
  console.log(
  "Finish reason:",
  result.response.candidates?.[0]?.finishReason
);

console.log(
  "Output chars:",
  rawText.length
);

console.log(
  "Findings count:",
  parsed.vulnerabilities?.length
);
}

/**
 * Calculates approximate token count for an array of files.
 * Useful for logging and monitoring.
 *
 * @param {Array<{ content: string }>} files
 * @returns {number}
 */
export function estimateTokenCount(files) {
  const totalChars = files.reduce((sum, f) => sum + f.content.length, 0);
  return Math.ceil(totalChars / CHARS_PER_TOKEN);
}
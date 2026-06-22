// scanService.js
// The pipeline orchestrator.
// Coordinates every stage of the scan in sequence.
// Emits Socket.IO progress events at each transition.
// Owns the error handling strategy for each stage.

import { v4 as uuidv4 } from 'uuid';
import { getIO, registerScan, deregisterScan } from '../socket/socketManager.js';
import { parseGithubUrl } from '../utils/urlParser.js';
import { filterFiles, optimizeTokens, estimateTokenCount } from '../utils/fileFilter.js';  // Phase 7
import {
  getRepoMetadata,
  getTreeSha,
  getRepoTree,
  getBulkFileContents
} from './githubService.js';
import { analyzeWithGemini } from './geminiService.js'; // Phase 8
import { AppError } from '../utils/AppError.js';

// ─────────────────────────────────────────────
// PROGRESS EMITTER
// Central function for emitting progress events.
// Keeps event shape consistent across all stages.
// ─────────────────────────────────────────────

// Temporary stubs — add at top of scanService.js for testing
// const filterFiles = (tree) => tree.filter(n => n.type === 'blob').slice(0, 5);
// const analyzeWithGemini = async (files) => ({
//   summary: { critical: 0, high: 1, medium: 2, low: 1 },
//   vulnerabilities: []
// });

function emitProgress(scanId, stage, message, progress) {
  const io = getIO();
  io.to(scanId).emit('scan-progress', {
    scanId,
    stage,
    message,
    progress,
    timestamp: new Date().toISOString(),
  });
  // Also log server-side for observability
  console.log(`[scan:${scanId}] [${progress}%] ${message}`);
}

function emitError(scanId, error) {
  const io = getIO();
  io.to(scanId).emit('scan-error', {
    scanId,
    error: {
      code: error.code || 'SCAN_FAILED',
      message: error.message,
    },
    timestamp: new Date().toISOString(),
  });
  console.error(`[scan:${scanId}] ERROR — ${error.code}: ${error.message}`);
}

function emitCompleted(scanId, report) {
  const io = getIO();
  io.to(scanId).emit('scan-completed', {
    scanId,
    report,
    timestamp: new Date().toISOString(),
  });
  console.log(`[scan:${scanId}] Scan completed successfully`);
}

// ─────────────────────────────────────────────
// THE PIPELINE
// ─────────────────────────────────────────────

/**
 * Executes the full repository security scan pipeline.
 *
 * @param {string} githubUrl - Raw URL from the client
 * @returns {{ scanId: string }} - Returned immediately to HTTP caller
 *
 * NOTE: This function is intentionally NOT fully awaited by the controller.
 * The controller gets the scanId immediately and returns HTTP 202 Accepted.
 * The pipeline runs asynchronously and communicates via Socket.IO.
 */// OLd code 
// export async function startScan(githubUrl) {
//   // Generate unique scan ID — this is our correlation ID
//   // for the entire lifecycle of this scan
//   const scanId = uuidv4();
//   const io = getIO();

//   // Emit started event immediately
//   io.to(scanId).emit('scan-started', {
//     scanId,
//     timestamp: new Date().toISOString(),
//   });

//   // Run pipeline asynchronously.
//   // We don't await this — the HTTP response returns scanId
//   // while this runs in the background.
//   // Errors are caught internally and emitted via socket.
//   runPipeline(scanId, githubUrl).catch((err) => {
//     // This catch handles any error that escapes runPipeline's
//     // internal error handling — a last-resort safety net
//     console.error(`[scan:${scanId}] Unhandled pipeline error:`, err);
//     emitError(scanId, err);
//   });

//   // Return scanId immediately to the HTTP caller
//   // HTTP response: 202 Accepted (request received, processing async)
//   return { scanId };
// }

// Update startScan() to register the scan:
// NEW CODE
export async function startScan(githubUrl) {
  const scanId = uuidv4();

  // Register scan for lifecycle tracking
  registerScan(scanId);

  const io = getIO();
  io.to(scanId).emit('scan-started', {
    scanId,
    timestamp: new Date().toISOString(),
  });

  runPipeline(scanId, githubUrl).catch((err) => {
    console.error(`[scan:${scanId}] Unhandled pipeline error:`, err);
    emitError(scanId, err);
    deregisterScan(scanId); // cleanup on error
  });

  return { scanId };
}

/**
 * The actual pipeline — runs all stages in sequence.
 * All errors are caught here and emitted via socket.
 * Never throws to the caller — communicates via events instead.
 */
async function runPipeline(scanId, githubUrl) {
  try {

    // ── STAGE 1: Parse & Validate URL ──────────────────────
    emitProgress(scanId, 'parsing', 'Validating repository URL...', 10);

    const { owner, repo } = parseGithubUrl(githubUrl);
    // If this throws, the catch block emits scan-error and stops.

    // ── STAGE 2: Fetch Repository Metadata ─────────────────
    emitProgress(scanId, 'metadata', 'Connecting to GitHub...', 20);

    const metadata = await getRepoMetadata(owner, repo);

    // Emit started with full repo context now that we have it
    const io = getIO();
    io.to(scanId).emit('scan-started', {
      scanId,
      repository: metadata.fullName,
      description: metadata.description,
      language: metadata.language,
      timestamp: new Date().toISOString(),
    });

    // ── STAGE 3: Resolve Tree SHA ───────────────────────────
    emitProgress(scanId, 'resolving', `Resolving ${metadata.defaultBranch} branch...`, 30);

    const treeSha = await getTreeSha(owner, repo, metadata.defaultBranch);

    // ── STAGE 4: Fetch Complete File Tree ───────────────────
    emitProgress(scanId, 'fetching-tree', 'Fetching repository file tree...', 40);

    const tree = await getRepoTree(owner, repo, treeSha);

    // ── STAGE 5: Filter Files ───────────────────────────────
    emitProgress(scanId, 'filtering', 'Filtering source files...', 50);

    const filteredFiles = filterFiles(tree);
    // filterFiles is implemented in Phase 7

    // Guard: if no scannable files found, abort with clear message
    if (filteredFiles.length === 0) {
      throw new AppError(
        'No scannable source files found in this repository. ' +
        'CodeShield supports JavaScript, TypeScript, Python, and other source files.',
        422,
        'NO_SCANNABLE_FILES'
      );
    }

    emitProgress(
      scanId,
      'filtering',
      `Found ${filteredFiles.length} files to analyze...`,
      55
    );

    // ── STAGE 6: Download File Contents ────────────────────
    emitProgress(
      scanId,
      'downloading',
      `Downloading ${filteredFiles.length} source files...`,
      60
    );

    const fileContents = await getBulkFileContents(owner, repo, filteredFiles);

    // Guard: if we couldn't fetch any files at all, abort
    if (fileContents.length === 0) {
      throw new AppError(
        'Failed to download repository source files.',
        500,
        'FILE_DOWNLOAD_FAILED'
      );
    }

    // Build the in-memory file array with extensions
    const rawFiles = fileContents.map(file => ({
      path: file.path,
      extension: getExtension(file.path),
      content: file.content,
    }));

    // ── STAGE 6b: Token Optimization ───────────────────────
    // Apply per-file truncation and token budget enforcement.
    // Files are already sorted by priority from filterFiles(),
    // so the most security-relevant files survive budget cuts.
    emitProgress(
      scanId,
      'optimizing',
      'Optimizing files for AI analysis...',
      68
    );

    const files = optimizeTokens(rawFiles);
    const estimatedTokens = estimateTokenCount(files);

    emitProgress(
      scanId,
      'downloaded',
      `Prepared ${files.length} files (~${estimatedTokens.toLocaleString()} tokens). Starting security analysis...`,
      70
    );

    // ── STAGE 7: Gemini Analysis ────────────────────────────
    emitProgress(
      scanId,
      'analyzing',
      'Running AI-powered security analysis (this may take 20–30 seconds)...',
      75
    );

    const report = await analyzeWithGemini(files, metadata);
    // analyzeWithGemini is implemented in Phase 8

    // ── STAGE 8: Finalize & Emit Report ────────────────────
    emitProgress(scanId, 'finalizing', 'Finalizing security report...', 95);

    // Attach metadata to the report
    const finalReport = {
      scanId,
      repository: metadata.fullName,
      description: metadata.description,
      language: metadata.language,
      scannedFiles: files.length,
      ...report,
      scannedAt: new Date().toISOString(),
    };

    emitCompleted(scanId, finalReport);
    deregisterScan(scanId); // cleanup on success
    return finalReport;

    // Return the report — the controller will also send this
    // in the HTTP response for clients that poll instead of
    // using sockets (progressive enhancement)

  } catch (err) {
    // All stage failures land here.
    // Emit the error via socket so the client can display it.
    emitError(scanId, err);
    deregisterScan(scanId); // cleanup on error
    // Re-throw so the outer .catch() in startScan can log it
    throw err;
  }
}

// ─────────────────────────────────────────────
// UTILITY
// ─────────────────────────────────────────────

/**
 * Extracts the file extension from a path.
 * Returns empty string if no extension found.
 *
 * Examples:
 *   "src/app.js"        → ".js"
 *   "config/.env"       → ".env"
 *   "Dockerfile"        → ""
 *   "src/utils/index.ts"→ ".ts"
 */
function getExtension(filePath) {
  // path.extname would work here too, but keeping it
  // dependency-free with a simple string operation
  const filename = filePath.split('/').pop();   // get filename
  const dotIndex = filename.lastIndexOf('.');

  // No dot, or dot is first character (hidden file like .gitignore)
  if (dotIndex <= 0) {
    // Special case: files starting with dot ARE their own extension
    // ".env", ".gitignore" should return ".env", ".gitignore"
    if (filename.startsWith('.')) {
      return filename; // the whole filename is the "extension"
    }
    return '';
  }

  return filename.slice(dotIndex); // includes the dot: ".js"
}
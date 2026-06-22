// /server/src/controllers/scanController.js

import { startScan } from '../services/scanService.js';
import { AppError } from '../utils/AppError.js';

/**
 * POST /api/analyze
 *
 * Controller responsibilities (and ONLY these):
 *   1. Extract githubUrl from request body
 *   2. Validate presence (not format — that's the service's job)
 *   3. Call the service
 *   4. Format and send the HTTP response
 *   5. Pass errors to next() for global error handler
 */
export async function analyzeRepo(req, res, next) {
  try {
    // Step 1: Extract from request
    const { githubUrl } = req.body;

    // Step 2: Presence check only
    // Format validation (is it a valid GitHub URL?) happens
    // inside scanService → parseGithubUrl()
    // The controller only checks: did the client send anything?
    if (!githubUrl) {
      throw new AppError(
        'githubUrl is required in the request body.',
        400,
        'MISSING_GITHUB_URL'
      );
    }

    // Step 3: Delegate to service
    // Controller has NO idea what happens inside startScan()
    // It just calls it and trusts the output
    const { scanId } = await startScan(githubUrl);

    // Step 4: Format HTTP response
    // 202 Accepted = request received, processing async
    return res.status(202).json({
      success: true,
      data: {
        scanId,
        message: 'Scan started. Connect to socket room with scanId for real-time updates.',
      }
    });

  } catch (err) {
    // Step 5: All errors go to global error handler
    // Controller never handles errors directly
    next(err);
  }
}
// /server/src/routes/scanRoutes.js
// Maps HTTP verbs + paths to controller functions.
// The route layer is intentionally thin.
// Rate limiting applied per-route where needed.

import { Router } from 'express';
import { analyzeRepo } from '../controllers/scanController.js';
import { scanRateLimiter } from '../middleware/rateLimiter.js';

const router = Router();

/**
 * POST /api/analyze
 * Starts an async security scan of a GitHub repository.
 *
 * Middleware chain for this route:
 *   globalRateLimiter (from app.js) → runs first
 *   scanRateLimiter (here) → stricter, scan-specific
 *   analyzeRepo (controller) → business logic entry point
 */
router.post('/analyze', scanRateLimiter, analyzeRepo);

// Future routes go here:
// router.get('/scans/:scanId', getScanResult);      // Phase v2
// router.get('/scans', getUserScans);               // Phase v2
// router.delete('/scans/:scanId', deleteScan);      // Phase v2

export default router;
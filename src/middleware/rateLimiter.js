// rateLimiter.js
// Three purpose-specific rate limiters.
// Each protects a different resource at a different threshold.

import rateLimit from 'express-rate-limit';
import { config } from '../config/index.js';
import { AppError } from '../utils/AppError.js';

// ─────────────────────────────────────────────
// SHARED HANDLER
// Called when any rate limit is exceeded.
// Constructs a consistent error response via
// our global error handler.
// ─────────────────────────────────────────────

/**
 * Creates a rate limit exceeded handler.
 * Returns a function that constructs an AppError
 * and passes it to Express error handling.
 *
 * @param {string} message - Human-readable message for this limiter
 * @returns {Function} express-rate-limit handler
 */
function createLimitHandler(message) {
  return (req, res, next, options) => {
    // Calculate seconds until the window resets
    const resetTime = req.rateLimit?.resetTime;
    const retryAfterSeconds = resetTime
      ? Math.ceil((resetTime.getTime() - Date.now()) / 1000)
      : options.windowMs / 1000;

    // Attach retryAfter to the response headers
    // Standards-compliant: RFC 6585 specifies Retry-After header
    res.set('Retry-After', retryAfterSeconds);

    // Create an AppError with rate limit context
    const err = new AppError(message, 429, 'RATE_LIMIT_EXCEEDED');

    // Attach retryAfter to the error for the error handler
    // to include in the response body
    err.retryAfter = retryAfterSeconds;

    next(err);
  };
}

// ─────────────────────────────────────────────
// LIMITER 1: Global Rate Limiter
// Applied to ALL routes.
// Protects server from general DoS/scraping.
// ─────────────────────────────────────────────

export const globalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minute window
  max: 100,                   // 100 requests per window per IP

  // standardHeaders: true → use RateLimit-* headers (RFC standard)
  // legacyHeaders: false  → disable old X-RateLimit-* headers
  standardHeaders: true,
  legacyHeaders: false,

  // Skip rate limiting for health checks from monitoring tools
  // that make frequent requests from known IPs
  skip: (req) => req.path === '/health',

  handler: createLimitHandler(
    'Too many requests from this IP. Please wait 15 minutes before trying again.'
  ),

  // keyGenerator: how to identify the "who" being limited
  // Default: req.ip — correct for our use case
  // Alternative: req.user?.id for authenticated user-based limiting
  keyGenerator: (req) => req.ip,
});

// ─────────────────────────────────────────────
// LIMITER 2: Scan Endpoint Rate Limiter
// Applied ONLY to POST /api/analyze.
// Protects GitHub API quota and Gemini billing.
// Stricter than global limiter.
// ─────────────────────────────────────────────

export const scanRateLimiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: config.rateLimitMaxScans,  // 1 hour window
 // 5 scans per hour per IP

  standardHeaders: true,
  legacyHeaders: false,

  handler: createLimitHandler(
    'Too many scan requests. You can perform 5 scans per hour. ' +
    'Please try again later.'
  ),

  // Custom key: include method + path so this counter is
  // isolated from the global counter.
  // Same IP making GET /health doesn't consume scan quota.
  keyGenerator: (req) => `scan:${req.ip}`,
});

// ─────────────────────────────────────────────
// LIMITER 3: Health Check Limiter
// Applied to GET /health.
// Allows frequent monitoring but prevents flooding.
// ─────────────────────────────────────────────

export const healthRateLimiter = rateLimit({
  windowMs: 60 * 1000,        // 1 minute window
  max: 30,                    // 30 requests per minute per IP

  standardHeaders: true,
  legacyHeaders: false,

  handler: createLimitHandler(
    'Too many health check requests.'
  ),
});
// /server/src/app.js
// Express application configuration.
// Registers middleware in the correct order.
// Order matters — middleware runs top to bottom.

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';  // npm install helmet
import { config } from './config/index.js';
import { requestLogger } from './middleware/requestLogger.js';
import { globalRateLimiter, healthRateLimiter } from './middleware/rateLimiter.js';
import { errorHandler } from './middleware/errorHandler.js';
import scanRoutes from './routes/scanRoutes.js';
import { getSocketStats } from './socket/socketManager.js';

const app = express();

// ── Trust Proxy ──────────────────────────────────────────────
// Must be set BEFORE rate limiter so req.ip is correct
if (config.nodeEnv === 'production') {
  app.set('trust proxy', 1);
}

// ── Security Headers ─────────────────────────────────────────
// helmet() sets 11 security-related HTTP headers
// Must be first — before any response can be sent
app.use(helmet());

// ── CORS ─────────────────────────────────────────────────────
// Must be before routes so preflight OPTIONS requests
// are handled correctly
app.use(cors({
  origin: config.clientUrl,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));

// ── Body Parser ──────────────────────────────────────────────
// Parse JSON request bodies
// limit: prevent oversized payloads
app.use(express.json({ limit: '10kb' }));

// ── Request Logging ──────────────────────────────────────────
// After body parsing so we could log body if needed
// Before rate limiting so we log even rejected requests
app.use(requestLogger);

// ── Global Rate Limiter ──────────────────────────────────────
// Applied to ALL routes before any route handler runs
app.use(globalRateLimiter);

// ── Health Check ─────────────────────────────────────────────
// Before API routes — health check has no business logic
// Has its own rate limiter (separate from global)
app.get('/health', healthRateLimiter, (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: config.nodeEnv,
    socket: getSocketStats(),
  });
});

// ── API Routes ───────────────────────────────────────────────
// All business routes under /api prefix
app.use('/api', scanRoutes);

// ── 404 Handler ──────────────────────────────────────────────
// Catches requests that didn't match any route
// Must be AFTER all routes, BEFORE error handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: `Route ${req.method} ${req.path} not found.`,
    }
  });
});

// ── Global Error Handler ─────────────────────────────────────
// Must be LAST — Express identifies error handlers
// by their 4-argument signature (err, req, res, next)
app.use(errorHandler);

export default app;
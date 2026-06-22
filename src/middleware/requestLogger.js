// /server/src/middleware/requestLogger.js

/**
 * Simple request logger middleware.
 * Logs method, path, status, and response time
 * for every request.
 *
 * In production you'd replace this with Winston or
 * Morgan configured to output structured JSON.
 */
export const requestLogger = (req, res, next) => {
  const start = Date.now();

  // Log when response finishes (not when request arrives)
  // This gives us the status code and duration
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logLine = [
      `[${new Date().toISOString()}]`,
      req.method,
      req.path,
      res.statusCode,
      `${duration}ms`,
      req.ip,
    ].join(' ');

    // Color-code by status for readability in dev
    if (res.statusCode >= 500) console.error(logLine);
    else if (res.statusCode >= 400) console.warn(logLine);
    else console.log(logLine);
  });

  next();
};
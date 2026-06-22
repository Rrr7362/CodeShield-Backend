import { AppError } from '../utils/AppError.js';

export const errorHandler = (err, req, res, next) => {
  console.error(`[error] ${req.method} ${req.path}`, {
    message: err.message,
    code: err.code || 'UNKNOWN',
    statusCode: err.statusCode || 500,
  });

  if (err instanceof AppError && err.isOperational) {
    const response = {
      success: false,
      error: {
        code: err.code,
        message: err.message,
      }
    };

    // Include retryAfter for rate limit errors
    // Client uses this to show a countdown timer
    if (err.retryAfter) {
      response.error.retryAfter = err.retryAfter;
    }

    return res.status(err.statusCode).json(response);
  }

  return res.status(500).json({
    success: false,
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred. Please try again.',
      ...(config.nodeEnv === 'development' && { debug: err.message }),
    }
  });
};
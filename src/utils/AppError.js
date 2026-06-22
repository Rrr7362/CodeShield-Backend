// AppError.js
// A custom error class that carries HTTP status codes and
// machine-readable error codes alongside the message.
// Thrown anywhere in the pipeline, caught by errorHandler middleware.

export class AppError extends Error {
  constructor(message, statusCode, code) {
    // Call the parent Error constructor with the message.
    // This sets this.message and captures the stack trace.
    super(message);

    this.statusCode = statusCode;
    this.code = code;

    // Marks this as an operational error (expected, handled)
    // vs a programmer error (unexpected bug).
    // Useful for monitoring — you alert differently on each type.
    this.isOperational = true;

    // Maintains proper stack trace in V8 (Node.js/Chrome)
    Error.captureStackTrace(this, this.constructor);
  }
}
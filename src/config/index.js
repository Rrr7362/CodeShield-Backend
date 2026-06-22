// config/index.js
// Single source of truth for all environment variables.
// The app fails fast here if required secrets are missing.

import dotenv from 'dotenv';
dotenv.config();

const requiredEnvVars = [
  'GITHUB_TOKEN',
  'GEMINI_API_KEY',
  'CLIENT_URL'
];

// Validate on startup — fail fast, fail loudly
for (const varName of requiredEnvVars) {
  if (!process.env[varName]) {
    // We throw synchronously — this crashes the process at boot
    // which is exactly what we want. A server running without
    // required secrets is more dangerous than a server that
    // refuses to start.
    throw new Error(`FATAL: Missing required environment variable: ${varName}`);
  }
}

export const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  githubToken: process.env.GITHUB_TOKEN,
  geminiApiKey: process.env.GEMINI_API_KEY,
  clientUrl: process.env.CLIENT_URL,
  rateLimitWindowMs:
    Number(process.env.RATE_LIMIT_WINDOW_MS) || 3600000,
  rateLimitMaxScans:
    Number(process.env.RATE_LIMIT_MAX_SCANS) || 5,
};
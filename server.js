// server.js — Entry point
// Responsibilities: import app, create HTTP server,
// attach Socket.IO, start listening.

import http from 'http';
import app from './src/app.js';
import { config } from './src/config/index.js';
import { initSocket } from './src/socket/socketManager.js';

// Create a raw HTTP server wrapping the Express app.
// We need this because Socket.IO attaches to the HTTP server
// directly, not to the Express app object.
const server = http.createServer(app);

// Initialize Socket.IO on the HTTP server
initSocket(server);

server.listen(config.port, () => {
  console.log(`[server] Running on port ${config.port} in ${config.nodeEnv} mode`);
});
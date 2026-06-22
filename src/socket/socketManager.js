// socketManager.js
// Production-grade Socket.IO server setup.
// Handles: connection lifecycle, room management,
// heartbeat configuration, disconnect cleanup,
// and error handling.

import { Server } from 'socket.io';
import { config } from '../config/index.js';

let io;

// Track active scans for cleanup purposes
// Map of scanId → { startedAt, socketId }
// This lets us detect and clean up abandoned scans
const activeScans = new Map();

// Maximum scan duration before we consider it abandoned
// If a scan takes longer than this, something went wrong
const SCAN_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

export const initSocket = (httpServer) => {
  io = new Server(httpServer, {

    // CORS — must match Express CORS config
    cors: {
      origin: config.clientUrl,
      methods: ['GET', 'POST'],
    },

    // Heartbeat configuration
    // These values work well for most network conditions
    pingTimeout: 20000,    // 20s: close connection if no pong
    pingInterval: 25000,   // 25s: send ping every 25 seconds

    // Maximum HTTP buffer size for a single message
    // Prevents oversized payloads (DoS protection)
    maxHttpBufferSize: 1e6, // 1MB

    // Transport configuration
    // Try WebSocket first, fall back to polling
    transports: ['websocket', 'polling'],

    // Connection state recovery
    // Allows clients to recover missed events after
    // a brief disconnection (within the recovery window)
    connectionStateRecovery: {
      maxDisconnectionDuration: 2 * 60 * 1000, // 2 minutes
      skipMiddlewares: true,
    }
  });

  // ── Connection Handler ──────────────────────────────────

  io.on('connection', (socket) => {
    console.log(`[socket] Connected: ${socket.id} (transport: ${socket.conn.transport.name})`);

    // Log transport upgrades (polling → websocket)
    socket.conn.on('upgrade', (transport) => {
      console.log(`[socket] Upgraded: ${socket.id} → ${transport.name}`);
    });

    // ── Room Management ───────────────────────────────────

    // Client joins a scan room to receive scan-specific events
    socket.on('join-scan', (scanId) => {
      // Validate scanId — basic UUID format check
      // Prevents clients from joining arbitrary rooms
      if (!isValidScanId(scanId)) {
        socket.emit('error', {
          code: 'INVALID_SCAN_ID',
          message: 'Invalid scan ID format'
        });
        return;
      }

      socket.join(scanId);
      console.log(`[socket] ${socket.id} joined scan room: ${scanId}`);

      // Acknowledge the join so client knows it's ready
      // Client should only start showing progress UI after this
      socket.emit('joined-scan', {
        scanId,
        socketId: socket.id,
        timestamp: new Date().toISOString()
      });

      // Register this socket with the scan
      // Used for cleanup if socket disconnects mid-scan
      if (activeScans.has(scanId)) {
        activeScans.get(scanId).socketIds.add(socket.id);
      }
    });

    // ── Disconnect Handler ────────────────────────────────

    socket.on('disconnect', (reason) => {
      console.log(`[socket] Disconnected: ${socket.id} — reason: ${reason}`);

      // Common disconnect reasons:
      // 'transport close'     → network dropped
      // 'transport error'     → connection error
      // 'ping timeout'        → heartbeat failed
      // 'server namespace disconnect' → server called socket.disconnect()
      // 'client namespace disconnect' → client called socket.disconnect()

      // Socket.IO automatically removes socket from all rooms
      // No manual room cleanup needed here
    });

    // ── Error Handler ─────────────────────────────────────

    socket.on('error', (err) => {
      console.error(`[socket] Error on ${socket.id}:`, err.message);
    });

  });

  // ── Server-Level Error Handler ────────────────────────────

  io.engine.on('connection_error', (err) => {
    console.error('[socket] Connection error:', {
      code: err.code,
      message: err.message,
      context: err.context,
    });
  });

  // ── Periodic Cleanup ─────────────────────────────────────
  // Remove abandoned scans that never completed
  // Runs every 10 minutes

  setInterval(() => {
    const now = Date.now();
    let cleaned = 0;

    for (const [scanId, scan] of activeScans.entries()) {
      if (now - scan.startedAt > SCAN_TIMEOUT_MS) {
        activeScans.delete(scanId);
        cleaned++;
        console.log(`[socket] Cleaned up abandoned scan: ${scanId}`);
      }
    }

    if (cleaned > 0) {
      console.log(`[socket] Cleanup: removed ${cleaned} abandoned scans`);
    }
  }, 10 * 60 * 1000); // every 10 minutes

  console.log('[socket] Socket.IO server initialized');
  return io;
};

// ── Public API ────────────────────────────────────────────────

export const getIO = () => {
  if (!io) throw new Error('Socket.IO not initialized.');
  return io;
};

/**
 * Registers a scan as active.
 * Called by scanService when a scan begins.
 */
export const registerScan = (scanId) => {
  activeScans.set(scanId, {
    startedAt: Date.now(),
    socketIds: new Set(),
  });
};

/**
 * Marks a scan as complete and removes from active tracking.
 * Called by scanService when scan completes or errors.
 */
export const deregisterScan = (scanId) => {
  activeScans.delete(scanId);
};

/**
 * Returns current server statistics.
 * Useful for health checks and monitoring endpoints.
 */
export const getSocketStats = () => ({
  connectedClients: io?.engine?.clientsCount || 0,
  activeScans: activeScans.size,
});

// ── Utilities ─────────────────────────────────────────────────

/**
 * Validates that a scanId looks like a UUID v4.
 * Prevents clients from joining arbitrary room names.
 */
function isValidScanId(scanId) {
  if (typeof scanId !== 'string') return false;
  const uuidV4Pattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidV4Pattern.test(scanId);
}
/**
 * WebSocket route — /ws?scanId=<uuid>
 *
 * Clients connect with a scanId query parameter and receive
 * real-time progress events via Redis Pub/Sub.
 */
import { FastifyInstance } from 'fastify';
import { subscribe, unsubscribe } from '../lib/ws-manager.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function wsRoutes(server: FastifyInstance): Promise<void> {
  server.get('/ws', { websocket: true }, (socket, request) => {
    const url = new URL(request.url, 'http://localhost');
    const scanId = url.searchParams.get('scanId');

    if (!scanId || !UUID_REGEX.test(scanId)) {
      socket.close(4400, 'Invalid or missing scanId');
      return;
    }

    subscribe(scanId, socket);

    socket.on('close', () => {
      unsubscribe(scanId, socket);
    });

    socket.on('error', () => {
      unsubscribe(scanId, socket);
    });

    // Send a welcome message so the client knows the connection is established
    socket.send(JSON.stringify({
      type: 'connected',
      scanId,
      timestamp: new Date().toISOString(),
    }));
  });
}

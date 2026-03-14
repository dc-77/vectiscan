/**
 * WebSocket route — /ws?orderId=<uuid>
 *
 * Clients connect with an orderId query parameter and receive
 * real-time progress events via Redis Pub/Sub.
 * Also accepts legacy scanId param for backward compatibility.
 */
import { FastifyInstance } from 'fastify';
import { subscribe, unsubscribe } from '../lib/ws-manager.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function wsRoutes(server: FastifyInstance): Promise<void> {
  server.get('/ws', { websocket: true }, (socket, request) => {
    const url = new URL(request.url, 'http://localhost');
    const orderId = url.searchParams.get('orderId') || url.searchParams.get('scanId');

    if (!orderId || !UUID_REGEX.test(orderId)) {
      socket.close(4400, 'Invalid or missing orderId');
      return;
    }

    subscribe(orderId, socket);

    socket.on('close', () => {
      unsubscribe(orderId, socket);
    });

    socket.on('error', () => {
      unsubscribe(orderId, socket);
    });

    // Send a welcome message so the client knows the connection is established
    socket.send(JSON.stringify({
      type: 'connected',
      orderId,
      timestamp: new Date().toISOString(),
    }));
  });
}

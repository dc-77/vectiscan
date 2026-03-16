/**
 * WebSocket route — /ws?orderId=<uuid>
 *
 * Clients connect with an orderId query parameter and receive
 * real-time progress events via Redis Pub/Sub.
 * Also accepts legacy scanId param for backward compatibility.
 */
import { FastifyInstance } from 'fastify';
import { subscribe, unsubscribe } from '../lib/ws-manager.js';
import { query } from '../lib/db.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Replay persisted AI events to a late-joining client. */
async function replayEvents(socket: import('ws').WebSocket, orderId: string): Promise<void> {
  try {
    // Replay discovered hosts
    const orderResult = await query(
      'SELECT discovered_hosts FROM orders WHERE id = $1',
      [orderId],
    );
    if (orderResult.rows.length > 0) {
      const hosts = (orderResult.rows[0] as Record<string, unknown>).discovered_hosts;
      if (hosts && Array.isArray((hosts as Record<string, unknown>)?.hosts || hosts)) {
        const hostList = Array.isArray(hosts) ? hosts : (hosts as Record<string, unknown[]>).hosts || [];
        if (hostList.length > 0) {
          socket.send(JSON.stringify({
            type: 'hosts_discovered',
            orderId,
            hosts: hostList,
            hostsTotal: hostList.length,
            updatedAt: new Date().toISOString(),
          }));
        }
      }
    }

    // Replay AI strategy + configs from scan_results
    const aiResults = await query(
      `SELECT tool_name, host_ip, raw_output FROM scan_results
       WHERE order_id = $1 AND tool_name IN ('ai_host_strategy', 'ai_phase2_config')
       ORDER BY created_at ASC`,
      [orderId],
    );

    for (const row of aiResults.rows as Array<Record<string, unknown>>) {
      try {
        const parsed = JSON.parse(row.raw_output as string);
        if (row.tool_name === 'ai_host_strategy') {
          socket.send(JSON.stringify({ type: 'ai_strategy', orderId, strategy: parsed, updatedAt: new Date().toISOString() }));
        } else if (row.tool_name === 'ai_phase2_config' && row.host_ip) {
          socket.send(JSON.stringify({ type: 'ai_config', orderId, ip: row.host_ip, config: parsed, updatedAt: new Date().toISOString() }));
        }
      } catch { /* skip unparseable */ }
    }

    // Replay tool output summaries
    const toolResults = await query(
      `SELECT tool_name, host_ip, LEFT(raw_output, 150) as summary FROM scan_results
       WHERE order_id = $1 AND tool_name NOT IN ('ai_host_strategy', 'ai_phase2_config', 'ai_host_skip')
         AND exit_code >= 0
       ORDER BY created_at ASC LIMIT 50`,
      [orderId],
    );

    for (const row of toolResults.rows as Array<Record<string, unknown>>) {
      socket.send(JSON.stringify({
        type: 'tool_output',
        orderId,
        tool: row.tool_name,
        host: row.host_ip || '',
        summary: ((row.summary as string) || '').split('\n')[0].slice(0, 100),
        updatedAt: new Date().toISOString(),
      }));
    }
  } catch {
    // Non-critical — replay is best-effort
  }
}

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

    // Send welcome message
    socket.send(JSON.stringify({
      type: 'connected',
      orderId,
      timestamp: new Date().toISOString(),
    }));

    // Replay past events for late-joining clients
    replayEvents(socket, orderId);
  });
}

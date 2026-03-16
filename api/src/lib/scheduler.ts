/**
 * Scan Scheduler — checks every 60s for due recurring scans and enqueues them.
 */
import { query } from './db.js';
import { scanQueue, publishEvent } from './queue.js';

const INTERVAL_MS = 60_000;

function calculateNextScanAt(scheduleType: string, from: Date): Date | null {
  const next = new Date(from);
  switch (scheduleType) {
    case 'weekly':
      next.setDate(next.getDate() + 7);
      return next;
    case 'monthly':
      next.setMonth(next.getMonth() + 1);
      return next;
    case 'quarterly':
      next.setMonth(next.getMonth() + 3);
      return next;
    case 'once':
      return null; // one-shot, disable after execution
    default:
      return null;
  }
}

async function tick(): Promise<void> {
  try {
    // Find all due schedules (row-level lock to prevent double-processing)
    const result = await query(
      `SELECT s.id, s.customer_id, s.target_url, s.package, s.schedule_type
       FROM scan_schedules s
       WHERE s.enabled = true AND s.next_scan_at <= NOW()
       FOR UPDATE SKIP LOCKED`,
    );

    for (const row of result.rows as Array<Record<string, unknown>>) {
      try {
        // Create order directly in queued state (skip verification — domain was verified before)
        const orderResult = await query(
          `INSERT INTO orders (customer_id, target_url, package, status, verified_at)
           VALUES ($1, $2, $3, 'queued', NOW())
           RETURNING id`,
          [row.customer_id, row.target_url, row.package],
        );
        const orderId = (orderResult.rows[0] as Record<string, unknown>).id as string;

        // Enqueue scan job
        await scanQueue.add('scan', {
          orderId,
          targetDomain: row.target_url,
          package: row.package,
        });

        // Publish status event
        await publishEvent(orderId, {
          type: 'status',
          orderId,
          status: 'queued',
          updatedAt: new Date().toISOString(),
        });

        // Update schedule: set next_scan_at, mark last scan
        const nextAt = calculateNextScanAt(row.schedule_type as string, new Date());
        const enabled = row.schedule_type !== 'once';
        await query(
          `UPDATE scan_schedules
           SET last_scan_at = NOW(),
               next_scan_at = COALESCE($1, next_scan_at + INTERVAL '100 years'),
               last_order_id = $2,
               enabled = $3,
               updated_at = NOW()
           WHERE id = $4`,
          [nextAt?.toISOString() || null, orderId, enabled, row.id],
        );

        console.log(`[scheduler] Enqueued scan for ${row.target_url} (schedule ${row.id}, order ${orderId})`);
      } catch (err) {
        console.error(`[scheduler] Failed to process schedule ${row.id}:`, err);
      }
    }
  } catch (err) {
    console.error('[scheduler] Tick error:', err);
  }
}

export function startScheduler(): void {
  console.log('[scheduler] Started (checking every 60s)');
  tick(); // check immediately on startup
  setInterval(tick, INTERVAL_MS);
}

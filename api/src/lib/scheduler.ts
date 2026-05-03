/**
 * Subscription Scheduler — checks every 60s for due subscription scans.
 *
 * For each active subscription with verified/enabled domains where a scan
 * is due, creates an order and enqueues the scan job.
 *
 * Also keeps legacy scan_schedules working for backward compatibility.
 */
import { query } from './db.js';
import { scanQueue, reportQueue, publishEvent } from './queue.js';

const INTERVAL_MS = 60_000;

function calculateNextScanAt(interval: string, from: Date): Date | null {
  const next = new Date(from);
  switch (interval) {
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
      return null;
    default:
      return null;
  }
}

async function expireSubscriptions(): Promise<void> {
  // Mark expired subscriptions as 'expired'
  const result = await query(
    `UPDATE subscriptions SET status = 'expired', updated_at = NOW()
     WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < NOW()
     RETURNING id`,
  );
  if (result.rows.length > 0) {
    console.log(`[scheduler] Expired ${result.rows.length} subscription(s)`);
  }
}

async function tickSubscriptions(): Promise<void> {
  // Find due active subscriptions with at least one approved target.
  const result = await query(
    `SELECT s.id AS subscription_id, s.customer_id, s.package, s.scan_interval
     FROM subscriptions s
     WHERE s.status = 'active'
       AND EXISTS (
         SELECT 1 FROM scan_targets t
         WHERE t.subscription_id = s.id AND t.status = 'approved'
       )
       AND (
         s.last_scan_at IS NULL
         OR (s.scan_interval = 'weekly' AND s.last_scan_at < NOW() - INTERVAL '7 days')
         OR (s.scan_interval = 'monthly' AND s.last_scan_at < NOW() - INTERVAL '1 month')
         OR (s.scan_interval = 'quarterly' AND s.last_scan_at < NOW() - INTERVAL '3 months')
       )
     FOR UPDATE OF s SKIP LOCKED`,
  );

  for (const row of result.rows as Array<Record<string, unknown>>) {
    const subId = row.subscription_id as string;

    try {
      const targetsRes = await query(
        `SELECT id, canonical, discovery_policy, exclusions
         FROM scan_targets
         WHERE subscription_id = $1 AND status = 'approved'`,
        [subId],
      );
      const targets = targetsRes.rows as Array<Record<string, unknown>>;
      if (targets.length === 0) continue;

      const displayName = targets.length === 1
        ? (targets[0].canonical as string)
        : `multi-target (${targets.length})`;

      const orderResult = await query(
        `INSERT INTO orders (customer_id, target_url, package, status, verified_at, subscription_id, target_count, is_rescan)
         VALUES ($1, $2, $3, 'queued', NOW(), $4, $5, true)
         RETURNING id`,
        [row.customer_id, displayName, row.package, subId, targets.length],
      );
      const orderId = (orderResult.rows[0] as Record<string, unknown>).id as string;

      for (const t of targets) {
        await query(
          `INSERT INTO scan_run_targets
             (order_id, scan_target_id, in_scope, snapshot_discovery_policy, snapshot_exclusions)
           VALUES ($1, $2, true, $3, $4)`,
          [orderId, t.id, t.discovery_policy, t.exclusions],
        );
      }

      await scanQueue.add('scan', { orderId, package: row.package });
      await publishEvent(orderId, {
        type: 'status', orderId, status: 'queued',
        updatedAt: new Date().toISOString(),
      });

      await query(
        `UPDATE subscriptions SET last_scan_at = NOW(), updated_at = NOW() WHERE id = $1`,
        [subId],
      );

      console.log(`[scheduler] Subscription scan enqueued: sub ${subId}, order ${orderId}, targets ${targets.length}`);
    } catch (err) {
      console.error(`[scheduler] Failed to process subscription ${subId}:`, err);
    }
  }
}

async function tickLegacySchedules(): Promise<void> {
  // Keep legacy scan_schedules working
  const result = await query(
    `SELECT s.id, s.customer_id, s.target_url, s.package, s.schedule_type
     FROM scan_schedules s
     WHERE s.enabled = true AND s.next_scan_at <= NOW()
     FOR UPDATE SKIP LOCKED`,
  );

  for (const row of result.rows as Array<Record<string, unknown>>) {
    try {
      const orderResult = await query(
        `INSERT INTO orders (customer_id, target_url, package, status, verified_at)
         VALUES ($1, $2, $3, 'queued', NOW())
         RETURNING id`,
        [row.customer_id, row.target_url, row.package],
      );
      const orderId = (orderResult.rows[0] as Record<string, unknown>).id as string;

      await scanQueue.add('scan', {
        orderId,
        targetDomain: row.target_url,
        package: row.package,
      });

      await publishEvent(orderId, {
        type: 'status',
        orderId,
        status: 'queued',
        updatedAt: new Date().toISOString(),
      });

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

      console.log(`[scheduler] Legacy scan enqueued: ${row.target_url} (schedule ${row.id}, order ${orderId})`);
    } catch (err) {
      console.error(`[scheduler] Failed to process legacy schedule ${row.id}:`, err);
    }
  }
}

/**
 * PR-Posture (2026-05-03): periodischer Status-Report-Trigger.
 *
 * Pro aktiver Subscription: wenn last_status_report_at NULL ist ODER
 * laenger als scan_interval zurueckliegt, schiebt einen
 * subscription-status-report-Job in die report-pending-Queue.
 */
async function tickStatusReports(): Promise<void> {
  const result = await query<{
    id: string; scan_interval: string; last_status_report_at: Date | null;
  }>(
    `SELECT id, scan_interval, last_status_report_at
       FROM subscriptions
      WHERE status = 'active'
        AND scan_interval IN ('weekly', 'monthly', 'quarterly')
        AND (
              last_status_report_at IS NULL
           OR (scan_interval = 'weekly'    AND last_status_report_at < NOW() - INTERVAL '7 days')
           OR (scan_interval = 'monthly'   AND last_status_report_at < NOW() - INTERVAL '30 days')
           OR (scan_interval = 'quarterly' AND last_status_report_at < NOW() - INTERVAL '90 days')
        )`,
  );
  for (const row of result.rows) {
    try {
      await reportQueue.add('subscription-status-report', {
        subscriptionId: row.id,
        triggerReason: 'scheduled',
      });
      console.log(`[scheduler] Status-Report enqueued for subscription ${row.id} (${row.scan_interval})`);
    } catch (err) {
      console.error(`[scheduler] Failed to enqueue status-report for ${row.id}:`, err);
    }
  }
}

async function tick(): Promise<void> {
  try {
    await expireSubscriptions();
    await tickSubscriptions();
    await tickLegacySchedules();
    await tickStatusReports();
  } catch (err) {
    console.error('[scheduler] Tick error:', err);
  }
}

export function startScheduler(): void {
  console.log('[scheduler] Started (subscriptions + legacy schedules, checking every 60s)');
  tick();
  setInterval(tick, INTERVAL_MS);
}

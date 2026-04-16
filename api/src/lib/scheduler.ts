/**
 * Subscription Scheduler — checks every 60s for due subscription scans.
 *
 * For each active subscription with verified/enabled domains where a scan
 * is due, creates an order and enqueues the scan job.
 *
 * Also keeps legacy scan_schedules working for backward compatibility.
 */
import { query } from './db.js';
import { scanQueue, publishEvent } from './queue.js';

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

async function tickSubscriptions(): Promise<void> {
  // Find all active subscriptions where a scan is due
  // A scan is due when: last_scan_at + interval < NOW(), or last_scan_at IS NULL (first scan)
  const result = await query(
    `SELECT s.id AS subscription_id, s.customer_id, s.package, s.scan_interval,
            s.last_scan_at, s.report_emails,
            sd.id AS domain_id, sd.domain
     FROM subscriptions s
     JOIN subscription_domains sd ON sd.subscription_id = s.id
     WHERE s.status = 'active'
       AND sd.enabled = true
       AND sd.status = 'verified'
       AND (
         s.last_scan_at IS NULL
         OR (s.scan_interval = 'weekly' AND s.last_scan_at < NOW() - INTERVAL '7 days')
         OR (s.scan_interval = 'monthly' AND s.last_scan_at < NOW() - INTERVAL '1 month')
         OR (s.scan_interval = 'quarterly' AND s.last_scan_at < NOW() - INTERVAL '3 months')
       )
     FOR UPDATE OF s SKIP LOCKED`,
  );

  // Group by subscription to avoid scanning same subscription twice in one tick
  const processed = new Set<string>();

  for (const row of result.rows as Array<Record<string, unknown>>) {
    const subId = row.subscription_id as string;
    const domain = row.domain as string;
    const domainKey = `${subId}:${domain}`;

    if (processed.has(domainKey)) continue;
    processed.add(domainKey);

    try {
      // Create order linked to subscription
      const orderResult = await query(
        `INSERT INTO orders (customer_id, target_url, package, status, verified_at, subscription_id)
         VALUES ($1, $2, $3, 'queued', NOW(), $4)
         RETURNING id`,
        [row.customer_id, domain, row.package, subId],
      );
      const orderId = (orderResult.rows[0] as Record<string, unknown>).id as string;

      // Enqueue scan job
      await scanQueue.add('scan', {
        orderId,
        targetDomain: domain,
        package: row.package,
      });

      await publishEvent(orderId, {
        type: 'status',
        orderId,
        status: 'queued',
        updatedAt: new Date().toISOString(),
      });

      // Update subscription last_scan_at
      await query(
        `UPDATE subscriptions SET last_scan_at = NOW(), updated_at = NOW() WHERE id = $1`,
        [subId],
      );

      console.log(`[scheduler] Subscription scan enqueued: ${domain} (sub ${subId}, order ${orderId})`);
    } catch (err) {
      console.error(`[scheduler] Failed to process subscription domain ${domain}:`, err);
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

async function tick(): Promise<void> {
  try {
    await tickSubscriptions();
    await tickLegacySchedules();
  } catch (err) {
    console.error('[scheduler] Tick error:', err);
  }
}

export function startScheduler(): void {
  console.log('[scheduler] Started (subscriptions + legacy schedules, checking every 60s)');
  tick();
  setInterval(tick, INTERVAL_MS);
}

/**
 * Audit trail — logs key actions to the audit_log table.
 * Fire-and-forget: errors are logged but never block the caller.
 */
import { query } from './db.js';
import pino from 'pino';

const log = pino({ name: 'audit' });

export type AuditAction =
  | 'order.created'
  | 'order.cancelled'
  | 'order.deleted'
  | 'order.verified'
  | 'scan.started'
  | 'scan.completed'
  | 'scan.failed'
  | 'report.generated'
  | 'report.downloaded'
  | 'user.registered'
  | 'user.login'
  | 'user.password_reset'
  | 'user.role_changed'
  | 'user.disabled'
  | 'user.deleted';

interface AuditEntry {
  orderId?: string | null;
  action: AuditAction;
  details?: Record<string, unknown>;
  ip?: string | null;
}

export async function audit(entry: AuditEntry): Promise<void> {
  try {
    await query(
      `INSERT INTO audit_log (order_id, action, details, ip_address)
       VALUES ($1, $2, $3, $4)`,
      [
        entry.orderId ?? null,
        entry.action,
        entry.details ? JSON.stringify(entry.details) : null,
        entry.ip ?? null,
      ],
    );
  } catch (err) {
    log.error({ err, ...entry }, 'Failed to write audit log');
  }
}

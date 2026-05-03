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
  | 'report.regenerate'
  | 'finding.excluded'
  | 'finding.unexcluded'
  | 'user.registered'
  | 'user.login'
  | 'user.password_reset'
  | 'user.role_changed'
  | 'user.disabled'
  | 'user.deleted'
  | 'order.approved'
  | 'order.rejected'
  | 'subscription.created'
  | 'subscription.domain_requested'
  | 'subscription.domain_approved'
  | 'subscription.domain_rejected'
  | 'subscription.target_requested'
  | 'subscription.target_removed'
  | 'subscription.target_approved'
  | 'subscription.target_rejected'
  | 'subscription.rescan'
  | 'target.approved'
  | 'target.rejected'
  | 'target.updated'
  | 'authorization.uploaded'
  | 'authorization.deleted'
  | 'order.released'
  | 'finding.accept_risk'
  | 'finding.reopen'
  | 'subscription.status_report_requested'
  | 'subscription.status_report_generated';

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
// Build 1776359991

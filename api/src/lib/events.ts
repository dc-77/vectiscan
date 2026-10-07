/**
 * Name des Pub/Sub-Kanals je Order (Swarm-Umzug, 06.10.2026).
 *
 * Pub/Sub kennt in Redis keine Datenbank-Nummer: Auf dem gemeinsamen Redis
 * empfingen Test und Prod sonst gegenseitig ihre Ereignisse, und
 * handleReportComplete liefe fuer Orders des anderen Feldes. REDIS_EVENT_PREFIX
 * traegt deshalb das Feld (vect-prod:, vect-test:); auf docker02 bleibt es leer.
 * scan-worker (progress.py) und report-worker (worker.py) lesen dieselbe
 * Variable, alle muessen denselben Wert sehen.
 *
 * Eigenes Modul aus demselben Grund wie lib/buckets.ts: Tests ersetzen
 * lib/queue durch eine Attrappe.
 */
export const EVENT_CHANNEL_PREFIX = process.env.REDIS_EVENT_PREFIX ?? '';

export function eventChannel(orderId: string): string {
  return `${EVENT_CHANNEL_PREFIX}scan:events:${orderId}`;
}

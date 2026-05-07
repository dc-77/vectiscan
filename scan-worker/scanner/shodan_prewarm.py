"""Shodan on-demand Pre-Warm-Trigger (F-P0A-006).

Wird beim Scan-Start (nach Release-Punkt = scan_authorizations bereits
hochgeladen, status `queued`) aufgerufen. Loest fuer berechtigte Orders
einen Shodan on-demand Scan ueber `POST /shodan/scan` aus, sodass Phase 0a
24-48h spaeter frischere Shodan-Daten sieht.

Pfade:
- Subscription-Pfad: default-on. Jede Subscription-Order triggert.
- One-Off-Order-Pfad: opt-in. Nur wenn `orders.pre_warm_requested = TRUE`.

Persistenz:
- Bei Subscription-Pfad: `subscriptions.shodan_scan_request` (JSONB).
- Bei One-Off-Pfad: kein DB-Schreib (Order ist nicht reversibel; Audit
  steht ueber den scan-worker-Log + Shodan-API-Antwort).

Failure-Modes:
- Kein API-Key: stiller Skip.
- Shodan-API-Down: log warning, kein Block, Phase 0a nutzt Cache wie bisher.
- DB-Lookup-Failure: log warning, fail-safe (kein Pre-Warm).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

import psycopg2
import psycopg2.extras
import structlog

from scanner.passive.shodan_client import ShodanClient

log = structlog.get_logger()

# Shodan-API Limit fuer POST /shodan/scan: praktisch unbegrenzt fuer den
# Freelancer-Plan, aber wir cappen defensiv um Credit-Spikes zu vermeiden.
PRE_WARM_IP_CAP = 50


def _conn() -> Any:
    return psycopg2.connect(
        os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan"),
        connect_timeout=10,
        options="-c statement_timeout=15000",
    )


def _load_approved_ips(order_id: str) -> list[str]:
    """Ladet die IPs der approved Targets aus scan_target_hosts.

    Wir nehmen alle is_live=TRUE IPs der approved scan_targets dieser Order.
    Sortiert + dedupliziert fuer Determinismus.
    """
    try:
        with _conn() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT DISTINCT h.ip
                     FROM scan_target_hosts h
                     JOIN scan_targets t ON t.id = h.scan_target_id
                    WHERE t.order_id = %s
                      AND t.status = 'approved'
                      AND h.is_live = true
                      AND h.ip IS NOT NULL""",
                (order_id,),
            )
            rows = cur.fetchall()
            ips = sorted({str(r[0]) for r in rows if r and r[0]})
            return ips
    except Exception as exc:
        log.warning("shodan_prewarm_ip_lookup_failed",
                    order_id=order_id, error=str(exc))
        return []


def _load_order_context(order_id: str) -> dict[str, Any] | None:
    """Liest die Pre-Warm-Relevanz fuer eine Order aus der DB."""
    try:
        with _conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT subscription_id, pre_warm_requested
                     FROM orders
                    WHERE id = %s""",
                (order_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "subscription_id": row.get("subscription_id"),
                "pre_warm_requested": bool(row.get("pre_warm_requested") or False),
            }
    except Exception as exc:
        log.warning("shodan_prewarm_order_lookup_failed",
                    order_id=order_id, error=str(exc))
        return None


def _persist_subscription_request(subscription_id: str, scan_id: str,
                                  ips: list[str]) -> None:
    """Schreibt subscriptions.shodan_scan_request (JSONB) als Audit-Trail."""
    payload = {
        "scan_id": scan_id,
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "ips": list(ips),
        "status": "submitted",
    }
    try:
        with _conn() as conn, conn.cursor() as cur:
            cur.execute(
                """UPDATE subscriptions
                      SET shodan_scan_request = %s::jsonb
                    WHERE id = %s""",
                (json.dumps(payload), subscription_id),
            )
            conn.commit()
        log.info("shodan_prewarm_persisted",
                 subscription_id=subscription_id, scan_id=scan_id,
                 ip_count=len(ips))
    except Exception as exc:
        log.warning("shodan_prewarm_persist_failed",
                    subscription_id=subscription_id, error=str(exc))


def maybe_trigger_prewarm(order_id: str, ips: list[str] | None = None) -> str | None:
    """Triggert Shodan Pre-Warm wenn Order/Subscription dafuer berechtigt ist.

    Args:
        order_id: Order-UUID (scan-pending-Job).
        ips: Optionale IPv4-Liste; wenn None werden die IPs aus
             `scan_target_hosts` (approved Targets, is_live=TRUE) geladen.
             Wird auf PRE_WARM_IP_CAP gecappt.

    Returns:
        scan_id auf Erfolg, None wenn Skip oder Failure.
    """
    ctx = _load_order_context(order_id)
    if ctx is None:
        return None

    is_subscription = bool(ctx.get("subscription_id"))
    is_one_off_optin = ctx.get("pre_warm_requested", False)

    if not is_subscription and not is_one_off_optin:
        # One-Off ohne Opt-In: kein Pre-Warm.
        return None

    if ips is None:
        ips = _load_approved_ips(order_id)
    if not ips:
        log.info("shodan_prewarm_skipped",
                 reason="no_ips", order_id=order_id,
                 path="subscription" if is_subscription else "one_off_optin")
        return None

    # Cap defensiv (caller sollte schon gecappt haben).
    capped = list(ips)[:PRE_WARM_IP_CAP]

    client = ShodanClient()
    if not client.available:
        log.info("shodan_prewarm_skipped",
                 reason="no_api_key", order_id=order_id,
                 path="subscription" if is_subscription else "one_off_optin")
        return None

    log.info("shodan_prewarm_starting",
             order_id=order_id, ip_count=len(capped),
             path="subscription" if is_subscription else "one_off_optin")

    scan_id = client.request_scan(capped)
    if not scan_id:
        return None

    # Persistenz nur fuer Subscription-Pfad (Audit-Trail in subscriptions-Tabelle).
    if is_subscription:
        _persist_subscription_request(
            subscription_id=ctx["subscription_id"],
            scan_id=scan_id,
            ips=capped,
        )

    return scan_id


__all__ = ["maybe_trigger_prewarm", "PRE_WARM_IP_CAP"]

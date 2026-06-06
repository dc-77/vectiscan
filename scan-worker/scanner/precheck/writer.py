"""Persistenz-Helfer fuer Precheck-Ergebnisse."""

from __future__ import annotations

import json
import os
from typing import Any, Optional

import psycopg2
import psycopg2.extras


def _conn():
    return psycopg2.connect(
        os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan"),
        connect_timeout=10,
        options="-c statement_timeout=30000",
    )


def load_target(target_id: str) -> Optional[dict[str, Any]]:
    with _conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """SELECT id, order_id, subscription_id, raw_input, canonical,
                      target_type, discovery_policy, exclusions, status
               FROM scan_targets WHERE id = %s""",
            (target_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def set_target_status(target_id: str, status: str) -> None:
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE scan_targets SET status = %s, updated_at = NOW() WHERE id = %s",
            (status, target_id),
        )
        conn.commit()


def insert_host(
    target_id: str,
    ip: Optional[str],
    fqdns: list[str],
    is_live: bool,
    ports: list[int],
    http_status: Optional[int],
    http_title: Optional[str],
    http_final_url: Optional[str],
    reverse: Optional[str],
    cloud_provider: Optional[str],
    parking: bool,
    source: str,
) -> None:
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO scan_target_hosts
               (scan_target_id, ip, fqdns, is_live, ports_hint,
                http_status, http_title, http_final_url, reverse_dns,
                cloud_provider, parking_page, source)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (target_id, ip, fqdns, is_live, ports,
             http_status, http_title, http_final_url, reverse,
             cloud_provider, parking, source),
        )
        conn.commit()


def count_pending_targets(order_id: Optional[str], subscription_id: Optional[str]) -> int:
    """Wie viele Targets des Owners sind noch nicht fertig gecheckt?"""
    with _conn() as conn, conn.cursor() as cur:
        if order_id:
            cur.execute(
                """SELECT COUNT(*) FROM scan_targets
                   WHERE order_id = %s
                     AND status IN ('pending_precheck', 'precheck_running')""",
                (order_id,),
            )
        else:
            cur.execute(
                """SELECT COUNT(*) FROM scan_targets
                   WHERE subscription_id = %s
                     AND status IN ('pending_precheck', 'precheck_running')""",
                (subscription_id,),
            )
        return int(cur.fetchone()[0])


def update_live_hosts_count(order_id: str) -> int:
    """Summe lebender Hosts ueber alle Targets dieser Order in orders.live_hosts_count."""
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE orders SET
                 live_hosts_count = (
                   SELECT COUNT(*) FROM scan_target_hosts h
                   JOIN scan_targets t ON t.id = h.scan_target_id
                   WHERE t.order_id = %s AND h.is_live = true
                 ),
                 updated_at = NOW()
               WHERE id = %s
               RETURNING live_hosts_count""",
            (order_id, order_id),
        )
        row = cur.fetchone()
        conn.commit()
        return int(row[0]) if row and row[0] is not None else 0


def set_order_status(order_id: str, status: str) -> None:
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE orders SET status = %s, updated_at = NOW() WHERE id = %s",
            (status, order_id),
        )
        conn.commit()


# Marker fuer auto-freigegebene Targets (kein menschlicher Reviewer).
AUTO_APPROVE_NOTE = "auto-approved: verified webcheck-free domain control (VEC-172)"


def try_auto_approve_webcheck_order(order_id: str) -> bool:
    """VEC-172: Auto-Approve fuer verifizierte anonyme WebCheck-Free-Scans.

    Komplettmediation / deny-by-default. Gibt die Order NUR dann am
    Admin-Review-Gate frei (Status ``pending_target_review`` -> ``queued``),
    wenn ALLE Bedingungen erfuellt sind:

      * ``orders.package == 'webcheck'``        (Hard-Lock, kein anderes Paket)
      * ``orders.status == 'pending_target_review'``
      * ``orders.target_count == 1``            (keine Scope-Eskalation)
      * genau 1 ``scan_target``, Status ``precheck_complete``
      * es existiert ein ``webcheck_leads``-Row mit ``order_id == orders.id``
        UND ``verified = TRUE``

    Jede andere Order (Nicht-WebCheck, unverifiziert, fremd, Mehrfach-Target,
    Precheck fehlgeschlagen) bleibt UNBERUEHRT im Admin-Gate. Idempotent &
    race-sicher: die Order-Zeile wird via ``SELECT ... FOR UPDATE`` gesperrt und
    der finale Status-Uebergang per ``WHERE status = 'pending_target_review'``
    abgesichert, sodass ein paralleler/wiederholter Aufruf nicht doppelt
    freigibt.

    Returns ``True``, wenn diese Order durch *diesen* Aufruf nach ``queued``
    ueberging (der Caller MUSS dann den Scan enqueuen); sonst ``False``.
    """
    with _conn() as conn, conn.cursor() as cur:
        # Order-Zeile sperren + alle Gate-Fakten in EINER Abfrage holen.
        cur.execute(
            """SELECT o.status, o.package, o.target_count,
                      (SELECT COUNT(*) FROM webcheck_leads wl
                         WHERE wl.order_id = o.id AND wl.verified = TRUE) AS verified_leads,
                      (SELECT COUNT(*) FROM scan_targets t
                         WHERE t.order_id = o.id) AS total_targets,
                      (SELECT COUNT(*) FROM scan_targets t
                         WHERE t.order_id = o.id AND t.status = 'precheck_complete') AS complete_targets
               FROM orders o WHERE o.id = %s FOR UPDATE""",
            (order_id,),
        )
        row = cur.fetchone()
        if row is None:
            conn.rollback()
            return False
        status, package, target_count, verified_leads, total_targets, complete_targets = row

        # Deny-by-default: jede Abweichung -> kein Auto-Approve.
        if (
            status != "pending_target_review"
            or package != "webcheck"
            or int(target_count or 0) != 1
            or int(verified_leads or 0) < 1
            or int(total_targets or 0) != 1
            or int(complete_targets or 0) != 1
        ):
            conn.rollback()
            return False

        # Das einzige, precheck-fertige Target freigeben.
        cur.execute(
            """UPDATE scan_targets
               SET status = 'approved', approved_at = NOW(), updated_at = NOW(),
                   review_notes = %s
               WHERE order_id = %s AND status = 'precheck_complete'
               RETURNING id, discovery_policy, exclusions""",
            (AUTO_APPROVE_NOTE, order_id),
        )
        trow = cur.fetchone()
        if trow is None:
            conn.rollback()
            return False
        target_id, discovery_policy, exclusions = trow

        # Scan-Run-Target-Snapshot (in_scope) anlegen — spiegelt den
        # Admin-Release-Pfad in routes/admin-review.ts.
        cur.execute(
            """INSERT INTO scan_run_targets
                 (order_id, scan_target_id, in_scope,
                  snapshot_discovery_policy, snapshot_exclusions)
               VALUES (%s, %s, true, %s, %s)
               ON CONFLICT (order_id, scan_target_id) DO UPDATE
                 SET snapshot_discovery_policy = EXCLUDED.snapshot_discovery_policy,
                     snapshot_exclusions = EXCLUDED.snapshot_exclusions""",
            (order_id, target_id, discovery_policy, exclusions or []),
        )

        # Order freigeben — Status-Guard haelt den Uebergang idempotent.
        cur.execute(
            """UPDATE orders SET status = 'queued', updated_at = NOW()
               WHERE id = %s AND status = 'pending_target_review'""",
            (order_id,),
        )
        transitioned = cur.rowcount == 1
        conn.commit()
        return transitioned

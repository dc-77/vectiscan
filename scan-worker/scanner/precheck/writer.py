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

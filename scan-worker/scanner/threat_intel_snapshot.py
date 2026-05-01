"""Threat-Intel-Snapshot-Lifecycle (M2, 2026-05-01).

Aktiviert das Schema aus Migration 017 (`threat_intel_snapshots`):
einmal pro Tag wird ein Snapshot der NVD/EPSS/KEV-Daten angelegt; alle
Phase-3-Lookups innerhalb dieses Tages nutzen den Snapshot statt
Live-API-Calls.

Wirkung: Re-Scans derselben Domain im selben Tag liefern identische
CVE-Severity-Decisions (KEV-Status, EPSS-Score, NVD-CVSS).

Schema (Migration 017):
    threat_intel_snapshots (
        snapshot_id UUID PK,
        created_at TIMESTAMPTZ,
        nvd_version TEXT, kev_version TEXT, epss_version TEXT,
        nvd_data JSONB, kev_data JSONB, epss_data JSONB,
        metadata JSONB
    )
    orders.threat_intel_snapshot_id UUID FK ON DELETE SET NULL

Hinweis: Snapshot-Daten werden lazy gefuellt — d.h. der erste Phase-3-Lauf
des Tages legt einen leeren Snapshot an, holt die CVEs von NVD/EPSS/KEV,
und schreibt sie in die JSONB-Spalten. Folgelaeufe lesen aus dem Snapshot.

Implementierungs-Strategie:
- Public function `get_or_create_today_snapshot_id()` -> UUID, idempotent.
- Public function `attach_snapshot_to_order(order_id, snapshot_id)`.
- Public function `enrich_via_snapshot(snapshot_id, cve_ids)` -> dict.
  (Nutzt erst die Snapshot-JSONB; faellt auf Live-Lookup zurueck wenn
   CVE im Snapshot fehlt, persistiert das Ergebnis dann im Snapshot.)
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

import psycopg2
import psycopg2.extras
import structlog

log = structlog.get_logger()


def _get_db_conn():
    return psycopg2.connect(
        os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan"),
    )


def get_or_create_today_snapshot_id() -> Optional[str]:
    """Holt die snapshot_id fuer heute (UTC) oder legt eine neue an.

    Returns: UUID-String der Snapshot-ID, None bei DB-Fehler.

    Idempotent ueber den Tag hinweg: zweiter Aufruf am selben Tag liefert
    dieselbe ID. Snapshot-Daten (nvd_data/kev_data/epss_data) bleiben
    initial NULL — werden lazy ueber `enrich_via_snapshot` gefuellt.
    """
    try:
        conn = _get_db_conn()
        try:
            with conn.cursor() as cur:
                # Existiert heute schon ein Snapshot?
                cur.execute(
                    """
                    SELECT snapshot_id FROM threat_intel_snapshots
                     WHERE created_at::date = (NOW() AT TIME ZONE 'UTC')::date
                     ORDER BY created_at ASC
                     LIMIT 1
                    """
                )
                row = cur.fetchone()
                if row:
                    return str(row[0])

                # Neu anlegen
                cur.execute(
                    """
                    INSERT INTO threat_intel_snapshots (
                        nvd_version, kev_version, epss_version, metadata
                    )
                    VALUES (%s, %s, %s, %s::jsonb)
                    RETURNING snapshot_id
                    """,
                    (
                        datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                        datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                        datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                        json.dumps({"strategy": "lazy-fill", "version": "v1"}),
                    ),
                )
                row = cur.fetchone()
                conn.commit()
                snap_id = str(row[0]) if row else None
                log.info("threat_intel_snapshot_created", snapshot_id=snap_id)
                return snap_id
        finally:
            conn.close()
    except Exception as exc:
        log.warning("threat_intel_snapshot_fetch_failed", error=str(exc))
        return None


def attach_snapshot_to_order(order_id: str, snapshot_id: Optional[str]) -> bool:
    """Setzt orders.threat_intel_snapshot_id."""
    if not snapshot_id:
        return False
    try:
        conn = _get_db_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE orders SET threat_intel_snapshot_id = %s WHERE id = %s",
                    (snapshot_id, order_id),
                )
                conn.commit()
                return cur.rowcount > 0
        finally:
            conn.close()
    except Exception as exc:
        log.warning("attach_snapshot_failed", error=str(exc), order_id=order_id)
        return False


def get_snapshot_data(snapshot_id: str) -> dict[str, Any]:
    """Liest nvd_data + kev_data + epss_data aus dem Snapshot.

    Returns: dict mit Keys 'nvd', 'kev', 'epss'. Bei DB-Fehler / None
    werden leere Dicts zurueckgegeben.
    """
    if not snapshot_id:
        return {"nvd": {}, "kev": {}, "epss": {}}
    try:
        conn = _get_db_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    "SELECT nvd_data, kev_data, epss_data FROM threat_intel_snapshots "
                    "WHERE snapshot_id = %s",
                    (snapshot_id,),
                )
                row = cur.fetchone()
                if not row:
                    return {"nvd": {}, "kev": {}, "epss": {}}
                return {
                    "nvd": dict(row["nvd_data"] or {}),
                    "kev": dict(row["kev_data"] or {}),
                    "epss": dict(row["epss_data"] or {}),
                }
        finally:
            conn.close()
    except Exception as exc:
        log.warning("snapshot_read_failed", error=str(exc), snapshot_id=snapshot_id)
        return {"nvd": {}, "kev": {}, "epss": {}}


def merge_into_snapshot(
    snapshot_id: str,
    *,
    nvd_delta: Optional[dict[str, Any]] = None,
    kev_delta: Optional[dict[str, Any]] = None,
    epss_delta: Optional[dict[str, Any]] = None,
) -> bool:
    """Merged neue CVE-Daten in den Snapshot (lazy-fill).

    Verwendet PostgreSQLs `||` JSONB-Operator (later wins). Wenn die Spalte
    NULL ist, wird sie initialisiert.
    """
    if not snapshot_id:
        return False
    if not (nvd_delta or kev_delta or epss_delta):
        return True  # nichts zu mergen
    try:
        conn = _get_db_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE threat_intel_snapshots
                       SET nvd_data  = COALESCE(nvd_data,  '{}'::jsonb) || %s::jsonb,
                           kev_data  = COALESCE(kev_data,  '{}'::jsonb) || %s::jsonb,
                           epss_data = COALESCE(epss_data, '{}'::jsonb) || %s::jsonb
                     WHERE snapshot_id = %s
                    """,
                    (
                        json.dumps(nvd_delta or {}, default=str),
                        json.dumps(kev_delta or {}, default=str),
                        json.dumps(epss_delta or {}, default=str),
                        snapshot_id,
                    ),
                )
                conn.commit()
                return cur.rowcount > 0
        finally:
            conn.close()
    except Exception as exc:
        log.warning("snapshot_merge_failed", error=str(exc), snapshot_id=snapshot_id)
        return False


__all__ = [
    "get_or_create_today_snapshot_id",
    "attach_snapshot_to_order",
    "get_snapshot_data",
    "merge_into_snapshot",
]

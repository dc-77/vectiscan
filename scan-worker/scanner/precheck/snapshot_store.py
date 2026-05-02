"""Subdomain-Snapshot-Store fuer Phase 0b (PR-M4, 2026-05-02).

Persistiert das per-Target Subdomain-Inventar nach Phase 0b und stellt
einen Reuse-Pfad fuer nachfolgende Scans desselben Targets innerhalb der
TTL bereit.

Hintergrund TIEFENANALYSE-RUN-DRIFT-2026-05-02.md, Rang 2 der Drift-
Quellen: crt.sh / subfinder / dnsx liefern bei zwei Laeufen kurz
hintereinander leicht abweichende Subdomain-Sets, weil externe APIs
(Cert-Transparency-DB, Resolver) nicht stabil antworten. Mit diesem
Snapshot wird das Inventar einmal pro Target ermittelt und danach 24h
wiederverwendet — Re-Scans werden subdomain-deterministisch.

Laufzeit-Verhalten:
- `find_fresh_for_domain(domain)`: matched ueber `scan_targets.canonical`
  (alle approved Targets fuer diese Domain), gibt das juengste in TTL
  liegende Snapshot-Set zurueck.
- `save_for_target(target_id, ...)`: upsert, setzt `snapshot_ts = NOW()`.
- TTL-Default 24h, ueber ENV `SUBDOMAIN_SNAPSHOT_TTL_HOURS` veraenderbar
  bzw. pro Eintrag (`ttl_hours`-Spalte).
"""

from __future__ import annotations

import os
from typing import Any, Optional

import psycopg2
import psycopg2.extras


DEFAULT_TTL_HOURS = int(os.environ.get("SUBDOMAIN_SNAPSHOT_TTL_HOURS", "24"))


def _conn():
    return psycopg2.connect(
        os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan"),
        connect_timeout=10,
        options="-c statement_timeout=30000",
    )


def find_fresh_for_domain(domain: str) -> Optional[dict[str, Any]]:
    """Sucht den juengsten Snapshot innerhalb TTL fuer eine Domain.

    Match-Regel: `scan_targets.canonical = domain` (case-insensitive).
    Wir bevorzugen approved Targets, weil bei Re-Scans nur approved
    Targets in den Pre-Check kommen.

    Returns dict mit Keys ``subdomains`` (list[str]), ``tool_sources``
    (dict), ``snapshot_ts``, ``scan_target_id``, ``age_seconds``.
    Returns ``None`` wenn nichts Frisches da ist.
    """
    domain_norm = (domain or "").strip().lower()
    if not domain_norm:
        return None
    with _conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """SELECT s.scan_target_id, s.all_subdomains, s.tool_sources,
                      s.snapshot_ts, s.ttl_hours,
                      EXTRACT(EPOCH FROM (NOW() - s.snapshot_ts))::int AS age_seconds
                 FROM scan_target_subdomain_snapshots s
                 JOIN scan_targets t ON t.id = s.scan_target_id
                WHERE LOWER(t.canonical) = %s
                  AND s.snapshot_ts > NOW() - (s.ttl_hours || ' hours')::interval
                ORDER BY s.snapshot_ts DESC
                LIMIT 1""",
            (domain_norm,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "scan_target_id": str(row["scan_target_id"]),
            "subdomains": list(row["all_subdomains"] or []),
            "tool_sources": dict(row["tool_sources"] or {}),
            "snapshot_ts": row["snapshot_ts"],
            "ttl_hours": int(row["ttl_hours"]),
            "age_seconds": int(row["age_seconds"]),
        }


def save_for_target(
    scan_target_id: str,
    all_subdomains: list[str],
    tool_sources: dict[str, list[str]],
    ttl_hours: int = DEFAULT_TTL_HOURS,
) -> None:
    """Upsert eines Snapshots.

    `tool_sources` ist eine Mapping `tool_name -> list[subdomain]`.
    Wird als JSONB persistiert, damit spaetere Audits sehen koennen,
    welcher Tool welche Subdomain beigetragen hat.
    """
    if not scan_target_id:
        return
    subs_norm = sorted(set(s.strip().lower() for s in (all_subdomains or []) if s and s.strip()))
    sources_norm: dict[str, list[str]] = {}
    for tool, subs in (tool_sources or {}).items():
        sources_norm[tool] = sorted(set(s.strip().lower() for s in subs if s and s.strip()))
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO scan_target_subdomain_snapshots
                 (scan_target_id, all_subdomains, tool_sources, snapshot_ts, ttl_hours)
               VALUES (%s, %s, %s, NOW(), %s)
               ON CONFLICT (scan_target_id) DO UPDATE SET
                 all_subdomains = EXCLUDED.all_subdomains,
                 tool_sources   = EXCLUDED.tool_sources,
                 snapshot_ts    = EXCLUDED.snapshot_ts,
                 ttl_hours      = EXCLUDED.ttl_hours,
                 updated_at     = NOW()""",
            (scan_target_id, subs_norm, psycopg2.extras.Json(sources_norm), ttl_hours),
        )
        conn.commit()


def invalidate_for_target(scan_target_id: str) -> None:
    """Loescht den Snapshot fuer ein Target — z.B. wenn der Admin manuell
    sagt „nochmal komplett neu enumerieren"."""
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM scan_target_subdomain_snapshots WHERE scan_target_id = %s",
            (scan_target_id,),
        )
        conn.commit()


__all__ = [
    "DEFAULT_TTL_HOURS",
    "find_fresh_for_domain",
    "save_for_target",
    "invalidate_for_target",
]

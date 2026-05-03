#!/usr/bin/env python3
"""Backfill der Subscription-Posture aus historischen Orders (PR-Posture, 2026-05-03).

Iteriert ueber alle Subscriptions, laedt deren Orders chronologisch
(aelteste zuerst) und ruft `aggregate_into_posture(order_id, findings_data)`
fuer jede Order auf. Idempotent — kann mehrfach laufen, dedup ueber
uq_dedup_key.

Verwendung:
    python scripts/backfill-posture.py [--dry-run] [--subscription-id <uuid>]

ENV:
    DATABASE_URL  postgresql://...

Im Container (vectiscan-report-worker hat reporter-Modul auf PYTHONPATH):
    docker compose exec report-worker python /app/scripts/backfill-posture.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import psycopg2
import psycopg2.extras


def main() -> int:
    parser = argparse.ArgumentParser(description="Posture backfill")
    parser.add_argument("--dry-run", action="store_true",
                        help="Nur listen welche Subscriptions/Orders verarbeitet wuerden")
    parser.add_argument("--subscription-id", type=str, default=None,
                        help="Nur eine Subscription verarbeiten")
    args = parser.parse_args()

    db_url = os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan")
    print(f"[backfill] connecting: {db_url.split('@')[-1] if '@' in db_url else db_url}")
    conn = psycopg2.connect(db_url)

    # 1. Subscriptions auflisten
    sql = "SELECT id FROM subscriptions"
    params: tuple = ()
    if args.subscription_id:
        sql += " WHERE id = %s"
        params = (args.subscription_id,)
    sql += " ORDER BY started_at"

    with conn.cursor() as cur:
        cur.execute(sql, params)
        sub_ids = [str(r[0]) for r in cur.fetchall()]
    print(f"[backfill] subscriptions to process: {len(sub_ids)}")

    if args.dry_run:
        print("[backfill] DRY RUN — nichts wird geschrieben")

    # 2. pro Subscription: Orders chronologisch
    from reporter.posture_aggregator import aggregate_into_posture

    total_orders = 0
    total_findings = 0
    for sub_id in sub_ids:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT o.id, o.created_at, r.findings_data
                   FROM orders o
                   LEFT JOIN LATERAL (
                       SELECT findings_data FROM reports
                       WHERE order_id = o.id ORDER BY version DESC LIMIT 1
                   ) r ON true
                   WHERE o.subscription_id = %s
                     AND o.status IN ('report_complete', 'delivered', 'pending_review')
                   ORDER BY o.created_at ASC""",
                (sub_id,),
            )
            orders = cur.fetchall()

        print(f"[backfill] subscription={sub_id}: {len(orders)} orders")
        for o in orders:
            order_id = str(o["id"])
            fd = o["findings_data"] or {}
            if isinstance(fd, str):
                try:
                    fd = json.loads(fd)
                except Exception:
                    fd = {}
            n_findings = len(fd.get("findings", []) or [])
            print(f"  - {order_id} ({o['created_at']:%Y-%m-%d %H:%M}) {n_findings} findings")
            total_findings += n_findings

            if not args.dry_run:
                try:
                    snap = aggregate_into_posture(conn, order_id, fd)
                    if snap:
                        print(f"    → score={snap.posture_score} new={snap.new_findings} "
                              f"resolved={snap.resolved_findings} regressed={snap.regressed_findings}")
                except Exception as e:
                    print(f"    ERROR: {e}", file=sys.stderr)
            total_orders += 1

    conn.close()
    print(f"[backfill] done — subscriptions={len(sub_ids)} orders={total_orders} findings={total_findings}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

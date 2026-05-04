#!/usr/bin/env python3
"""Forensik: vergleicht 2 Orders pro Tool, zeigt Diff der Tool-Outputs.

Usage:
    python scripts/diff-orders.py <order_a> <order_b> [--tools tool1,tool2]
    python scripts/diff-orders.py <order_a> <order_b> --policy-ids   # Vergleich der Findings-Policy-IDs

Liest scan_results-Tabelle, wendet output_normalizer an, gibt unified Diff
pro Tool aus. Hilft bei Determinismus-Outliern (z.B. 3fa6a538 vs 434f06b3 —
warum HIGH bei dem einen, MEDIUM beim anderen?).

Voraussetzung: DATABASE_URL gesetzt, scan-worker venv aktiv.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
from pathlib import Path

# scan-worker scanner-Modul auf sys.path
_SCAN_WORKER = Path(__file__).resolve().parent.parent / "scan-worker"
if _SCAN_WORKER.exists():
    sys.path.insert(0, str(_SCAN_WORKER))

try:
    from scanner.output_normalizer import normalize  # type: ignore
except Exception:
    def normalize(_tool: str, raw):  # type: ignore
        return raw

import psycopg2  # noqa: E402


def fetch_results(conn, order_id: str, tools_filter: list[str] | None = None) -> dict[str, dict]:
    """Liefert {tool_name: {host_ip, raw_output_normalized}} pro Tool."""
    where = "WHERE order_id = %s"
    params: list = [order_id]
    if tools_filter:
        placeholders = ",".join(["%s"] * len(tools_filter))
        where += f" AND tool_name IN ({placeholders})"
        params.extend(tools_filter)
    with conn.cursor() as cur:
        cur.execute(
            f"""SELECT tool_name, host_ip, raw_output, exit_code, duration_ms
                  FROM scan_results
                  {where}
                  ORDER BY tool_name, host_ip""",
            tuple(params),
        )
        rows = cur.fetchall()
    out: dict[str, dict] = {}
    for tool, host_ip, raw, exit_code, dur in rows:
        # Mehrere Hosts pro Tool moeglich → key = (tool, host_ip)
        key = f"{tool}@{host_ip or 'global'}"
        out[key] = {
            "tool": tool,
            "host_ip": host_ip,
            "raw": normalize(tool, raw or ""),
            "exit_code": exit_code,
            "duration_ms": dur,
        }
    return out


def fetch_policy_ids(conn, order_id: str) -> dict[str, list[str]]:
    """Liefert {report_id: [policy_id, ...]} der Order."""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT id, policy_id_distinct, severity_counts, findings_data->'findings'
                 FROM reports
                WHERE order_id = %s
                ORDER BY created_at DESC""",
            (order_id,),
        )
        return {str(rid): {
            "policy_ids": list(pids or []),
            "severity": sev,
            "finding_count": len(findings or []),
        } for rid, pids, sev, findings in cur.fetchall()}


def diff_text(a: str, b: str, label_a: str, label_b: str) -> str:
    """Unified Diff zweier Strings."""
    diff = difflib.unified_diff(
        (a or "").splitlines(keepends=True),
        (b or "").splitlines(keepends=True),
        fromfile=label_a, tofile=label_b, n=2,
    )
    return "".join(diff)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("order_a", help="Order-A UUID (Referenz)")
    ap.add_argument("order_b", help="Order-B UUID (Vergleich)")
    ap.add_argument("--tools", help="Comma-separated tool-Filter")
    ap.add_argument("--policy-ids", action="store_true",
                    help="Vergleiche nur Findings-Policy-IDs (kompakt)")
    ap.add_argument("--max-diff-lines", type=int, default=50,
                    help="Max Zeilen pro Diff (default: 50)")
    args = ap.parse_args()

    db_url = os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan")
    conn = psycopg2.connect(db_url, connect_timeout=5)

    try:
        if args.policy_ids:
            print(f"=== Policy-IDs Vergleich ===")
            print(f"Order A: {args.order_a}")
            print(f"Order B: {args.order_b}")
            print()
            pa = fetch_policy_ids(conn, args.order_a)
            pb = fetch_policy_ids(conn, args.order_b)
            sa = set().union(*(set(r["policy_ids"]) for r in pa.values())) if pa else set()
            sb = set().union(*(set(r["policy_ids"]) for r in pb.values())) if pb else set()
            both = sa & sb
            only_a = sa - sb
            only_b = sb - sa
            union = sa | sb
            score = round(len(both) / max(len(union), 1) * 100, 1) if union else 0
            print(f"Schnittmenge: {len(both)}")
            print(f"Nur in A: {len(only_a)}  → {sorted(only_a)[:10]}")
            print(f"Nur in B: {len(only_b)}  → {sorted(only_b)[:10]}")
            print(f"Vereinigung: {len(union)}")
            print(f"Determinismus-Score: {score}%")
            return

        # Tool-Diff-Modus
        tools_filter = args.tools.split(",") if args.tools else None
        print(f"=== Tool-Output-Diff ===")
        print(f"Order A: {args.order_a}")
        print(f"Order B: {args.order_b}")
        if tools_filter:
            print(f"Tools-Filter: {tools_filter}")
        print()

        ra = fetch_results(conn, args.order_a, tools_filter)
        rb = fetch_results(conn, args.order_b, tools_filter)
        all_keys = sorted(set(ra.keys()) | set(rb.keys()))

        for key in all_keys:
            a = ra.get(key)
            b = rb.get(key)
            if a is None:
                print(f"[ONLY-B] {key}")
                continue
            if b is None:
                print(f"[ONLY-A] {key}")
                continue
            if a["raw"] == b["raw"]:
                print(f"[IDENTICAL] {key}  (after normalize)")
                continue
            print(f"[DIFF] {key}  (exit {a['exit_code']}/{b['exit_code']},  duration {a['duration_ms']}/{b['duration_ms']}ms)")
            d = diff_text(a["raw"][:50000], b["raw"][:50000],
                          f"A:{key}", f"B:{key}").splitlines()
            for line in d[:args.max_diff_lines]:
                print(f"   {line.rstrip()}")
            if len(d) > args.max_diff_lines:
                print(f"   ... +{len(d) - args.max_diff_lines} weitere Zeilen abgeschnitten")
            print()
    finally:
        conn.close()


if __name__ == "__main__":
    main()

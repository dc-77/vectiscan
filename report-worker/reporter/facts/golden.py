"""Golden-Facts: eine Funktion fuer CLI (``--golden``) und Test (Drift-Guard).

Quelle je Order: ``tests/golden/tars/<order>.tar.gz`` plus die ``scan_results``-Zeilen
aus ``tests/golden/api-snapshot/<order>/results.json`` und die Zielliste aus
``api-snapshot/orders.json``. Ergebnis: ``tests/golden/facts/<order>.json``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reporter.facts.build import build_facts, build_from_snapshot
from reporter.facts.serialize import dumps, load_json, write_json

REPORT_WORKER_ROOT = Path(__file__).resolve().parents[2]
GOLDEN = REPORT_WORKER_ROOT / "tests" / "golden"
FACTS_DIR = GOLDEN / "facts"
SNAPSHOT = GOLDEN / "api-snapshot"


def golden_orders() -> list[dict[str, Any]]:
    manifest = load_json(GOLDEN / "manifest.json")
    return [o for o in manifest.get("orders", []) if o.get("tar", {}).get("present")]


def tar_path(order_id: str) -> Path:
    return GOLDEN / "tars" / f"{order_id}.tar.gz"


def results_path(order_id: str) -> Path | None:
    p = SNAPSHOT / order_id / "results.json"
    return p if p.exists() else None


def build_golden_facts(order_id: str):
    """Facts fuer eine Golden-Order aus Tar + Snapshot-Zeilen + Zielliste."""
    orders_json = SNAPSHOT / "orders.json"
    return build_facts(tar_path(order_id), tool_runs=results_path(order_id),
                       orders_json=orders_json if orders_json.exists() else None)


def build_snapshot_facts(order_id: str):
    """Facts nur aus dem API-Snapshot (Orders ohne Tar)."""
    return build_from_snapshot(SNAPSHOT / order_id)


def facts_path(order_id: str) -> Path:
    return FACTS_DIR / f"{order_id}.json"


def build_all_golden() -> list[tuple[str, Path]]:
    written: list[tuple[str, Path]] = []
    for order in golden_orders():
        oid = order["order_id"]
        facts = build_golden_facts(oid)
        path = facts_path(oid)
        write_json(path, facts.to_dict())
        written.append((oid, path))
    return written


def check_all_golden() -> list[tuple[str, str]]:
    diffs: list[tuple[str, str]] = []
    for order in golden_orders():
        oid = order["order_id"]
        path = facts_path(oid)
        if not path.exists():
            diffs.append((oid, f"{path.name} fehlt"))
            continue
        current = build_golden_facts(oid).to_dict()
        stored = load_json(path)
        if current != stored:
            diffs.append((oid, first_difference(stored, current)))
    return diffs


def first_difference(a: Any, b: Any, path: str = "$") -> str:
    """Erste abweichende Stelle zweier JSON-Strukturen als Pfad."""
    if type(a) is not type(b):
        return f"{path}: Typ {type(a).__name__} != {type(b).__name__}"
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                return f"{path}.{k}: fehlt im Bestand"
            if k not in b:
                return f"{path}.{k}: fehlt im Neubau"
            d = first_difference(a[k], b[k], f"{path}.{k}")
            if d:
                return d
        return ""
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: Laenge {len(a)} != {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{path}[{i}]")
            if d:
                return d
        return ""
    if a != b:
        return f"{path}: {json.dumps(a, ensure_ascii=False)[:80]} != {json.dumps(b, ensure_ascii=False)[:80]}"
    return ""


__all__ = ["GOLDEN", "FACTS_DIR", "SNAPSHOT", "golden_orders", "build_golden_facts",
           "build_snapshot_facts", "facts_path", "build_all_golden", "check_all_golden",
           "first_difference", "dumps"]

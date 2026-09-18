"""CLI: facts.json aus einem Roh-Tar, Scan-Verzeichnis oder API-Snapshot bauen.

    python -m reporter.facts <tar|dir> [--tool-runs results.json] [--orders orders.json] [-o facts.json]
    python -m reporter.facts --snapshot <api-snapshot/<order>> [-o facts.json]
    python -m reporter.facts --golden [--check]

Ohne ``-o`` landet die Datei neben der Quelle als ``<order>.facts.json``. ``--golden`` baut
die Golden-Facts fuer alle Manifest-Orders (``tests/golden/facts/<order>.json``);
``--check`` schreibt nichts und meldet Abweichungen mit Exit 1.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from reporter.facts.build import build_facts, build_from_snapshot
from reporter.facts.serialize import dumps, write_json


def _summary(facts) -> str:
    parts = [f"{name}={len(getattr(facts, name))}" for name in facts.ENTITY_FIELDS]
    return f"order={facts.scan.order_id} " + " ".join(parts) + f" warnings={len(facts.warnings)}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m reporter.facts", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", nargs="?", help="Roh-Tar (.tar.gz) oder entpacktes Scan-Verzeichnis")
    ap.add_argument("--tool-runs", help="results.json (scan_results-Zeilen, API-Form oder Liste)")
    ap.add_argument("--orders", help="api-snapshot/orders.json fuer die Zielliste (Multi-Target)")
    ap.add_argument("--snapshot", help="api-snapshot/<order>-Verzeichnis statt Tar")
    ap.add_argument("--golden", action="store_true", help="alle Golden-Orders bauen")
    ap.add_argument("--check", action="store_true", help="mit --golden: nur vergleichen, nichts schreiben")
    ap.add_argument("-o", "--out", help="Zieldatei (Default: <order>.facts.json neben der Quelle, '-' = stdout)")
    args = ap.parse_args(argv)

    if args.golden:
        from reporter.facts.golden import build_all_golden, check_all_golden
        if args.check:
            diffs = check_all_golden()
            for order_id, msg in diffs:
                print(f"ABWEICHUNG {order_id}: {msg}", file=sys.stderr)
            print(f"golden: {len(diffs)} Abweichung(en)", file=sys.stderr)
            return 1 if diffs else 0
        for order_id, path in build_all_golden():
            print(f"geschrieben {order_id[:8]} -> {path}", file=sys.stderr)
        return 0

    if args.snapshot:
        facts = build_from_snapshot(args.snapshot)
        default_out = Path(args.snapshot) / f"{facts.scan.order_id}.facts.json"
    elif args.source:
        facts = build_facts(args.source, tool_runs=args.tool_runs, orders_json=args.orders)
        src = Path(args.source)
        default_out = (src.parent if src.is_file() else src) / f"{facts.scan.order_id}.facts.json"
    else:
        ap.error("Quelle fehlt: Tar/Verzeichnis, --snapshot oder --golden")
        return 2

    data = facts.to_dict()
    if args.out == "-":
        sys.stdout.write(dumps(data))
    else:
        out = Path(args.out) if args.out else default_out
        write_json(out, data)
        print(f"geschrieben {out}", file=sys.stderr)
    print(_summary(facts), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

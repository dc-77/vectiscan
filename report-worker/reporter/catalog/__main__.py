"""CLI: Pruefkatalog auf eine facts.json anwenden.

    python -m reporter.catalog <facts.json> [-o ergebnis.json|-]
    python -m reporter.catalog --golden <order_id> [-o ...]
    python -m reporter.catalog --snapshot tests/golden/api-snapshot/<order> [-o ...]

Ohne ``-o`` geht das JSON nach stdout (UTF-8, LF). Die Zusammenfassung steht auf stderr.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from reporter.catalog.engine import evaluate, load_catalog
from reporter.facts.serialize import dumps, load_json, write_json


def _summary(out) -> str:
    s = out.summary
    st = " ".join(f"{k}={v}" for k, v in s.by_status.items())
    return (f"order={out.order_id} catalog={out.catalog_version} checks={s.checks} results={s.results} {st} "
            f"positives={s.positives} unprocessed={s.unprocessed} ignored={s.ignored}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m reporter.catalog", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("facts", nargs="?", help="facts.json (Ausgabe von reporter.facts)")
    ap.add_argument("--golden", help="Order-ID: liest tests/golden/facts/<order>.json")
    ap.add_argument("--snapshot", help="api-snapshot/<order>-Verzeichnis: baut Facts ueber reporter.facts")
    ap.add_argument("--catalog-dir", help="abweichendes Katalogverzeichnis (Tests)")
    ap.add_argument("-o", "--out", help="Zieldatei ('-' oder leer = stdout)")
    args = ap.parse_args(argv)

    if args.golden:
        from reporter.facts.golden import facts_path
        facts = load_json(facts_path(args.golden))
    elif args.snapshot:
        from reporter.facts.build import build_from_snapshot
        facts = build_from_snapshot(args.snapshot).to_dict()
    elif args.facts:
        facts = load_json(Path(args.facts))
    else:
        ap.error("Quelle fehlt: facts.json, --golden oder --snapshot")
        return 2

    catalog = load_catalog(args.catalog_dir) if args.catalog_dir else None
    out = evaluate(facts, catalog)
    data = out.to_dict()
    if not args.out or args.out == "-":
        sys.stdout.buffer.write(dumps(data).encode("utf-8"))
        sys.stdout.buffer.flush()
    else:
        write_json(Path(args.out), data)
        print(f"geschrieben {args.out}", file=sys.stderr)
    print(_summary(out), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

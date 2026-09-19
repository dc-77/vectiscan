# -*- coding: utf-8 -*-
"""CLI: python -m reporter.v3 <facts.json> [katalog.json] [-o out.json]

Weitere Formen:
    python -m reporter.v3 --golden <order_id>     Fakten und Katalog selbst bauen
    python -m reporter.v3 <facts.json> --no-prose kein KI-Aufruf, nur Katalogtexte

Ohne ``ANTHROPIC_API_KEY`` laeuft alles mit Katalogtexten durch; das ist kein Fehler.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from reporter.facts.serialize import dumps
from reporter.v3.report_data import build_report_data
from reporter.v3.selfcheck import check_report_data


def _load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="reporter.v3", description=__doc__)
    ap.add_argument("facts", nargs="?", help="facts.json aus reporter.facts")
    ap.add_argument("catalog", nargs="?", help="Ergebnis aus reporter.catalog (optional)")
    ap.add_argument("--golden", metavar="ORDER_ID", help="Golden-Order aus tests/golden/facts")
    ap.add_argument("--golden-all", action="store_true",
                    help="Golden-Reportdaten aller Auftraege neu bauen")
    ap.add_argument("--check", action="store_true",
                    help="mit --golden-all nur vergleichen, nichts schreiben")
    ap.add_argument("--order", help="order.json mit Kundenname und Lauf-Liste")
    ap.add_argument("--customer-context", help="JSON mit kuerzel, branche, mitarbeiter, systeme")
    ap.add_argument("--report-version", default="1.0")
    ap.add_argument("--report-date", help="TT.MM.JJJJ, sonst heute")
    ap.add_argument("--no-prose", action="store_true", help="ohne KI-Aufruf")
    ap.add_argument("-o", "--out", help="Zieldatei, - fuer stdout")
    args = ap.parse_args(argv)

    if args.golden_all:
        from reporter.v3.golden import build_all_golden

        results = build_all_golden(check=args.check)
        drift = [oid for oid, same in results if not same]
        for oid, same in results:
            print(f"{oid} {'unveraendert' if same else 'neu gebaut' if not args.check else 'DRIFT'}",
                  file=sys.stderr)
        return 1 if (args.check and drift) else 0

    if args.golden:
        from reporter.facts.golden import facts_path

        path = facts_path(args.golden)
        if not path.exists():
            print(f"keine Golden-Fakten fuer {args.golden}", file=sys.stderr)
            return 2
        facts = _load(str(path))
    elif args.facts:
        facts = _load(args.facts)
    else:
        ap.error("facts.json oder --golden noetig")
        return 2

    catalog = _load(args.catalog) if args.catalog else None
    order = _load(args.order) if args.order else None
    context = _load(args.customer_context) if args.customer_context else None

    prose: dict[str, Any] | None = None
    if not args.no_prose:
        from reporter.v3 import prose as P

        if P.available():
            draft = build_report_data(facts, catalog, order=order, customer_context=context,
                                      report_version=args.report_version,
                                      report_date=args.report_date)
            fields, _cost = P.generate(P.build_payload(draft, context),
                                       order_id=draft.meta.orders[0].id if draft.meta.orders else None)
            prose = fields or None

    data = build_report_data(facts, catalog, order=order, customer_context=context,
                             report_version=args.report_version, report_date=args.report_date,
                             prose=prose)
    errors = check_report_data(data)
    for error in errors:
        print(f"SELBSTCHECK: {error}", file=sys.stderr)

    text = dumps(data.to_dict())
    if args.out in (None, "-"):
        sys.stdout.write(text + "\n")
    else:
        Path(args.out).write_text(text + "\n", encoding="utf-8", newline="")
    print(f"order={data.meta.orders[0].id if data.meta.orders else '?'} "
          f"befunde={len(data.findings)} positive={len(data.positives)} "
          f"plan={len(data.plan)} defekte={len(errors)}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

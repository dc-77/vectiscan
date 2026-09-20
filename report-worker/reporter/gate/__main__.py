# -*- coding: utf-8 -*-
"""Das Gate von Hand fahren (S5).

Zwei Zwecke:

* Nachsehen, was das Gate zu einem Auftrag sagt, ohne einen Bericht zu bauen.
* Die Abnahme: einen vorhandenen Auftrag gezielt beschaedigen und zeigen, dass
  er unter ``strict`` auf ``report_blocked`` landet und im Admin sichtbar ist.

Beschaedigt wird immer nur die Kopie im Speicher, nie ein Tar und nie eine
Faktendatei. ``--apply`` schreibt Defektliste und Status auf die Order; ohne den
Schalter wird nur ausgegeben.

    python -m reporter.gate --order <uuid>
    python -m reporter.gate --order <uuid> --damage abdeckung --apply
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from reporter.gate import defects as GD
from reporter.gate import v3_checks

# Die Beschaedigungen. Jede trifft genau eine Pruefung, damit die Abnahme zeigt,
# welche Regel gegriffen hat.
DAMAGES = ("abdeckung", "tech", "ids", "keine")


def _damage(data: Any, facts: Any, art: str) -> str:
    """Datenmodell gezielt beschaedigen. Liefert eine Beschreibung."""
    if art == "abdeckung":
        for host in data.scope.hosts:
            host.coverage = ""
        return "Abdeckung aller Hosts geleert (Kapitel 2 ohne Angaben)"
    if art == "tech":
        if not data.findings:
            return "keine Befunde vorhanden, nichts beschaedigt"
        # Ein Produkt nehmen, das wirklich in der Tech-Tabelle steht, und im
        # Befund eine Hauptversion behaupten, die es dort nicht gibt.
        treffer = next((sw for sw in facts.software
                        if sw.version_norm and sw.version_norm[0].isdigit()), None)
        if treffer is None:
            return "keine Software mit Version in den Fakten, nichts beschaedigt"
        falsch = int(treffer.version_norm.split(".")[0]) + 100
        finding = data.findings[0]
        finding.title = f"{treffer.product} {falsch}.0 wird nicht mehr gepflegt"
        finding.affected = f"{treffer.host_ip}:443"
        return (f"Befund {finding.id} behauptet {treffer.product} {falsch}.0 auf "
                f"{treffer.host_ip}, die Tabelle nennt {treffer.version_norm}")
    if art == "ids":
        if len(data.findings) < 2:
            return "zu wenige Befunde, nichts beschaedigt"
        data.findings[1].id = data.findings[0].id
        return "zwei Befunde tragen dieselbe ID"
    return "nichts beschaedigt"


def _block(order_id: str, payload: dict) -> None:
    """Defektliste und Status auf die Order schreiben."""
    import psycopg2

    from reporter.worker import DATABASE_URL, _store_report_defects, _update_order_status

    with psycopg2.connect(DATABASE_URL) as conn:
        _store_report_defects(conn, order_id, payload)
        _update_order_status(
            conn, order_id, "report_blocked",
            error_message=f"Bericht v3 blockiert: {payload['counts']['errors']} Defekte")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m reporter.gate",
                                 description="Gate eines Auftrags pruefen")
    ap.add_argument("--order", required=True, help="Order-UUID")
    ap.add_argument("--tar", help="Roh-Tar statt Download aus MinIO")
    ap.add_argument("--damage", choices=DAMAGES, default="keine",
                    help="Datenmodell gezielt beschaedigen (nur im Speicher)")
    ap.add_argument("--apply", action="store_true",
                    help="Defektliste und Status report_blocked auf die Order schreiben")
    args = ap.parse_args(argv)

    # Das JSON geht nach stdout und soll durch eine Pipe lesbar bleiben; die
    # Logzeilen der Bibliotheken gehoeren daneben, nicht mittenrein.
    import structlog

    structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=sys.stderr))

    from reporter.pdf.v3.pipeline import (fetch_rawdata, minio_client,
                                          report_bundle_from_source,
                                          tool_runs_from_db)
    from reporter.v3.selfcheck import check_report_data_detailed

    with tempfile.TemporaryDirectory(prefix=f"gate-{args.order}-") as tmp:
        quelle = Path(args.tar) if args.tar else fetch_rawdata(
            minio_client(), args.order, Path(tmp))
        facts, output, data = report_bundle_from_source(
            quelle, tool_runs=tool_runs_from_db(args.order))

    beschreibung = _damage(data, facts, args.damage)

    liste = GD.from_selfcheck(check_report_data_detailed(data))
    liste.extend(v3_checks.run_all(data, facts, output))
    payload = GD.payload(liste, engine="v3", level="strict", facts=facts,
                         output=output, blocked=any(d.is_error for d in liste))

    ausgabe = {
        "order_id": args.order,
        "beschaedigung": beschreibung if args.damage != "keine" else None,
        **payload,
    }
    print(json.dumps(ausgabe, ensure_ascii=False, indent=2))

    if args.apply:
        if not payload["counts"]["errors"]:
            print("Keine Defekte, Order bleibt unveraendert.", file=sys.stderr)
            return 0
        _block(args.order, payload)
        print(f"Order {args.order} steht auf report_blocked "
              f"({payload['counts']['errors']} Defekte).", file=sys.stderr)
    return 1 if payload["counts"]["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

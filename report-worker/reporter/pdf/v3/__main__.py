# -*- coding: utf-8 -*-
"""CLI des Renderers v3.

    python -m reporter.pdf.v3 --golden <order_id> [-o bericht.pdf] [--html b.html]
    python -m reporter.pdf.v3 --source <tar|verzeichnis> -o bericht.pdf
    python -m reporter.pdf.v3 --order <order_id> --upload      # holt das Tar aus MinIO
    python -m reporter.pdf.v3 --selftest                       # Abnahme im Abbild
    python -m reporter.pdf.v3 --write-snapshot                 # Regressionsdatei neu

``--golden`` und ``--source`` bauen die Reportdaten ohne Sprachmodell (Katalogtexte).
``--upload`` legt das PDF unter ``scan-debug/v3/`` ab und laesst Auftrag, Status und
``reports`` unberuehrt.

``--context`` holt den Kundenkontext der Order (S5), ``--prose`` laesst zusaetzlich
die Prosa-KI laufen und meldet, welche Felder das Gate genommen und welche es
abgelehnt hat. Beides ist fuer die Abnahme auf Produktion gedacht; der Auftrag
bleibt auch damit unberuehrt.
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPORT_WORKER = Path(__file__).resolve().parents[3]
SNAPSHOT_DIR = REPORT_WORKER / "tests" / "golden" / "render"
SNAPSHOT_ORDER = "0bf16342-ed96-4b0e-a596-05aee3a62cb5"
PAGES_FILE = SNAPSHOT_DIR / "expected-pages.json"

# Fuer den Selbsttest: ein grosser Auftrag mit Anhang zu Kapitel 6, ein mittlerer mit
# mehreren Domains, ein kleiner. Mehr braucht die Abnahme im Abbild nicht.
SELFTEST_ORDERS = (
    "4e6b6883-a6c8-4204-8b13-b37f907322ca",   # castenow, 29 Befunde
    SNAPSHOT_ORDER,                            # Junkerwerk, drei Laeufe
    "a6df9d9d-eccd-49d1-8dd3-b00a5e005108",   # junkerwerk.hu, kurz
)

# Der Auftrag, gegen den der Prototyp entworfen wurde. Hier gilt die Vorgabe aus S4
# unveraendert: keine halbleere Seite. Bei den uebrigen Auftraegen wird der Ist-Stand
# festgeschrieben, damit eine *neue* halbleere Seite auffaellt.
REFERENZ_ORDER = SNAPSHOT_ORDER

# Fester Stichtag, damit Seitenzahl und Schnappschuss nicht vom Kalender abhaengen.
REPORT_DATE = "19.09.2026"


def _kundenkontext(order_id: str) -> dict:
    """Kundenkontext der Order aus der Datenbank (S5). Leer, wenn nichts da ist."""
    try:
        import psycopg2

        from reporter.worker import DATABASE_URL, _load_customer_context
        with psycopg2.connect(DATABASE_URL) as conn:
            return _load_customer_context(conn, order_id)
    except Exception as exc:  # pragma: no cover - Datenbankpfad
        print(f"Kundenkontext nicht lesbar: {exc}", file=sys.stderr)
        return {}


def _golden_data(order_id: str):
    from reporter.v3.golden import build_golden_report_data
    return build_golden_report_data(order_id)


def _snapshot_path(order_id: str) -> Path:
    return SNAPSHOT_DIR / f"{order_id}.html.gz"


def _write_snapshot(order_id: str) -> Path:
    from reporter.pdf.v3 import render_html
    html = render_html(_golden_data(order_id))[0]
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    path = _snapshot_path(order_id)
    # mtime=0, damit zwei Laeufe dieselbe Datei ergeben und der Diff aussagekraeftig ist.
    with gzip.GzipFile(path, "wb", mtime=0) as fh:
        fh.write(html.encode("utf-8"))
    return path


def erwartungen() -> dict[str, dict]:
    if not PAGES_FILE.exists():
        return {}
    return json.loads(PAGES_FILE.read_text(encoding="utf-8"))


def pruefe(order_id: str, result, soll: dict | None) -> list[str]:
    """Abweichungen eines Renders vom Erwartungswert."""
    fehler = [f"{order_id[:8]} Defekt: {d}" for d in result.defects]
    # Ohne pypdf liefern Sparse- und Schriftpruefung stillschweigend nichts. Das waere
    # eine gruene Abnahme ohne eine einzige Pruefung.
    if not result.words_per_page:
        fehler.append(f"{order_id[:8]} keine Wortzahl je Seite (pypdf fehlt?)")
    fehler += [f"{order_id[:8]} {w}" for w in result.warnings
               if "Schrift nicht eingebettet" in w]
    # S6b-1 (spec/09 Teil 3, Entscheidung DC): in der Golden-Render-Suite ist ein Kicker
    # ohne Ueberschrift auf derselben Seite ein Fehler, im Produktionsgate eine Warnung.
    # Dasselbe gilt fuer Boxen ausserhalb des Satzspiegels. Ohne lesbare Seitenboxen
    # waere die Pruefung stumm, deshalb ist auch das ein Fehler.
    if not result.layout_ok:
        fehler.append(f"{order_id[:8]} Layoutpruefung nicht verfuegbar")
    fehler += [f"{order_id[:8]} Kicker ohne Überschrift auf Seite {p}" for p in result.kicker_pages]
    fehler += [f"{order_id[:8]} außerhalb des Satzspiegels: {w}" for w in result.overflow]
    if order_id == REFERENZ_ORDER and result.sparse_pages:
        fehler.append(f"{order_id[:8]} halbleere Seiten {list(result.sparse_pages)} "
                      "im Referenzauftrag")
    if soll is None:
        fehler.append(f"{order_id[:8]} kein Erwartungswert in {PAGES_FILE.name}")
        return fehler
    if result.pages != soll["pages"]:
        fehler.append(f"{order_id[:8]} Seitenzahl {result.pages} statt {soll['pages']}")
    neu = sorted(set(result.sparse_pages) - set(soll.get("sparse", [])))
    if neu:
        fehler.append(f"{order_id[:8]} neue halbleere Seiten {neu}")
    return fehler


def _kennzahlen(order_id: str | None, *, tar: bool) -> int:
    """Nur nachsehen, nichts schreiben: kommt die Faktenschicht in Produktion an?

    Die Zahlen sind genau die Abnahmepunkte aus S5b: Abdeckung je Host (nicht
    ``unknown``), TLS-Protokolle vorhanden, Anhang A.3 gefuellt, Defekte des
    Gates, dazu Laufzeit und Spitzenspeicher. Geladen wird ueber dieselben Wege
    wie im Worker: Roh-Tar aus MinIO und ``scan_results`` ueber
    ``_load_tool_runs``. Auftrag, ``reports`` und Defektliste bleiben unberuehrt.
    """
    import time
    try:
        import resource  # nur unter Unix, also im Abbild und in der Pipeline
    except ImportError:  # pragma: no cover - Windows
        resource = None  # type: ignore[assignment]

    from reporter import engine as _engine
    from reporter.gate import v3_checks
    from reporter.gate.defects import Defect  # noqa: F401  (Typ fuer die Lesbarkeit)
    from reporter.pdf.v3 import pipeline as P
    from reporter.v3.selfcheck import check_report_data_detailed

    if not order_id:
        print("--kennzahlen braucht --order oder --golden", file=sys.stderr)
        return 2

    start = time.monotonic()
    tmpdir: tempfile.TemporaryDirectory | None = None
    if tar:
        tmpdir = tempfile.TemporaryDirectory()
        quelle: object = P.fetch_rawdata(P.minio_client(), order_id, Path(tmpdir.name))
        zeilen = P.tool_runs_from_db(order_id)
    else:
        from reporter.facts.golden import results_path, tar_path
        quelle = tar_path(order_id)
        zeilen = results_path(order_id)

    # S6b-2 (offener Punkt nach S6a): im Produktionspfad derselbe Kundenkontext wie im
    # Worker; ohne ihn meldete die Diagnose "auftraggeber_fehlt", obwohl der Bericht
    # den Firmennamen traegt.
    kontext = _kundenkontext(order_id) if tar else None
    facts, output, data = P.report_bundle_from_source(quelle, tool_runs=zeilen,
                                                      customer_context=kontext)
    # Dieselbe Strenge wie der Worker. Ohne das meldet die Diagnose einen
    # fehlenden Auftraggeber als Warnung und "fehler": 0, waehrend derselbe
    # Bericht in der Produktion unter strict auf report_blocked laeuft. Ein
    # gruenes --kennzahlen muss heissen, dass der Bericht durchgeht.
    streng = _engine.validation_level() == "strict"
    defekte = [d for d in v3_checks.run_all(data, facts, output, strict=streng)]
    defekte += list(check_report_data_detailed(data))

    stati: dict[str, int] = {}
    for c in facts.coverage:
        stati[c.status] = stati.get(c.status, 0) + 1
    hosts_ohne = [h.ip for h in data.scope.hosts if not (h.coverage or "").strip()]
    tls_mit = sum(1 for t in facts.tls if t.protocols
                  and any(v is not None for v in t.protocols.values()))

    bericht = {
        "order_id": facts.scan.order_id,
        "paket": facts.scan.package,
        "zeilen": len(zeilen) if isinstance(zeilen, list) else None,
        "coverage": stati,
        "hosts": len(data.scope.hosts),
        "hosts_ohne_abdeckung": hosts_ohne,
        "tls_dienste": len(facts.tls),
        "tls_mit_protokollen": tls_mit,
        "threats": len(facts.threats),
        "cve_refs": len(data.appendix.cve_refs),
        "befunde": len(data.findings),
        "positive": len(data.positives),
        "werkzeuge_im_anhang": len(data.appendix.tools),
        "defekte": [{"pruefung": d.check, "stufe": d.severity, "meldung": d.message}
                    for d in defekte],
        "fehler": sum(1 for d in defekte if d.severity == "error"),
        "laufzeit_s": round(time.monotonic() - start, 1),
        "speicher_mib": (round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
                         if resource is not None else None),
    }
    print(json.dumps(bericht, ensure_ascii=False, indent=1, sort_keys=True))
    if tmpdir is not None:
        tmpdir.cleanup()
    return 1 if bericht["fehler"] else 0


def _selftest() -> int:
    from reporter.pdf.v3 import render_report_v3

    erwartet = erwartungen()
    fehler: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        for order_id in SELFTEST_ORDERS:
            result = render_report_v3(_golden_data(order_id), Path(tmp) / f"{order_id}.pdf")
            soll = erwartet.get(order_id)
            print(f"{order_id[:8]} Seiten={result.pages} soll={soll} "
                  f"sparse={list(result.sparse_pages)} defekte={len(result.defects)}")
            fehler += pruefe(order_id, result, soll)
    for zeile in fehler:
        print(f"FEHLER {zeile}", file=sys.stderr)
    print(f"selftest: {len(fehler)} Fehler", file=sys.stderr)
    return 1 if fehler else 0


def _update_pages() -> int:
    """Seitenzahlen und bekannte halbleere Seiten festschreiben.

    Laeuft ueber alle Golden-Auftraege, nicht nur die drei des Selbsttests: die Datei
    ist der Erwartungswert fuer tests/pdf_v3/test_pdf.py.
    """
    from reporter.pdf.v3 import render_report_v3
    from reporter.v3.golden import order_ids

    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    werte: dict[str, dict] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for order_id in order_ids():
            result = render_report_v3(_golden_data(order_id), Path(tmp) / "x.pdf")
            werte[order_id] = {"pages": result.pages,
                               "sparse": list(result.sparse_pages)}
            print(f"{order_id[:8]} -> {result.pages} Seiten, "
                  f"halbleer {list(result.sparse_pages)}")
            for cause in result.sparse_causes:
                print(f"{order_id[:8]}    {cause}")
    PAGES_FILE.write_text(json.dumps(werte, indent=1, sort_keys=True) + "\n",
                          encoding="utf-8")
    print(f"geschrieben {PAGES_FILE}", file=sys.stderr)
    return 0


def _prosa(data, customer_context: dict | None, order_id: str | None) -> int:
    """Prosa-KI auf fertige Reportdaten anwenden und berichten.

    Fuer die Abnahme: welche der vier Felder das Gate genommen hat, welche es mit
    welcher Begruendung abgelehnt hat, und was der Aufruf gekostet hat.
    """
    from reporter.v3 import prose

    if not prose.available():
        print("Prosa-KI uebersprungen: kein ANTHROPIC_API_KEY", file=sys.stderr)
        return 0

    payload = prose.build_payload(data, customer_context)
    vorher = (data.glance.overall_text, data.business.implication,
              [o.meaning for o in data.business.observed],
              [f.impact for f in data.findings])
    fields, cost = prose.generate(payload, order_id=order_id)
    rejected = prose.apply_prose(data, fields, payload)

    angenommen = []
    if data.glance.overall_text != vorher[0]:
        angenommen.append("overall_text")
    if data.business.implication != vorher[1]:
        angenommen.append("implication")
    geaendert = sum(1 for alt, o in zip(vorher[2], data.business.observed)
                    if alt != o.meaning)
    if geaendert:
        angenommen.append(f"observed ({geaendert} von {len(vorher[2])})")
    geaendert = sum(1 for alt, f in zip(vorher[3], data.findings) if alt != f.impact)
    if geaendert:
        angenommen.append(f"impact ({geaendert} von {len(vorher[3])})")

    print(f"Prosa angenommen: {', '.join(angenommen) or 'nichts'}")
    print(f"Prosa abgelehnt: {len(rejected)}")
    for grund in rejected:
        print(f"  abgelehnt: {grund}", file=sys.stderr)
    if cost:
        print(f"Prosa Kosten: {json.dumps(cost, ensure_ascii=False, sort_keys=True)}")
    return len(rejected)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m reporter.pdf.v3", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--golden", metavar="ORDER_ID", help="Reportdaten aus den Golden-Fakten")
    ap.add_argument("--source", help="Roh-Tar oder entpacktes Scan-Verzeichnis")
    ap.add_argument("--order", metavar="ORDER_ID", help="Roh-Tar aus MinIO holen")
    ap.add_argument("--upload", action="store_true",
                    help="mit --order: PDF nach scan-debug/v3/ legen")
    ap.add_argument("--package", help="Paketvariante uebersteuern (webcheck, perimeter, ...)")
    ap.add_argument("-o", "--out", help="Ziel-PDF")
    ap.add_argument("--html", help="zusaetzlich das HTML schreiben")
    ap.add_argument("--html-only", action="store_true", help="kein PDF, nur HTML (ohne WeasyPrint)")
    ap.add_argument("--strict", action="store_true", help="Defekte als Fehler behandeln")
    ap.add_argument("--context", action="store_true",
                    help="mit --order: Kundenkontext aus der Datenbank laden (S5)")
    ap.add_argument("--prose", action="store_true",
                    help="Prosa-KI laufen lassen und das Ergebnis berichten (S5)")
    ap.add_argument("--selftest", action="store_true", help="Golden-Auftraege rendern und pruefen")
    ap.add_argument("--write-snapshot", action="store_true", help="Regressionsdatei neu schreiben")
    ap.add_argument("--update-pages", action="store_true", help="Seitenzahlen neu festschreiben")
    ap.add_argument("--kennzahlen", action="store_true",
                    help="nur nachsehen: Abdeckung, TLS, Anhang A.3, Defekte als JSON")
    args = ap.parse_args(argv)

    if args.write_snapshot:
        print(f"geschrieben {_write_snapshot(SNAPSHOT_ORDER)}", file=sys.stderr)
        return 0
    if args.update_pages:
        return _update_pages()
    if args.selftest:
        return _selftest()
    if args.kennzahlen:
        return _kennzahlen(args.order or args.golden, tar=not args.golden)

    from reporter.pdf.v3 import render_html, render_report_v3
    from reporter.pdf.v3 import pipeline as P
    from reporter.pdf.v3.screenshots import MinioScreenshots

    resolver = None
    tmpdir: tempfile.TemporaryDirectory | None = None
    client = None
    customer_context: dict | None = None
    order_id = args.order or args.golden or "bericht"

    if args.golden:
        data = _golden_data(args.golden)
    elif args.source:
        data = P.report_data_from_source(args.source, report_date=REPORT_DATE)
    elif args.order:
        client = P.minio_client()
        tmpdir = tempfile.TemporaryDirectory()
        tar = P.fetch_rawdata(client, args.order, Path(tmpdir.name))
        if args.context:
            customer_context = _kundenkontext(args.order)
            print(f"Kundenkontext: {json.dumps(customer_context, ensure_ascii=False, sort_keys=True)}")
        data = P.report_data_from_source(tar, tool_runs=P.tool_runs_from_db(args.order),
                                         customer_context=customer_context)
        resolver = MinioScreenshots(client)
    else:
        ap.error("eine Quelle angeben: --golden, --source oder --order")
        return 2

    if args.prose:
        _prosa(data, customer_context, args.order)

    if args.html_only:
        html = render_html(data, resolver=resolver, package=args.package)[0]
        target = Path(args.html or args.out or f"{order_id}.html")
        target.write_text(html, encoding="utf-8")
        print(f"geschrieben {target}", file=sys.stderr)
        return 0

    out = Path(args.out) if args.out else Path(f"{order_id}.pdf")
    result = render_report_v3(data, out, resolver=resolver, package=args.package,
                              html_out=args.html, strict=args.strict)
    print(f"{out} · {result.pages} Seiten · {len(result.defects)} Defekte · "
          f"{len(result.warnings)} Warnungen")
    for defekt in result.defects:
        print(f"  Defekt: {defekt}", file=sys.stderr)
    for warnung in result.warnings:
        print(f"  Warnung: {warnung}", file=sys.stderr)

    if args.upload:
        if client is None:
            client = P.minio_client()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        print(f"MinIO: {P.upload_debug_pdf(client, order_id, out, stamp)}")

    if tmpdir is not None:
        tmpdir.cleanup()
    return 1 if result.defects else 0


if __name__ == "__main__":
    sys.exit(main())

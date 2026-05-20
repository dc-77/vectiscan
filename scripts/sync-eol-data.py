#!/usr/bin/env python3
"""Sync EOL-Daten von endoflife.date in `reporter/eol_data_generated.py`.

Aufruf:
    python scripts/sync-eol-data.py [--dry-run]

Quelle: https://endoflife.date/api/<product>.json (CC-BY-4.0)

Wir holen die ~25 fuer Pentest-Reports relevanten Produkte (Webserver,
Datenbanken, Crypto-Libs, OS, Frameworks) und schreiben das Ergebnis in
`report-worker/reporter/eol_data_generated.py`. Manuelle Overrides
in `eol_detector.EOL_DATA` haben weiterhin Vorrang (Loader-Logik).

Lizenz: Daten von endoflife.date — CC-BY-4.0 — Attribution im Report-Footer.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path

# Lokaler Import — `_sync_lib` liegt im selben Ordner.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _sync_lib import (  # noqa: E402
    SyncValidationError,
    atomic_write_python_module,
    fetch_with_retry,
    validate_min_entries,
)

# ────────────────────────────────────────────────────────────────────
# Mapping endoflife.date-Produkt -> (vendor, product, label) fuer
# unsere EOL_DATA-Schluessel. label kann pro Cycle ueberschrieben werden
# (z.B. Exchange "15.1" -> label "Exchange Server 2016").
# ────────────────────────────────────────────────────────────────────
PRODUCTS: dict[str, dict] = {
    # endoflife.date-product -> unser Mapping
    "exchange-server":      {"vendor": "microsoft", "product": "exchange",
                              "label_template": "Exchange Server {cycle}"},
    "windows-server":       {"vendor": "microsoft", "product": "windows-server",
                              "label_template": "Windows Server {cycle}"},
    "nginx":                {"vendor": "nginx", "product": ""},
    "apache":               {"vendor": "apache", "product": "httpd"},
    "iis":                  {"vendor": "microsoft", "product": "iis"},
    "openssl":              {"vendor": "openssl", "product": ""},
    "openssh":              {"vendor": "openssh", "product": ""},
    "php":                  {"vendor": "php", "product": ""},
    "python":               {"vendor": "python", "product": ""},
    "nodejs":               {"vendor": "node", "product": ""},
    "mysql":                {"vendor": "mysql", "product": ""},
    "mariadb":              {"vendor": "mariadb", "product": ""},
    "postgresql":           {"vendor": "postgresql", "product": ""},
    "redis":                {"vendor": "redis", "product": ""},
    "mongodb":              {"vendor": "mongodb", "product": ""},
    "ubuntu":               {"vendor": "ubuntu", "product": ""},
    "debian":               {"vendor": "debian", "product": ""},
    "centos":               {"vendor": "centos", "product": ""},
    "rhel":                 {"vendor": "rhel", "product": ""},
    "windows":              {"vendor": "microsoft", "product": "windows"},
    "java-oracle":          {"vendor": "oracle", "product": "java"},
    "wordpress":            {"vendor": "wordpress", "product": ""},
    "drupal":               {"vendor": "drupal", "product": ""},
    "django":               {"vendor": "django", "product": ""},
    "laravel":              {"vendor": "laravel", "product": ""},
    "ruby":                 {"vendor": "ruby", "product": ""},
}

# Severity-Heuristik: Crypto/OS-Komponenten kritischer als Frameworks
HIGH_RISK_VENDORS = {"openssl", "openssh", "microsoft", "apache", "nginx", "iis"}
CRITICAL_RISK_PRODUCTS = {"exchange", "iis", "windows-server"}

# Sanity-Schwelle: weniger als so viele Eintraege = vermutlich Quell-Panne
MIN_EXPECTED_ENTRIES = 50


def severity_for(vendor: str, product: str, days_eol: int) -> str:
    """Bestimme Default-Severity wenn endoflife.date keine eigene Kategorie hat."""
    if days_eol > 730:  # > 2 Jahre EOL -> kritisch
        return "CRITICAL"
    if vendor in HIGH_RISK_VENDORS or product in CRITICAL_RISK_PRODUCTS:
        return "HIGH" if days_eol > 0 else "MEDIUM"
    return "MEDIUM" if days_eol > 0 else "LOW"


def fetch_product(slug: str, timeout: int = 30) -> list[dict]:
    """Holt JSON-Liste von Cycles fuer ein Produkt — mit Retry/Backoff."""
    url = f"https://endoflife.date/api/{slug}.json"
    try:
        body = fetch_with_retry(url, retries=3, timeout=timeout)
        return json.loads(body)
    except Exception as e:  # noqa: BLE001 — endoflife-Quelle, generisch loggen
        print(f"  [WARN] {slug}: {e}", file=sys.stderr)
        return []


def build_entries(today: date) -> dict[tuple[str, str, str], dict]:
    """Iteriert PRODUCTS, baut EOL_DATA-aehnliches Dict."""
    out: dict[tuple[str, str, str], dict] = {}
    for slug, mapping in PRODUCTS.items():
        print(f"[INFO] fetching {slug} ...")
        cycles = fetch_product(slug)
        if not cycles:
            continue
        vendor = mapping["vendor"]
        product = mapping["product"]
        label_tpl = mapping.get("label_template")

        for cycle_obj in cycles:
            cycle = str(cycle_obj.get("cycle") or "").strip()
            eol_raw = cycle_obj.get("eol")
            if not cycle or eol_raw in (False, None, True):
                # eol=True/False/None bedeutet "noch supported" oder "unbekannt"
                continue
            try:
                eol_date = datetime.fromisoformat(str(eol_raw)).date()
            except Exception:
                continue
            # Nur aktuell oder bis 60 Tage Future erfassen
            days_eol = (today - eol_date).days
            if days_eol < -60:
                continue

            label = None
            if label_tpl:
                label = label_tpl.format(cycle=cycle)

            entry: dict = {
                "date": eol_date.isoformat(),
                "severity": severity_for(vendor, product, days_eol),
                "_source": "endoflife.date",
            }
            if label:
                entry["label"] = label
            # Latest-Patch-Version als Hint
            if cycle_obj.get("latest"):
                entry["latest_patch"] = str(cycle_obj["latest"])

            out[(vendor, product, cycle)] = entry
    return out


def _build_header(timestamp: str) -> str:
    """Baut den Modul-Docstring — bleibt inhaltlich identisch zur Vor-Refactor-Variante."""
    return (
        '"""GENERIERT — NICHT MANUELL EDITIEREN.\n'
        '\n'
        'Quelle: endoflife.date (CC-BY-4.0)\n'
        'Generator: scripts/sync-eol-data.py\n'
        f'Stand:    {timestamp}\n'
        '\n'
        'Manuelle Overrides + spezifische CVEs gehoeren in\n'
        '`reporter/eol_detector.py:EOL_DATA` — die haben Vorrang vor diesen\n'
        'generierten Eintraegen (Union-Loader in eol_detector).\n'
        '"""\n'
    )


def write_module(entries: dict, dest: Path) -> None:
    header = _build_header(datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    atomic_write_python_module(
        dest,
        header=header,
        data_name="EOL_DATA_GENERATED",
        data_dict=entries,
        dict_type_hint="dict[tuple[str, str, str], dict]",
    )
    print(f"[INFO] wrote {len(entries)} entries -> {dest}")


def validate_existing_entries(today: date) -> int:
    """M2 Track 2c — Validation-Pass ueber EOL_DATA_MANUAL + EOL_DATA_GENERATED.

    Prueft:
    - manual-Eintraege mit last_validated_at > 365 Tage alt → WARNING
    - Eintraege ohne source → WARNING (Schema-Verstoss)

    Liefert Anzahl Warnings (CI: Exit 1 bei > 0).
    """
    warnings = 0
    # Lazy-Import, damit das Script standalone laufen kann (auch ohne
    # vollstaendige PYTHONPATH-Setup).
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root / "report-worker"))
    try:
        from reporter.eol_detector import EOL_DATA_MANUAL  # type: ignore
    except Exception as e:  # noqa: BLE001
        print(f"[ERROR] Konnte EOL_DATA_MANUAL nicht laden: {e}",
              file=sys.stderr)
        return 1

    try:
        from reporter.eol_data_generated import EOL_DATA_GENERATED  # type: ignore
    except Exception:
        EOL_DATA_GENERATED = {}  # noqa: N806 — Fallback wenn Datei fehlt

    # Manual-Eintraege: Stale-Check
    for key, entry in EOL_DATA_MANUAL.items():
        src = entry.get("source")
        last = entry.get("last_validated_at")
        if not src:
            print(f"[WARN] Manual entry ohne source: {key}", file=sys.stderr)
            warnings += 1
            continue
        if src != "manual":
            continue
        if not last:
            print(f"[WARN] Manual entry ohne last_validated_at: {key}",
                  file=sys.stderr)
            warnings += 1
            continue
        try:
            last_dt = datetime.fromisoformat(str(last)).date()
        except Exception:
            print(f"[WARN] Manual entry mit invalid last_validated_at: "
                  f"{key} = {last!r}", file=sys.stderr)
            warnings += 1
            continue
        days = (today - last_dt).days
        if days > 365:
            print(
                f"[WARN] Manual entry stale: {key[0]} {key[2]} — "
                f"last validated {last_dt.isoformat()} ({days}d ago)",
                file=sys.stderr,
            )
            warnings += 1

    # Generated-Eintraege: Schema-Check (sollte _source ODER source haben)
    schema_violations = 0
    for key, entry in EOL_DATA_GENERATED.items():
        if "_source" not in entry and "source" not in entry:
            schema_violations += 1
    if schema_violations:
        print(f"[WARN] {schema_violations} generated entries ohne source-Feld",
              file=sys.stderr)
        warnings += 1

    print(
        f"[INFO] Validation done: {len(EOL_DATA_MANUAL)} manual + "
        f"{len(EOL_DATA_GENERATED)} generated entries, {warnings} warnings",
    )
    return warnings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="Nur fetchen + zusammenfassen, nicht schreiben")
    ap.add_argument("--validate-only", action="store_true",
                    help="Nur Schema/Staleness-Validation von bereits "
                         "vorhandenen Eintraegen (kein Fetch). "
                         "Exit 1 bei >0 Warnings (CI-tauglich).")
    ap.add_argument("--out", default=None,
                    help="Override Output-Pfad (default: report-worker/reporter/eol_data_generated.py)")
    args = ap.parse_args()

    today = date.today()

    # M2 2c — Validation-only-Mode: gegen endoflife.date NICHT fetchen,
    # nur Schema + Staleness der vorhandenen Daten pruefen.
    if args.validate_only:
        warnings = validate_existing_entries(today)
        return 1 if warnings > 0 else 0

    entries = build_entries(today)

    try:
        validate_min_entries(
            entries, min_count=MIN_EXPECTED_ENTRIES,
            source_name="endoflife.date",
        )
    except SyncValidationError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"\n[DRY-RUN] {len(entries)} Eintraege gefetched.")
        for k, v in list(sorted(entries.items()))[:8]:
            print(f"  {k} -> {v}")
        return 0

    repo_root = Path(__file__).resolve().parent.parent
    dest = (Path(args.out) if args.out
            else repo_root / "report-worker" / "reporter"
                            / "eol_data_generated.py")
    write_module(entries, dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())

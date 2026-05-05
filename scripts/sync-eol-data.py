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
import urllib.error
import urllib.request
from datetime import date, datetime
from pathlib import Path

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


def severity_for(vendor: str, product: str, days_eol: int) -> str:
    """Bestimme Default-Severity wenn endoflife.date keine eigene Kategorie hat."""
    if days_eol > 730:  # > 2 Jahre EOL -> kritisch
        return "CRITICAL"
    if vendor in HIGH_RISK_VENDORS or product in CRITICAL_RISK_PRODUCTS:
        return "HIGH" if days_eol > 0 else "MEDIUM"
    return "MEDIUM" if days_eol > 0 else "LOW"


def fetch_product(slug: str, timeout: float = 30.0) -> list[dict]:
    """Holt JSON-Liste von Cycles fuer ein Produkt."""
    url = f"https://endoflife.date/api/{slug}.json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  [WARN] {slug}: HTTP {e.code}", file=sys.stderr)
        return []
    except Exception as e:
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


_HEADER = '''"""GENERIERT — NICHT MANUELL EDITIEREN.

Quelle: endoflife.date (CC-BY-4.0)
Generator: scripts/sync-eol-data.py
Stand:    {ts}

Manuelle Overrides + spezifische CVEs gehoeren in
`reporter/eol_detector.py:EOL_DATA` — die haben Vorrang vor diesen
generierten Eintraegen (Union-Loader in eol_detector).
"""

from __future__ import annotations

# (vendor, product, version_prefix) -> info dict
EOL_DATA_GENERATED: dict[tuple[str, str, str], dict] = {{
'''
_FOOTER = "}\n"


def write_module(entries: dict, dest: Path) -> None:
    lines = [_HEADER.format(ts=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))]
    for (vendor, product, cycle), info in sorted(entries.items()):
        info_repr = ", ".join(
            f'"{k}": {json.dumps(v, ensure_ascii=False)}'
            for k, v in sorted(info.items())
        )
        lines.append(
            f'    ("{vendor}", "{product}", "{cycle}"): {{{info_repr}}},\n'
        )
    lines.append(_FOOTER)
    dest.write_text("".join(lines), encoding="utf-8")
    print(f"[INFO] wrote {len(entries)} entries -> {dest}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="Nur fetchen + zusammenfassen, nicht schreiben")
    ap.add_argument("--out", default=None,
                    help="Override Output-Pfad (default: report-worker/reporter/eol_data_generated.py)")
    args = ap.parse_args()

    today = date.today()
    entries = build_entries(today)
    if not entries:
        print("[ERROR] keine Eintraege gefetched — Abbruch.", file=sys.stderr)
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

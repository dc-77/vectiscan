#!/usr/bin/env python3
"""S0c Schritt 2: Soll-Listen des Junkerwerk-Prototyps als Golden-Fixture.

Quelle ist report-prototype/build/report_data.py, die kuratierte Datenbasis des
Prototyps (Stand 17.09.2026). Alternativ nimmt --source den JSON-Dump
report-prototype/out/report-data.json, der aber gitignored ist. Ergebnis ist
report-worker/tests/golden/expected/junkerwerk.json mit den 15 Befunden und
8 Positivbefunden, je mit id, family, scale, level, affected.

Zwei Felder gibt es in der Quelle nicht und werden hier vergeben:

1. `family`. report_data.py kennt nur die Report-Kategorie `cat` (A bis E). Die
   Sachverhaltsfamilien stammen aus dem Vokabular von
   report-prototype/build/catalog_sim.py (apply_rules). Mehrere Prototyp-Befunde
   buendeln bewusst mehrere Sachverhalte, deshalb traegt jeder Eintrag `family`
   (primaer, bestimmt die Zuordnung in S2) und `families` (vollstaendig).
   Namen, die catalog_sim.py noch nicht kennt, sind unten mit NEU markiert.

2. IDs fuer Positivbefunde. Die Quelle fuehrt sie ohne ID. Vergabe VS-2026-P01
   bis P08 in Quellreihenfolge. `scale` und `level` bleiben null, weil eine
   bestandene Pruefung keine Einstufung traegt.

Aufruf:
    python3 scripts/golden/build-expected-junkerwerk.py
"""

from __future__ import annotations

import argparse
import json
import runpy
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = REPO_ROOT / "report-prototype" / "build" / "report_data.py"
DEFAULT_DEST = REPO_ROOT / "report-worker" / "tests" / "golden" / "expected" / "junkerwerk.json"

# Befund-ID -> Familien. Erster Eintrag ist die primaere Familie.
# NEU = Name existiert in catalog_sim.py noch nicht und kommt in S2 dazu.
FINDING_FAMILIES: dict[str, list[str]] = {
    "VS-2026-001": ["db_exposed"],
    "VS-2026-002": ["admin_service_exposed"],
    "VS-2026-003": ["default_page_exposed"],
    "VS-2026-004": ["software_eol"],
    "VS-2026-005": ["legacy_protocols_present"],            # NEU (TLS-Zwang, kein Klartext)
    "VS-2026-006": ["software_lifecycle_review"],           # NEU (Lifecycle, kein EOL-Beleg)
    "VS-2026-007": ["dmarc_missing", "spf_softfail"],
    "VS-2026-008": ["mta_sts_missing", "tls_rpt_missing", "dane_missing"],  # NEU: tls_rpt, dane
    "VS-2026-009": ["tls_weak_ciphers", "tls_no_13", "hsts_short", "http_compression"],  # NEU: tls_no_13, http_compression
    "VS-2026-010": ["cert_hostname_mismatch"],
    "VS-2026-011": ["csp_weak", "header_duplicate", "csrf_token_missing"],
    "VS-2026-012": ["tls_legacy_protocols", "tls_no_fallback_protection"],  # NEU: fallback
    "VS-2026-013": ["security_headers_incomplete"],
    "VS-2026-014": ["banner_version_disclosure", "http_trace_enabled"],     # NEU: http_trace
    "VS-2026-015": ["dnssec_missing", "caa_missing"],
}

# Positivbefund (Reihenfolge in report_data.py) -> Familien.
POSITIVE_FAMILIES: list[list[str]] = [
    ["rdp_not_exposed", "smb_not_exposed"],   # NEU, Gegenstueck zu rdp_exposed/smb_exposed
    ["mail_tls_enforced"],                    # NEU, Gegenstueck zu mail_plaintext/ftp_exposed
    ["software_supported"],                   # NEU, Gegenstueck zu software_eol
    ["spf_present", "dkim_present"],          # NEU, Gegenstueck zu spf_missing/dkim_missing
    ["dns_no_zone_transfer", "dns_no_dangling"],  # NEU, Gegenstueck zu dns_axfr/dns_dangling
    ["cert_valid_chain"],                     # NEU, Gegenstueck zu cert_chain_incomplete
    ["tls_modern"],                           # NEU, Gegenstueck zu tls_legacy_protocols
    ["reputation_clean"],                     # NEU, Gegenstueck zu urlhaus_compromise
]

SCALES = {"exposure", "hygiene"}
LEVELS = {"kritisch", "hoch", "mittel", "niedrig"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    ap.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    args = ap.parse_args()

    source: Path = args.source.resolve()
    if not source.is_file():
        print(f"Quelle fehlt: {source}", file=sys.stderr)
        return 2

    if source.suffix == ".py":
        # report_data.py ist reine Daten: ein Modul mit der Konstante DATA.
        data = runpy.run_path(str(source))["DATA"]
    else:
        data = json.loads(source.read_text(encoding="utf-8"))
    src_findings = data["findings"]
    src_positives = data["positives"]

    if len(src_findings) != 15 or len(src_positives) != 8:
        print(
            f"Unerwartete Mengen: {len(src_findings)} Befunde, {len(src_positives)} Positivbefunde "
            "(erwartet 15 und 8)",
            file=sys.stderr,
        )
        return 1

    findings = []
    for entry in src_findings:
        fid = entry["id"]
        families = FINDING_FAMILIES.get(fid)
        if not families:
            print(f"Keine Familienzuordnung fuer {fid}", file=sys.stderr)
            return 1
        if entry["scale"] not in SCALES or entry["level"] not in LEVELS:
            print(f"Ungueltige Einstufung bei {fid}", file=sys.stderr)
            return 1
        findings.append(
            {
                "id": fid,
                "family": families[0],
                "families": families,
                "cat": entry["cat"],
                "scale": entry["scale"],
                "level": entry["level"],
                "affected": entry["affected"],
                "status": entry["status"],
                "urgency": entry["urgency"],
                "title": entry["title"],
                "source": entry["source"],
                "policy": entry["policy"],
            }
        )

    positives = []
    for index, entry in enumerate(src_positives):
        families = POSITIVE_FAMILIES[index]
        positives.append(
            {
                "id": f"VS-2026-P{index + 1:02d}",
                "family": families[0],
                "families": families,
                "cat": entry["cat"],
                "scale": None,
                "level": None,
                "affected": None,
                "title": entry["title"],
                "evidence": entry["text"],
            }
        )

    out = {
        "source": "report-prototype/build/report_data.py (Stand 17.09.2026)",
        "report_id": data["meta"]["report_id"],
        "customer": data["meta"]["customer"],
        "domains": data["meta"]["domains"],
        "package": data["meta"]["package"].lower(),
        "order_ids": [order["id"] for order in data["meta"]["orders"]],
        "hinweis_family": (
            "family und families stammen aus dem Vokabular von "
            "report-prototype/build/catalog_sim.py apply_rules; Namen ohne Vorbild dort "
            "sind im Generator markiert. affected der Positivbefunde ist null, weil die "
            "Quelle keines fuehrt."
        ),
        "hinweis_positive_ids": (
            "Positivbefunde tragen in report_data.py keine ID. VS-2026-P01 bis P08 in "
            "Quellreihenfolge vergeben."
        ),
        "findings": findings,
        "positives": positives,
    }

    args.dest.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(out, ensure_ascii=False, indent=1) + "\n"
    args.dest.write_text(text, encoding="utf-8", newline="\n")
    print(f"{len(findings)} Befunde, {len(positives)} Positivbefunde -> {args.dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

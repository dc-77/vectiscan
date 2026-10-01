#!/usr/bin/env python3
"""S7a: Befundzahlen und Einstufungen aller Golden-Auftraege festschreiben.

Die Session S7a aendert die Darstellung, nicht die Befunde (spec/prompts/S7a.md).
Der Drift-Test der Reportdaten schuetzt das nicht: er wird fuer jede
Darstellungsaenderung neu geschrieben und haelt danach jede Zahl fest, die gerade
herauskommt. Diese Datei haelt nur, was gleich bleiben muss: je Befund ID,
Pruefungen, Ampel, Dringlichkeit, Skala und Einstufung, dazu die Positivbefunde
(Kategorie und Pruefungen), die Kategorieampeln und die Gesamtbewertung.

tests/v3/test_befundzahlen_s7a.py vergleicht die gebauten Reportdaten damit.

Aufruf (liest die eingecheckten report-data/*.json):
    python3 scripts/golden/build-befundzahlen.py
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN = REPO_ROOT / "report-worker" / "tests" / "golden"
REPORT_DATA = GOLDEN / "report-data"
OUT = GOLDEN / "befundzahlen.json"


def summary(data: dict) -> dict:
    """Was S7a nicht aendern darf, aus einem Reportdatenmodell (dict)."""
    glance = data.get("glance") or {}
    return {
        "overall": glance.get("overall"),
        "categories": {c["key"]: c["status"] for c in glance.get("categories") or []},
        "findings": [
            [f["id"], "+".join(f.get("checks") or []), f["status"], f["urgency"], f["scale"], f["level"]]
            for f in data.get("findings") or []
        ],
        "positives": sorted(
            [p["cat"], "+".join(p.get("checks") or [])] for p in data.get("positives") or []
        ),
    }


def main() -> None:
    out = {}
    for path in sorted(REPORT_DATA.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        out[path.stem] = summary(data)
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8", newline="\n")
    print(f"{OUT.relative_to(REPO_ROOT)}: {len(out)} Auftraege")


if __name__ == "__main__":
    main()

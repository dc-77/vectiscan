"""S0a: Zusagen, die der Scanner nicht einloest, duerfen nicht zurueckkehren.

Hintergrund: report-prototype/spec/05 B7. Ein automatisierter Aussenscan deckt
drei von sieben PTES-Phasen ab, und die Severity-Vergabe ist seit der
Determinismus-Pipeline regelbasiert (severity_policy ueberschreibt ~95 %).
"PTES-konform" und "KI-gestuetzt" sind damit Falschzusagen im Kundentext.

Der Test scannt die Quelldateien als Text, braucht also keinen Import und
laeuft auch dann, wenn ein Modul optionale Abhaengigkeiten hat.
"""

from __future__ import annotations

from pathlib import Path

REPORTER_DIR = Path(__file__).resolve().parent.parent / "reporter"

# Begriff -> Begruendung, die im Fehlerfall ausgegeben wird.
FORBIDDEN: dict[str, str] = {
    "PTES": "spec/05 B7 - nur 3 von 7 PTES-Phasen werden abgedeckt",
    "KI-gestützt": "Einstufung ist regelbasiert (severity_policy), nicht KI-gestuetzt",
    "KI-gestuetzt": "Einstufung ist regelbasiert (severity_policy), nicht KI-gestuetzt",
}


def _python_sources() -> list[Path]:
    return [p for p in REPORTER_DIR.rglob("*.py") if "__pycache__" not in p.parts]


def test_reporter_sources_have_no_legacy_claims() -> None:
    assert _python_sources(), f"Keine Quelldateien unter {REPORTER_DIR} gefunden"

    hits: list[str] = []
    for path in _python_sources():
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            for term, reason in FORBIDDEN.items():
                if term in line:
                    rel = path.relative_to(REPORTER_DIR.parent)
                    hits.append(f"{rel}:{line_no}: '{term}' ({reason})")

    assert not hits, "Verbotene Zusage im Reporter-Code:\n" + "\n".join(hits)

# -*- coding: utf-8 -*-
"""Ein Defekt, egal aus welchem Gate.

Der v2-Strang liefert ``ValidationIssue``-Objekte mit genau diesen Feldern, der
v3-Strang liefert Saetze. Die Adapter hier machen aus beidem dieselbe Form; der
Worker schreibt sie nach ``orders.report_defects``, die API reicht sie an das
Admin-Review durch.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional, Sequence

ENGINE_V2 = "v2"
ENGINE_V3 = "v3"

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"

# Eine Befund-ID steckt bei v3 nur im Satz ("... bei VS-JW-2026-003"), weil die
# Pruefungen aus dem Prototyp-Skript stammen. Das Muster deckt beide ID-Formen ab
# (mit und ohne Kundenkuerzel) und auch die Positiv-IDs.
FINDING_ID = re.compile(r"\bVS-(?:[A-Z0-9]{2,8}-)?\d{4}-P?\d{2,3}\b")

# Render-Warnungen, die einen Bericht blockieren sollen. Halbleere Seiten stehen
# bewusst nicht dabei: sie sind in tests/golden/render/expected-pages.json je
# Auftrag bekannt und haengen an der Datenmenge, nicht an einem Fehler (S4).
_RENDER_ERROR_MARKERS = ("Schrift nicht eingebettet", "Gedankenstrich")


@dataclass
class Defect:
    """Ein Defekt mit Herkunft."""

    engine: str
    check: str
    severity: str
    message: str
    finding_id: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        return self.severity == SEVERITY_ERROR

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def _finding_id_from(text: str) -> Optional[str]:
    match = FINDING_ID.search(text or "")
    return match.group(0) if match else None


# ---------------------------------------------------------------- v2

def from_validation_result(result: Any) -> list[Defect]:
    """``ValidationResult`` des alten Gates -> Defekte.

    ``ValidationIssue`` traegt check, severity, finding_id, message und detail
    bereits in der Zielform; hier kommt nur die Engine dazu.
    """
    defects: list[Defect] = []
    for issue in list(getattr(result, "errors", []) or []) + list(getattr(result, "warnings", []) or []):
        defects.append(Defect(
            engine=ENGINE_V2,
            check=str(getattr(issue, "check", "") or "unbekannt"),
            severity=str(getattr(issue, "severity", SEVERITY_ERROR) or SEVERITY_ERROR),
            message=str(getattr(issue, "message", "") or ""),
            finding_id=getattr(issue, "finding_id", None),
            detail=dict(getattr(issue, "detail", {}) or {}),
        ))
    return defects


# ---------------------------------------------------------------- v3

def from_selfcheck(entries: Iterable[Any]) -> list[Defect]:
    """Ergebnis von ``reporter.v3.selfcheck`` -> Defekte.

    Nimmt sowohl die strukturierte Form ``(check, message, finding_id)`` als auch
    die alte Satzliste; aus einem Satz wird die Befund-ID dann herausgelesen.
    """
    defects: list[Defect] = []
    for entry in entries or []:
        if isinstance(entry, str):
            check, message, finding_id = "selfcheck", entry, _finding_id_from(entry)
        else:
            check, message, finding_id = entry
        defects.append(Defect(
            engine=ENGINE_V3,
            check=str(check),
            severity=SEVERITY_ERROR,
            message=str(message),
            finding_id=finding_id,
        ))
    return defects


def from_render_result(result: Any) -> list[Defect]:
    """Render-Pruefungen aus ``reporter/pdf/v3`` -> Defekte.

    ``result.defects`` wird hier bewusst nicht gelesen: das ist dieselbe
    Selbstcheck-Liste, die der Worker schon strukturiert erhebt. Uebrig bleiben
    die Beobachtungen am fertigen Dokument (Schriften, Gedankenstriche, halbleere
    Seiten).
    """
    defects: list[Defect] = []
    for warning in list(getattr(result, "warnings", []) or []):
        text = str(warning)
        blocking = any(marker in text for marker in _RENDER_ERROR_MARKERS)
        defects.append(Defect(
            engine=ENGINE_V3,
            check="render",
            severity=SEVERITY_ERROR if blocking else SEVERITY_WARNING,
            message=text,
        ))
    return defects


# ---------------------------------------------------------------- Ablage

def _unprocessed_entries(facts: Any, output: Any) -> list[dict[str, Any]]:
    """Beobachtungen ohne Regel aus beiden Quellen, mit Herkunft.

    ``facts.unprocessed`` sind Beobachtungen, die der Faktenbauer nicht lesen
    konnte (S1); ``output.unprocessed`` sind Fakten, die keine Pruefung des
    Katalogs beansprucht hat (S2-Auffangregeln).
    """
    entries: list[dict[str, Any]] = []
    for item in list(getattr(facts, "unprocessed", []) or []):
        data = item.model_dump(mode="json") if hasattr(item, "model_dump") else dict(item)
        entries.append({"quelle": "fakten", **data})
    for item in list(getattr(output, "unprocessed", []) or []):
        data = item.model_dump(mode="json") if hasattr(item, "model_dump") else dict(item)
        entries.append({"quelle": "katalog", **data})
    return entries


def payload(defects: Sequence[Defect], *, engine: str, level: str,
            facts: Any = None, output: Any = None,
            blocked: bool = False) -> dict[str, Any]:
    """Inhalt von ``orders.report_defects``."""
    unprocessed = _unprocessed_entries(facts, output)
    errors = [d for d in defects if d.is_error]
    warnings = [d for d in defects if not d.is_error]
    return {
        "engine": engine,
        "level": level,
        "blocked_at": datetime.now(timezone.utc).isoformat(timespec="seconds") if blocked else None,
        "defects": [d.to_json() for d in defects],
        "unprocessed": unprocessed,
        "counts": {
            "errors": len(errors),
            "warnings": len(warnings),
            "unprocessed": sum(int(u.get("count", 1) or 1) for u in unprocessed),
        },
        # S7a Punkt 8 (E27): Fristen nahe einer Schwelle, damit die API sie fuer den Freigabetag
        # nachrechnen kann (``api/src/lib/fristen.ts``).
        **_fristen(facts),
    }


def _fristen(facts: Any) -> dict[str, Any]:
    # Nur mit einem Faktenmodell; Tests und Altpfade reichen teils nur die Beobachtungen durch.
    if facts is None or not all(hasattr(facts, a) for a in ("scan", "tls", "services", "hosts", "targets")):
        return {}
    from reporter.gate import fristen as FR

    return FR.nutzlast(facts)

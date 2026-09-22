# -*- coding: utf-8 -*-
"""Die drei Schalter des Report-Workers an einer Stelle.

Seit S6 ist der Katalogweg der Regelfall: Fakten, Pruefkatalog, Reportdaten v3,
Renderer v3, Gate strict. Der alte Weg (KI#5 mit Reparaturkette, Severity-Policy,
ReportLab) bleibt eine Release lang ueber ``VECTISCAN_REPORT_ENGINE=legacy``
erreichbar und wird danach entfernt.

    VECTISCAN_REPORT_ENGINE     catalog (Vorgabe) | legacy
    VECTISCAN_REPORT_LAYOUT     v3 (Vorgabe) | v2 | v1
    VECTISCAN_VALIDATION_LEVEL  strict (Vorgabe) | warn | off

Die Engine entscheidet, woher die Befunde kommen, das Layout, welcher Renderer
sie setzt. Beides gehoert zusammen: der v2- und der v1-Renderer lesen das
Datenmodell der alten Kette, das es unter ``catalog`` nicht gibt. Die Kombination
``catalog`` mit ``v2`` oder ``v1`` ist deshalb ein Fehler und keine stille
Notloesung. Umgekehrt ist ``legacy`` mit ``v3`` erlaubt: so lief die Produktion
zwischen S4 und S6, und ein Vergleichslauf braucht den Weg noch.

Ein unbekannter Wert ist ebenfalls ein Fehler. Ein Tippfehler in der
Deploy-Konfiguration darf nicht dazu fuehren, dass stillschweigend der alte Weg
laeuft; das faellt sonst erst am ausgelieferten Bericht auf.
"""
from __future__ import annotations

import os

ENGINE_CATALOG = "catalog"
ENGINE_LEGACY = "legacy"
ENGINES = (ENGINE_CATALOG, ENGINE_LEGACY)

LAYOUTS = ("v3", "v2", "v1")
LEGACY_LAYOUTS = ("v2", "v1")

VALIDATION_LEVELS = ("strict", "warn", "off")

DEFAULT_ENGINE = ENGINE_CATALOG
DEFAULT_LAYOUT = "v3"
DEFAULT_VALIDATION_LEVEL = "strict"


class EngineConfigError(RuntimeError):
    """Unbrauchbare Kombination oder unbekannter Wert in der Konfiguration."""


def _read(name: str, default: str, allowed: tuple[str, ...]) -> str:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    if raw not in allowed:
        raise EngineConfigError(
            f"{name}={raw!r} ist unbekannt; erlaubt sind {', '.join(allowed)}")
    return raw


def engine() -> str:
    return _read("VECTISCAN_REPORT_ENGINE", DEFAULT_ENGINE, ENGINES)


def layout() -> str:
    return _read("VECTISCAN_REPORT_LAYOUT", DEFAULT_LAYOUT, LAYOUTS)


def validation_level() -> str:
    return _read("VECTISCAN_VALIDATION_LEVEL", DEFAULT_VALIDATION_LEVEL,
                 VALIDATION_LEVELS)


def resolve() -> tuple[str, str]:
    """(Engine, Layout) mit Pruefung der Kombination."""
    eng = engine()
    lay = layout()
    if eng == ENGINE_CATALOG and lay in LEGACY_LAYOUTS:
        raise EngineConfigError(
            f"VECTISCAN_REPORT_ENGINE={eng} liefert keine Daten fuer den "
            f"Renderer {lay}; entweder VECTISCAN_REPORT_LAYOUT=v3 oder "
            f"VECTISCAN_REPORT_ENGINE=legacy setzen")
    return eng, lay


def uses_catalog() -> bool:
    return resolve()[0] == ENGINE_CATALOG


__all__ = [
    "ENGINE_CATALOG", "ENGINE_LEGACY", "ENGINES", "LAYOUTS", "LEGACY_LAYOUTS",
    "VALIDATION_LEVELS", "DEFAULT_ENGINE", "DEFAULT_LAYOUT",
    "DEFAULT_VALIDATION_LEVEL", "EngineConfigError", "engine", "layout",
    "validation_level", "resolve", "uses_catalog",
]

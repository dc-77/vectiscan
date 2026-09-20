# -*- coding: utf-8 -*-
"""Paketvarianten des Berichts.

Der Prototyp war ein Perimeter-Bericht und traegt das Wort an sechs Stellen fest im
Markup. Hier steht, was je Paket daraus wird und welche Kapitel ueberhaupt erscheinen.

Die Zuordnung Anzeigename -> Paketschluessel wird aus ``reporter.v3.tables.PACKAGE_LABELS``
erzeugt, damit es keine zweite Wahrheit ueber Paketnamen gibt. ``meta.package`` traegt
bereits den Anzeigenamen ("Perimeter", "WebCheck"), nicht den Schluessel.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from reporter.v3.tables import PACKAGE_LABELS


@dataclass(frozen=True)
class Variant:
    """Was das Paket am Bericht aendert."""

    key: str
    report_title: str       # Ueberschrift auf dem Deckblatt und im Dokumenttitel
    assessment: str         # laufender Kopf und Fusszeile
    eyebrow: str            # Zeile ueber der Deckblatt-Ueberschrift
    screens: bool           # Kapitel 3.4 Gesichtete Web-Oberflaechen
    inventory: bool         # Anhang Service-Inventar


_EYEBROW_EXTERN = "Sicherheitsbewertung der externen Angriffsfläche"
_EYEBROW_WEB = "Sicherheitsbewertung der öffentlichen Webpräsenz"


def _variant(key: str, name: str, *, eyebrow: str = _EYEBROW_EXTERN,
             screens: bool = True, inventory: bool = True) -> Variant:
    return Variant(
        key=key,
        report_title=f"{name}-Bericht",
        assessment=f"{name}-Sicherheitsbewertung",
        eyebrow=eyebrow,
        screens=screens,
        inventory=inventory,
    )


# WebCheck prueft Website und Mailsicherheit auf hoechstens drei Hosts. Das
# Bildschirmraster und das Service-Inventar entfallen (Entscheidung DC, S4).
VARIANTS: dict[str, Variant] = {
    "webcheck": _variant("webcheck", "WebCheck", eyebrow=_EYEBROW_WEB,
                         screens=False, inventory=False),
    "perimeter": _variant("perimeter", "Perimeter"),
    "compliance": _variant("compliance", "Compliance"),
    "supplychain": _variant("supplychain", "SupplyChain"),
    "insurance": _variant("insurance", "Insurance"),
    "tlscompliance": _variant("tlscompliance", "TLS-Compliance"),
}

DEFAULT_KEY = "perimeter"

# Anzeigename (klein) -> Paketschluessel. Kanonische Schluessel zuerst, damit die
# Legacy-Aliase (basic, professional, nis2) den Eintrag nicht ueberschreiben.
_BY_NAME: dict[str, str] = {}
for _key in VARIANTS:
    _name, _ = PACKAGE_LABELS.get(_key, (_key, ""))
    _BY_NAME.setdefault(_name.lower(), _key)
for _alias, (_name, _) in PACKAGE_LABELS.items():
    _BY_NAME.setdefault(_name.lower(), _alias)


def key_for(meta: Any, override: str | None = None) -> tuple[str, str | None]:
    """Paketschluessel bestimmen.

    Ein ausdruecklich uebergebener Schluessel gewinnt; sonst wird der Anzeigename aus
    ``meta.package`` zurueckuebersetzt. Rueckgabe ist (Schluessel, Warnung oder None).
    """
    if override:
        low = override.strip().lower()
        if low in VARIANTS:
            return low, None
        # Alias, der auf ein bekanntes Paket zeigt (basic -> webcheck).
        name, _ = PACKAGE_LABELS.get(low, ("", ""))
        if name and name.lower() in _BY_NAME:
            return _BY_NAME[name.lower()], None
        return DEFAULT_KEY, f"unbekanntes Paket {override!r}, Bericht als {DEFAULT_KEY}"

    package = getattr(meta, "package", None)
    if package is None and isinstance(meta, dict):
        package = meta.get("package")
    low = (package or "").strip().lower()
    if low in _BY_NAME:
        return _BY_NAME[low], None
    if low in VARIANTS:
        return low, None
    return DEFAULT_KEY, f"unbekanntes Paket {package!r}, Bericht als {DEFAULT_KEY}"


def variant_for(meta: Any, override: str | None = None) -> tuple[Variant, str | None]:
    key, warning = key_for(meta, override)
    return VARIANTS[key], warning

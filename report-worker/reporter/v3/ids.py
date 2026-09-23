# -*- coding: utf-8 -*-
"""Befund-IDs.

Mit Kundenkuerzel ``VS-<Kuerzel>-<Jahr>-<lfd>``, ohne Kuerzel ``VS-<Jahr>-<lfd>`` wie
bisher (Entscheidung DC, spec/07 Abschnitt 1). Das Kuerzel ist optional und kommt aus
dem Bestellprozess oder dem Admin-Review (S5). IDs werden erst nach der Konsolidierung
vergeben und sind lueckenlos (spec/03 Regel 1).
"""
from __future__ import annotations

import re

KUERZEL_RE = re.compile(r"^[A-Za-z0-9]{2,8}$")


def normalize_kuerzel(value: str | None) -> str:
    """Leeres oder unbrauchbares Kuerzel ergibt IDs ohne Kuerzel."""
    if not value:
        return ""
    value = str(value).strip().upper()
    return value if KUERZEL_RE.match(value) else ""


def prefix(kuerzel: str | None, year: int) -> str:
    kz = normalize_kuerzel(kuerzel)
    return f"VS-{kz}-{year}" if kz else f"VS-{year}"


def finding_id(kuerzel: str | None, year: int, index: int) -> str:
    """``index`` ist eins-basiert."""
    return f"{prefix(kuerzel, year)}-{index:03d}"


def positive_id(kuerzel: str | None, year: int, index: int) -> str:
    return f"{prefix(kuerzel, year)}-P{index:02d}"


def report_id(order_id: str | None, year: int, month_day: str) -> str:
    """Berichtsnummer ``VS-<Jahr>-<MMTT>-<Order>``, z. B. ``VS-2026-0831-0bf1``.

    S6a: bis dahin nur Kuerzel, Jahr und Scantag; ohne Kuerzel trugen zwei Kunden
    mit demselben Scantag dieselbe Nummer (Huendgen und castenow, VS-2026-0917).
    Die ersten vier Zeichen der Order-ID machen sie eindeutig. Das Kuerzel steht
    bewusst nicht darin: es kann im Admin-Review nachgetragen werden, und die
    Nummer muss ueber alle Versionen desselben Auftrags gleich bleiben. Scantag
    und Order-ID kommen aus den Fakten, nicht aus dem Erstellungsdatum.
    """
    order_part = re.sub(r"[^0-9a-f]", "", str(order_id or "").lower())[:4]
    base = f"VS-{year}-{month_day}"
    return f"{base}-{order_part}" if order_part else base

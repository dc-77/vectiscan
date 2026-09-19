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


def report_id(kuerzel: str | None, year: int, month_day: str) -> str:
    """Berichtsnummer auf dem Deckblatt, z. B. ``VS-JW-2026-0831``."""
    return f"{prefix(kuerzel, year)}-{month_day}"

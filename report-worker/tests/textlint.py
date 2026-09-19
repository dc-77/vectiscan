# -*- coding: utf-8 -*-
"""Gemeinsame Textpruefungen fuer Kundentexte.

Die Wortliste liegt im Produktionscode (``reporter/v3/orthography.py``), weil das Gate
der Prosa-KI dieselbe Pruefung zur Laufzeit braucht. Hier stehen nur die Re-Exporte und
die Muster, die ausschliesslich Tests benutzen.
"""
from __future__ import annotations

import re

from reporter.v3.orthography import (ASCII_UMLAUTS, DASHES, DU_FORM, FORBIDDEN_CLAIMS,
                                     find_ascii_umlauts, fix_ascii_umlauts)

__all__ = ["ASCII_UMLAUTS", "DASHES", "DU_FORM", "FORBIDDEN_CLAIMS", "find_ascii_umlauts",
           "fix_ascii_umlauts", "CUSTOMER_NAMES"]

CUSTOMER_NAMES = re.compile(
    r"junkerwerk|hetzner|hornetsecurity|united-domains|securess|castenow|heuel|trunk|"
    r"krause|telekom|sonicwall|rcdevs|webadm|openotp|konsoleh", re.I)

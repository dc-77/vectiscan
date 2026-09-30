# -*- coding: utf-8 -*-
"""Fehler- und Hinweistexte eines Werkzeugs sind keine Beobachtung (S7a Punkt 0).

castenow cd28d260, 92.205.163.53:8000: nmap meldet fuer ``http-server-header``,
``fingerprint-strings`` und ``https-redirect`` jeweils "ERROR: Script execution
failed (use -d to debug)". Der Parser las die erste Zeile von ``http-server-header``
als Server-Kennung, der Bericht zeigte den Text in Kapitel 2 und in einer
Betroffen-Zeile. Eine Skriptausgabe, die nur sagt, dass das Werkzeug gescheitert ist,
wird deshalb verworfen; danach gilt der normale Regelweg (Entscheidung DC 30.09.:
naechste Quelle, sonst "nicht identifiziert").

Die Muster sind eng gefasst, weil Server echte Fehlerseiten liefern, die eine
Kennung tragen: CloudFront antwortet mit dem Titel "ERROR: The request could not be
satisfied", Azure mit "Microsoft Azure Web App - Error 404". Beides ist ein Fakt ueber
den Dienst und bleibt stehen (Gegenprobe in tests/test_tool_errors_s7a.py).

Dieselbe Liste nutzt die Gate-Regel ``werkzeugfehler_im_kundentext``.
"""
from __future__ import annotations

import re
from typing import Optional

TOOL_ERROR_PATTERNS: tuple[re.Pattern[str], ...] = (
    # nmap NSE: "ERROR: Script execution failed (use -d to debug)"
    re.compile(r"Script execution failed", re.I),
    re.compile(r"\(use -d to debug\)", re.I),
    # nmap NSE mit eigener Fehlerursache ("ERROR: Failed to connect", "ERROR: Timeout");
    # nicht "ERROR: The request could not be satisfied" (Seitentitel von CloudFront).
    re.compile(r"^\s*ERROR:\s*(?:Script\b|Failed\b|Timeout\b|Timed out\b|Couldn't\b|Could not\b|"
               r"Unable to\b|Connection (?:refused|reset|timed out)\b)", re.I),
    re.compile(r"^\s*NSE:\s", re.I),
    # Python-Ausnahmen aus einem Werkzeuglauf.
    re.compile(r"Traceback \(most recent call last\)"),
    # Zeitlimit oder Abbruch als ganze Ausgabe.
    re.compile(r"^\s*(?:TIMEOUT|Timeout|timed out|Timed out)\b"),
    re.compile(r"^\s*Failed to\b"),
)


def is_tool_error(text: Optional[str]) -> bool:
    """True, wenn der Text eine Fehler- oder Hinweismeldung des Werkzeugs ist."""
    if not text:
        return False
    return any(p.search(text) for p in TOOL_ERROR_PATTERNS)


def tool_error_in(text: Optional[str]) -> Optional[str]:
    """Der erste Treffer im Text (fuer die Gate-Meldung), sonst None."""
    if not text:
        return None
    for p in TOOL_ERROR_PATTERNS:
        m = p.search(text)
        if m:
            return m.group(0).strip()
    return None


def clean(text: Optional[str]) -> Optional[str]:
    """Der Text, oder None, wenn er eine Werkzeugmeldung ist."""
    return None if is_tool_error(text) else text

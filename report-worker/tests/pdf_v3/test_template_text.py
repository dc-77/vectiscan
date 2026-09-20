# -*- coding: utf-8 -*-
"""Textlint ueber die Vorlage selbst.

``tests/v3/test_textqualitaet.py`` prueft die Reportdaten. Die Vorlage traegt aber
eigenen Kundentext (Kapitelvorspaenne, Tabellenkoepfe, Zeitstufen), und der ist bisher
von keiner Pruefung erfasst. Genau dort stand im Prototyp der Kundenname eines
Auftraggebers.
"""
from __future__ import annotations

import re

import pytest

from reporter.pdf.v3 import text as T
from reporter.pdf.v3 import variants as V
from reporter.pdf.v3.render import TEMPLATE, env
from tests.textlint import (CUSTOMER_NAMES, DASHES, DU_FORM, FORBIDDEN_CLAIMS,
                            find_ascii_umlauts)

JINJA = re.compile(r"\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}", re.S)
STYLE = re.compile(r"<style>.*?</style>", re.S)
COMMENT = re.compile(r"<!--.*?-->", re.S)
TAG = re.compile(r"<[^>]+>", re.S)

# Der Bericht sagt an drei Stellen ausdruecklich, dass er keine eigenen Fremdscores
# vergibt. Dafuer muss er den Begriff nennen duerfen. Wortlaut aus dem abgenommenen
# Entwurf (spec/03); aendert er sich, faellt dieser Test und jemand schaut hin.
CLAIM_AUSNAHMEN: tuple[str, ...] = (
    "Diese Seite nennt bewusst keine CVSS-Werte",
    "CVSS-Werte erscheinen nur als Fremdreferenz bei zitierten CVEs",
    "Der Bericht vergibt keine eigenen CVSS-Werte",
    "CVSS-Basiswerte erscheinen ausschließlich als Fremdreferenz zu zitierten CVEs",
)


def vorlagentext() -> str:
    quelle = env().loader.get_source(env(), TEMPLATE)[0]
    ohne_code = TAG.sub(" ", COMMENT.sub(" ", STYLE.sub(" ", JINJA.sub(" ", quelle))))
    import html as _html
    return _html.unescape(ohne_code)


def modultexte() -> list[str]:
    zahlen = [("Unverzüglich", 3), ("In Kürze", 2)]
    aus_text = [
        T.runs_line(2, 3, 1), T.runs_line(2, 3, 3),
        T.period_note("01.01.2026, 10:00 bis 11:00 Uhr (CET)", 1),
        T.period_note("01.01.2026, 10:00 bis 11:00 Uhr (CET)", 3),
        T.distribution_line(0, []), T.distribution_line(5, zahlen),
        T.split_note(15, 14, 29),
        T.MORE_TITLE, T.MORE_KICKER, T.MORE_LEAD,
        T.TOOL_FINDINGS_TITLE, T.TOOL_FINDINGS_LEAD, T.SCREENSHOT_MISSING,
    ]
    aus_text += list(T._ZAHLWORT.values())
    for variant in V.VARIANTS.values():
        aus_text += [variant.report_title, variant.assessment, variant.eyebrow]
    return aus_text


def _ohne_ausnahmen(text: str) -> str:
    for satz in CLAIM_AUSNAHMEN:
        text = text.replace(satz, " ")
    return text


def test_vorlage_hat_echte_umlaute():
    treffer = sorted(set(find_ascii_umlauts(vorlagentext())))
    assert not treffer, treffer


def test_vorlage_ohne_gedankenstriche():
    text = vorlagentext()
    for strich in DASHES:
        assert strich not in text, f"Gedankenstrich {strich!r} in der Vorlage"


def test_vorlage_ohne_zusagen():
    rest = _ohne_ausnahmen(vorlagentext())
    treffer = FORBIDDEN_CLAIMS.findall(rest)
    assert not treffer, treffer


def test_vorlage_in_sie_form():
    assert not DU_FORM.findall(vorlagentext())


def test_vorlage_ohne_kundennamen():
    """Der Prototyp trug 'junkerwerk.de' fest im Prueflaufhinweis."""
    treffer = sorted(set(CUSTOMER_NAMES.findall(vorlagentext())))
    assert not treffer, treffer


@pytest.mark.parametrize("text", modultexte())
def test_rendererstexte_sind_sauber(text):
    assert text.strip()
    assert not find_ascii_umlauts(text), find_ascii_umlauts(text)
    assert not any(d in text for d in DASHES), text
    assert not FORBIDDEN_CLAIMS.search(text), text
    assert not DU_FORM.search(text), text
    assert not CUSTOMER_NAMES.search(text), text
    assert not re.search(r"\{[a-z_]+\}|\[Hinweis|TODO", text), text

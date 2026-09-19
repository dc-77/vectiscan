"""Textlint fuer die Katalogtexte: keine Gedankenstriche, keine Platzhalterreste, keine Zusagen,
keine Kunden- oder Herstellernamen, Zahlen nur aus der Whitelist, Sie-Form."""
from __future__ import annotations

import re

import pytest

from reporter.catalog import tables as T
from tests.catalog.conftest import get_catalog

DASHES = ("–", "—")
FORBIDDEN_CLAIMS = re.compile(r"PTES|KI-gest|vollst[aä]ndig gepr[uü]ft|l[uü]ckenlos|garantiert|CVSS", re.I)
CUSTOMER_NAMES = re.compile(r"junkerwerk|hetzner|hornetsecurity|united-domains|securess|castenow|heuel|trunk|krause|"
                            r"telekom|sonicwall|rcdevs|webadm|openotp|konsoleh", re.I)
DU_FORM = re.compile(r"\b(du|dein|deine|deinem|deinen|dich|dir)\b", re.I)
NUMBER = re.compile(r"\d+(?:[.,]\d+)*")
ALLOWED_NUMBERS = {"1.2", "1.3", "1.0", "1.1", "2", "3", "8996", "7489", "8461", "8460", "8659", "0", "30", "24", "1", "6", "12",
                   "403", "405", "501", "200", "3389", "445", "139", "21", "22", "25", "80", "110", "143", "443", "465", "587",
                   "993", "995", "3306", "5432", "1433", "27017", "6379", "9200", "10000", "8443", "8080", "4433", "3116", "4"}
ALLOWED_NUMBERS |= {str(p) for p in T.DB_PORTS} | {str(p) for p in T.ADMIN_PORTS} | {str(p) for p in T.MAIL_PORTS}


def _texts(spec):
    t = spec.texts
    yield "title", spec.title
    yield "observation", t.observation
    yield "meaning", t.meaning
    yield "verify", t.verify
    for i, r in enumerate(t.recommendation):
        yield f"recommendation[{i}]", r.text
    if t.positive:
        yield "positive.title", t.positive.title
        yield "positive.text", t.positive.text


def _params():
    return [pytest.param(cc.spec, id=cc.spec.id) for cc in get_catalog().checks]


@pytest.mark.parametrize("spec", _params())
def test_keine_gedankenstriche(spec):
    for name, text in _texts(spec):
        assert not any(d in text for d in DASHES), f"{spec.id}.{name}: Gedankenstrich"


@pytest.mark.parametrize("spec", _params())
def test_keine_platzhalter_oder_fragezeichen(spec):
    for name, text in _texts(spec):
        stripped = re.sub(r"\{(affected|count|group|fqdn_names|domain|host_ip|notes)\}", "", text)
        assert "{" not in stripped and "}" not in stripped, f"{spec.id}.{name}: unbekannter Platzhalter"
        assert "?" not in text, f"{spec.id}.{name}: Fragezeichen"
        assert "[Hinweis" not in text and "TODO" not in text, f"{spec.id}.{name}: interner Hinweis"


@pytest.mark.parametrize("spec", _params())
def test_keine_zusagen_und_namen(spec):
    for name, text in _texts(spec):
        assert not FORBIDDEN_CLAIMS.search(text), f"{spec.id}.{name}: verbotene Zusage oder CVSS"
        assert not CUSTOMER_NAMES.search(text), f"{spec.id}.{name}: Kunden- oder Herstellername"
        assert not DU_FORM.search(text), f"{spec.id}.{name}: keine Sie-Form"


@pytest.mark.parametrize("spec", _params())
def test_zahlen_nur_aus_whitelist(spec):
    for name, text in _texts(spec):
        for num in NUMBER.findall(text):
            assert num in ALLOWED_NUMBERS, f"{spec.id}.{name}: Zahl {num} nicht in der Whitelist"


@pytest.mark.parametrize("spec", _params())
def test_texte_nicht_leer_und_empfehlung_mit_stufe(spec):
    for name, text in _texts(spec):
        assert text.strip(), f"{spec.id}.{name} leer"
    assert spec.texts.recommendation
    assert spec.policy.source.strip()

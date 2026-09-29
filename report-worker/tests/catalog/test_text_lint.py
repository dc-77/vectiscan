"""Textlint fuer die Katalogtexte: keine Gedankenstriche, keine Platzhalterreste, keine Zusagen,
keine Kunden- oder Herstellernamen, Zahlen nur aus der Whitelist, Sie-Form."""
from __future__ import annotations

import re

import pytest

from reporter.catalog import tables as T
from tests.catalog.conftest import get_catalog
from tests.textlint import find_ascii_umlauts

DASHES = ("–", "—")
FORBIDDEN_CLAIMS = re.compile(r"PTES|KI-gest|vollst[aä]ndig gepr[uü]ft|l[uü]ckenlos|garantiert|CVSS", re.I)
CUSTOMER_NAMES = re.compile(r"junkerwerk|hetzner|hornetsecurity|united-domains|securess|castenow|heuel|trunk|krause|"
                            r"telekom|sonicwall|rcdevs|webadm|openotp|konsoleh", re.I)
DU_FORM = re.compile(r"\b(du|dein|deine|deinem|deinen|dich|dir)\b", re.I)
NUMBER = re.compile(r"\d+(?:[.,]\d+)*")
ALLOWED_NUMBERS = {"1.2", "1.3", "1.0", "1.1", "2", "3", "8996", "7489", "8461", "8460", "8659", "0", "30", "24", "1", "6", "12",
                   "403", "405", "501", "200", "3389", "445", "139", "21", "22", "25", "80", "110", "143", "443", "465", "587",
                   "993", "995", "3306", "5432", "1433", "27017", "6379", "9200", "10000", "8443", "8080", "4433", "3116", "4",
                   # S6b-4 (spec/11 T4): ein Jahr in Sekunden als empfohlenes HSTS-max-age.
                   "31536000"}
ALLOWED_NUMBERS |= {str(p) for p in T.DB_PORTS} | {str(p) for p in T.ADMIN_PORTS} | {str(p) for p in T.MAIL_PORTS}


def _texts(spec):
    # S6b-2: jede Aussage einzeln (observation[0], recommendation[1] ...), dazu die Kurzform
    # fuer den Sammeltitel und die Plantexte; alles steht im Kundenreport.
    t = spec.texts
    yield "title", spec.title
    for sid, text, _cond, _quantor in t.all_statements():
        yield sid, text
    if t.short is not None:
        yield "short", t.short
    if t.plan is not None:
        yield "plan.lever", t.plan.lever
        yield "plan.effect", t.plan.effect
        if t.plan.per_rule_action:
            yield "plan.per_rule_action", t.plan.per_rule_action
    if t.positive:
        yield "positive.title", t.positive.title
        yield "positive.text", t.positive.text


def _params():
    return [pytest.param(cc.spec, id=cc.spec.id) for cc in get_catalog().checks]


@pytest.mark.parametrize("spec", _params())
def test_keine_gedankenstriche(spec):
    for name, text in _texts(spec):
        assert not any(d in text for d in DASHES), f"{spec.id}.{name}: Gedankenstrich"


# S6b-1 (spec/09 Teil 3): Einzahl und Mehrzahl nach der Zahl der Hosts, {n:Einzahl|Mehrzahl};
# S6b-4 (spec/11 T12): {m:Einzahl|Mehrzahl} nach der Zahl der Betroffenen.
NUMERUS = re.compile(r"\{[nm]:([^{}|]+)\|([^{}|]+)\}")


@pytest.mark.parametrize("spec", _params())
def test_numerus_formen_vollstaendig(spec):
    for name, text in _texts(spec):
        for one, many in NUMERUS.findall(text):
            assert one.strip() and many.strip() and one != many, f"{spec.id}.{name}: Numerus {one!r}|{many!r}"


FESTER_NUMERUS = re.compile(r"\b(Der|Die|Den|Dem) Hosts? \{(group|affected)\}")


@pytest.mark.parametrize("spec", _params())
def test_host_satz_mit_numerus(spec):
    # "Der Host {group}" stand auch vor drei Hosts (spec/09 Teil 3).
    for name, text in _texts(spec):
        assert not FESTER_NUMERUS.search(text), f"{spec.id}.{name}: Numerus fest, {{n:...|...}} verwenden"


@pytest.mark.parametrize("spec", _params())
def test_keine_platzhalter_oder_fragezeichen(spec):
    for name, text in _texts(spec):
        stripped = NUMERUS.sub("", text)
        # S6b-3: missing_header_names (spec/10 R2) und passed (R6) sind Gruppenvariablen;
        # S6b-4: valid_elsewhere (T14) und target_versions (T12) gesammelt ueber die Mitglieder.
        # S6d (A10): reputation_window (Abfragefenster der Reputation aus dem Rohdatum).
        stripped = re.sub(r"\{(affected|count|group|fqdn_names|domain|host_ip|notes|missing_header_names|passed|"
                          r"valid_elsewhere|target_versions|dmarc_rua|mx|dmarc_rua_own|dmarc_rua_foreign|dmarc_delegated_to|"
                          r"version_headers|feserver_names|cert_summary|shared_domains|reputation_window)\}",
                          "", stripped)
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


@pytest.mark.parametrize("spec", _params())
def test_echte_umlaute_statt_umschrift(spec):
    """S3: Kundentexte tragen echte Umlaute, keine ae/oe/ue/ss-Umschrift.

    Bezeichner bleiben ASCII; geprueft wird nur, was im Report steht (Titel, Texte,
    affected_template). Die Wortliste steht in tests/textlint.py.
    """
    for name, text in _texts(spec):
        hits = find_ascii_umlauts(text)
        assert not hits, f"{spec.id}.{name}: Umschrift statt Umlaut {sorted(set(hits))}"
    hits = find_ascii_umlauts(spec.affected_template)
    assert not hits, f"{spec.id}.affected_template: Umschrift statt Umlaut {sorted(set(hits))}"


def _bundle_texts(bundle):
    # S6b-2: ein Buendel traegt nur noch den Sammeltitel und den Positivtitel.
    yield "title", bundle.title
    if bundle.positive_title:
        yield "positive_title", bundle.positive_title


def _bundle_params():
    return [pytest.param(b, id=b.id) for b in get_catalog().bundles]


@pytest.mark.parametrize("bundle", _bundle_params())
def test_buendeltexte_sauber(bundle):
    """Buendeltexte stehen im Kundenreport und folgen denselben Regeln wie Pruefungstexte."""
    for name, text in _bundle_texts(bundle):
        where = f"{bundle.id}.{name}"
        assert text.strip(), f"{where} leer"
        assert not any(d in text for d in DASHES), f"{where}: Gedankenstrich"
        assert not FORBIDDEN_CLAIMS.search(text), f"{where}: verbotene Zusage oder CVSS"
        assert not CUSTOMER_NAMES.search(text), f"{where}: Kunden- oder Herstellername"
        assert not DU_FORM.search(text), f"{where}: keine Sie-Form"
        assert "?" not in text, f"{where}: Fragezeichen"
        stripped = re.sub(r"\{(affected|count|group|fqdn_names|domain|host_ip|notes|rules)\}", "", NUMERUS.sub("", text))
        assert "{" not in stripped and "}" not in stripped, f"{where}: unbekannter Platzhalter"
        for num in NUMBER.findall(text):
            assert num in ALLOWED_NUMBERS, f"{where}: Zahl {num} nicht in der Whitelist"
        hits = find_ascii_umlauts(text)
        assert not hits, f"{where}: Umschrift statt Umlaut {sorted(set(hits))}"


def test_coverage_gruende_mit_echten_umlauten():
    """Die not_testable-Gruende stehen in Kapitel 2 des Kundenreports."""
    bad: list[str] = []
    for code, (_status, text) in T.COVERAGE_REASONS.items():
        hits = find_ascii_umlauts(text)
        if hits:
            bad.append(f"{code}: {sorted(set(hits))}")
    assert not find_ascii_umlauts(T.GENERIC_NOT_TESTABLE), T.GENERIC_NOT_TESTABLE
    assert not bad, bad


@pytest.mark.parametrize("spec", _params())
def test_plan_hebel_ohne_platzhalter(spec):
    """Ein Hebel adressiert alle Befunde seiner Zeile und nennt keinen Host (Q6)."""
    if spec.texts.plan is None:
        return
    texts = [("plan.lever", spec.texts.plan.lever), ("plan.effect", spec.texts.plan.effect)]
    # S6b-4 (spec/11 T12, T14): Varianten und Einzelmassnahme je Regel stehen ebenfalls im Plan.
    texts += [(sid, text) for sid, text, _c, _q in spec.texts.all_statements() if sid.startswith("plan.")]
    if spec.texts.plan.per_rule_action:
        texts.append(("plan.per_rule_action", spec.texts.plan.per_rule_action))
    for name, text in texts:
        assert "{" not in text and "}" not in text, f"{spec.id}.{name}: Platzhalter"
        assert text.strip(), f"{spec.id}.{name} leer"

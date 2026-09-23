"""Pruefung dkim_missing: ein Test je Fixture (pass, nt), dazu die Faelle aus S6a.

#15 Teil 2 (S6a): Ohne Selektor aus einer echten E-Mail ist DKIM nicht pruefbar, nie
"fehlt". Deshalb gibt es kein ``_fail``-Fixture mehr; das ``_nt``-Fixture ist der Fall
"kein Schluessel unter den abgefragten Selektoren".
"""
import pytest

from tests.catalog.conftest import fixture_kinds, make_facts, run_check, run_fixture

CHECK_ID = "dkim_missing"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_dkim_missing(kind):
    run_fixture(CHECK_ID, kind)


def _ergebnis(dkim):
    dns = {"domain": "example.test", "mx": ["mx1.example.test"],
           "spf": {"raw": "v=spf1 mx -all", "all_qualifier": "-all"}}
    if dkim is not None:
        dns["dkim"] = dkim
    (result,) = run_check(CHECK_ID, make_facts({"dns": [dns]}, coverage_default="ok"))
    return result


@pytest.mark.parametrize("dkim", [
    {"present": False, "selectors": []},
    {"present": False, "selectors": [], "probed": ["default"], "probed_basis": "scan"},
    {"present": False, "selectors": [], "probed": ["default"], "probed_basis": "scanner_stand"},
])
def test_ohne_gefundenen_selektor_nie_fehlschlag(dkim):
    result = _ergebnis(dkim)
    assert result.status == "not_testable"
    assert result.reason_code == "dkim_selector_unknown"
    assert not result.positive


def test_ohne_dkim_fakt_bleibt_es_bei_zu_wenig_fakten():
    result = _ergebnis(None)
    assert (result.status, result.reason_code) == ("not_testable", "insufficient_facts")


def test_gefundener_selektor_besteht():
    result = _ergebnis({"present": True, "selectors": ["hse1", "hse2"]})
    assert result.status == "pass" and result.positive


def test_katalog_kennt_keinen_fehlschlag_mehr():
    from tests.catalog.conftest import get_catalog
    spec = get_catalog().by_id[CHECK_ID].spec
    assert spec.when is None


# Regressionssperre an echten Berichten: diese Auftraege trugen "DKIM fehlt", obwohl der
# Scanner nur keinen der gaengigen Selektoren gefunden hatte. Die ersten vier haben
# Golden-Fakten aus dem Tar, die letzten drei nur den API-Snapshot (ausgelieferte
# Berichte mit "DKIM-Record fehlt fuer ...").
DKIM_OHNE_SELEKTOR = {
    "14272c00-1145-4675-9b4c-19ce2ead403b": "dortmund-beach.com",   # v3, spec/08 Punkt 6
    "45bb234c-d556-4a80-9c78-3ce221ea28a6": "trunk-immobilien.de",
    "75338c97-6707-4d11-92bf-bb3cd2e02cde": "vectiscan.de",         # v3, WebCheck
    "fb13a98f-22c6-4d17-875c-eeeb14643beb": "krause-computer.de",   # VS-2026-007, ausgeliefert
    "47bd73df-bac7-4a45-a52b-e6e1eee62ef7": "dortmund-beach.com",   # VS-2026-010, ausgeliefert
    "5491c054-f288-42b8-90e6-4a88a07b717e": "dortmund-beach.com",   # VS-2026-006, ausgeliefert
    "0fc35ae8-6133-4487-99e5-0200e1300c06": "cyber-fuchs.de",       # VS-2026-006, ausgeliefert
}


@pytest.mark.parametrize("order_id", sorted(DKIM_OHNE_SELEKTOR), ids=lambda o: o[:8])
def test_echte_berichte_melden_nie_dkim_fehlt(order_id):
    from tests.catalog.test_snapshot_orders import facts_for
    domain = DKIM_OHNE_SELEKTOR[order_id]
    results = [r for r in run_check(CHECK_ID, facts_for(order_id)) if r.group_key == domain]
    assert results, f"{order_id[:8]}: kein Ergebnis fuer {domain}"
    for r in results:
        assert r.status != "fail", (order_id[:8], domain)
        if r.status == "not_testable":
            assert r.reason_code in ("dkim_selector_unknown", "insufficient_facts")

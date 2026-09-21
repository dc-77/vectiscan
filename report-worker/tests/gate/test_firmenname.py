# -*- coding: utf-8 -*-
"""Der Firmenname aus dem Kundenkontext steht im Bericht (S5).

Der Startprompt S5 sagt es ausdruecklich: ohne Firmenname bleibt "Auftraggeber"
stehen und das Gate meldet es als Warnung. Mit Firmenname muss beides
verschwinden. Die Verdrahtung hat bei der Abnahme gefehlt, deshalb dieser Test.
"""
from __future__ import annotations

from reporter.gate import v3_checks as VC
from reporter.v3.report_data import build_report_data
from tests.v3.conftest import JUNKERWERK, facts_for, output_for

ORDER = JUNKERWERK["multi"]


def _data(**kwargs):
    return build_report_data(facts_for(ORDER), output_for(ORDER),
                             report_date="19.09.2026", **kwargs)


def test_ohne_kontext_bleibt_auftraggeber() -> None:
    data = _data()

    assert data.meta.customer == "Auftraggeber"
    assert [d.check for d in VC.auftraggeber_fehlt(data)] == ["auftraggeber_fehlt"]


def test_firmenname_aus_dem_kundenkontext() -> None:
    data = _data(customer_context={"firmenname": "Beispiel Maschinenbau GmbH"})

    assert data.meta.customer == "Beispiel Maschinenbau GmbH"
    assert data.meta.customer_short == "Beispiel"
    assert VC.auftraggeber_fehlt(data) == []


def test_kuerzel_gewinnt_beim_kurznamen() -> None:
    """Das Kuerzel steht in der Fusszeile und in den Befund-Nummern."""
    data = _data(customer_context={"firmenname": "Beispiel Maschinenbau GmbH",
                                   "kuerzel": "BSP"})

    assert data.meta.customer_short == "BSP"
    assert data.findings[0].id.startswith("VS-BSP-")


def test_auftraggeber_aus_der_order_gewinnt() -> None:
    """Die Golden-Testdaten geben den Auftraggeber ueber die Order mit."""
    data = _data(order={"customer": "Aus der Order GmbH"},
                 customer_context={"firmenname": "Aus dem Kontext GmbH"})

    assert data.meta.customer == "Aus der Order GmbH"

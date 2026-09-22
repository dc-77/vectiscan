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
    # S6 (spec/08 Punkt 8): der Kurzname ist der Firmenname ohne Rechtsform,
    # nie das erste Wort. "Dortmund Beach Design" wurde sonst zu "Dortmund".
    assert data.meta.customer_short == "Beispiel Maschinenbau"
    assert VC.auftraggeber_fehlt(data) == []


def test_kurzname_ist_ein_eigenes_feld() -> None:
    """Steht ein Kurzname im Kundenkontext, gewinnt er."""
    data = _data(customer_context={"firmenname": "Beispiel Maschinenbau GmbH",
                                   "kurzname": "Beispiel Maschinenbau"})

    assert data.meta.customer_short == "Beispiel Maschinenbau"


def test_kuerzel_nummeriert_die_befunde_und_ist_kein_kurzname() -> None:
    """Das Kuerzel steht in den Befund-Nummern, nicht in der Fusszeile.

    Bis S6 war es auch der Kurzname; "BSP" in der Fusszeile sagt dem Leser
    weniger als der Firmenname ohne Rechtsform (Entscheidung DC).
    """
    data = _data(customer_context={"firmenname": "Beispiel Maschinenbau GmbH",
                                   "kuerzel": "BSP"})

    assert data.meta.customer_short == "Beispiel Maschinenbau"
    assert data.findings[0].id.startswith("VS-BSP-")


def test_personenzusatz_kommt_nicht_in_den_bericht() -> None:
    """spec/08 Punkt 8: dortmund-beach trug "Inhaber Christian Tacke" im Titel."""
    from reporter.v3.research import firmenname_ohne_person, kurzname_aus

    roh = "Dortmund Beach Design, Inhaber Christian Tacke"
    assert firmenname_ohne_person(roh) == "Dortmund Beach Design"
    assert kurzname_aus(roh) == "Dortmund Beach Design"


def test_auftraggeber_aus_der_order_gewinnt() -> None:
    """Die Golden-Testdaten geben den Auftraggeber ueber die Order mit."""
    data = _data(order={"customer": "Aus der Order GmbH"},
                 customer_context={"firmenname": "Aus dem Kontext GmbH"})

    assert data.meta.customer == "Aus der Order GmbH"

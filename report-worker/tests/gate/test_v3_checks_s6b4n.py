# -*- coding: utf-8 -*-
"""Gate-Regeln aus S6b-4n (spec/11 Teil 6): je Regel ein Nachweis, dass sie anschlaegt, und die
Gegenprobe an allen Golden-Auftraegen.

Die Fehlerbilder stammen aus den Berichten vom 27.09.2026 (spec/11 Teil 6). Sie werden an einer
Kopie der Reportdaten oder Fakten nachgestellt, weil die Reportdaten aus S6b-4n sie nicht mehr
enthalten.
"""
from __future__ import annotations

import pytest

from reporter.gate import v3_checks as VC
from tests.v3.conftest import data_for, facts_for, order_ids, output_for

LW = "c3d5724c-bdbf-4da8-982f-4f1a52210e28"
JW = "31d67a02-b485-4d05-b228-dbdde092cc68"
HE = "3cf01f8d-4d21-4e6d-bac2-7342f1a4d6c7"
BS = "68d59573-7a93-4efa-89cc-e7b10cc4d140"
CA = "1f8bc977-39a7-47c7-b4ad-7b05dbac2d52"
HL = "2e56abe1-c1a6-442e-b36a-dc9f83c81da8"

NEUE_REGELN = ("positiv_ohne_rohfakt", "anmeldename_im_kundentext")


def _kopie(order_id: str):
    return data_for(order_id).model_copy(deep=True)


def _http(order_id: str, fqdn: str):
    return next(h for h in facts_for(order_id).http if h.fqdn == fqdn)


@pytest.mark.parametrize("order_id", order_ids())
def test_golden_ohne_fehler_aus_den_regeln_von_s6b4n(order_id: str) -> None:
    defekte = VC.run_all(data_for(order_id), facts_for(order_id), output_for(order_id))
    fehler = [d for d in defekte if (d.check in NEUE_REGELN or d.check == "nachweis_ohne_regelfakt") and d.is_error]
    assert not fehler, [d.message for d in fehler]


def test_run_all_enthaelt_die_neuen_regeln() -> None:
    import inspect

    quelle = inspect.getsource(VC.run_all)
    for regel in NEUE_REGELN:
        assert f"{regel}(" in quelle, regel


# ---------------------------------------------------------------- N3 Endseite

def test_endseite_ohne_endantwort_greift() -> None:
    """heuel ose VS-002: "bewertet an der Endseite …/login.seam" mit den Headern der ersten Antwort."""
    data = _kopie(HL)
    url = _http(HL, "ose.heuel.com").header_eval.evaluated.url
    f = next(f for f in data.findings if "security_headers_incomplete" in f.checks and "ose.heuel.com" in f.affected)
    assert VC.nachweis_ohne_regelfakt(data, facts_for(HL)) == []
    f.evidence = f"Weiterleitungsprüfung · bewertet an der Endseite: {url} · Antwort: 200\n" + f.evidence
    defekte = VC.nachweis_ohne_regelfakt(data, facts_for(HL))
    assert [d.detail.get("grund") for d in defekte] == ["endseite_ohne_endantwort"]
    assert defekte[0].finding_id == f.id and defekte[0].is_error


def test_endseite_mit_endantwort_bleibt() -> None:
    """Gegenprobe junkerwerk outlook: logon.aspx nach HTTP-Weiterleitung, Header der Endantwort."""
    data = _kopie(JW)
    url = _http(JW, "outlook.junkerwerk.de").header_eval.evaluated.url
    f = next(f for f in data.findings if "outlook.junkerwerk.de" in f.affected)
    f.evidence = f"Weiterleitungsprüfung · bewertet an der Endseite: {url} · Antwort: 200\n" + f.evidence
    assert not [d for d in VC.nachweis_ohne_regelfakt(data, facts_for(JW))
                if d.detail.get("grund") == "endseite_ohne_endantwort"]


# ---------------------------------------------------------------- N6 Positiv gegen Rohfakt

def test_positiv_ohne_rohfakt_greift_ohne_eigenen_axfr_lauf() -> None:
    """junkerwerk P06 (27.09.): .hu im Positivbefund, der Rohbeleg fehlte. Nachgestellt, indem der
    AXFR-Nachweis von .hu aus einer Kopie der Fakten entfernt wird."""
    facts = facts_for(JW).model_copy(deep=True)
    hu = next(d for d in facts.dns if d.domain == "junkerwerk.hu")
    assert VC.positiv_ohne_rohfakt(data_for(JW), facts, output_for(JW)) == []
    hu.evidence = [e for e in hu.evidence if e.tool != "zone_transfer"]
    defekte = VC.positiv_ohne_rohfakt(data_for(JW), facts, output_for(JW))
    assert [d.detail for d in defekte] == [{"regel": "dns_zone_transfer", "subjekt": "junkerwerk.hu",
                                            "werkzeug": "zone_transfer"}]
    assert defekte[0].is_error


def test_positiv_ohne_bejahte_regel_greift() -> None:
    """Ein Positivbefund nennt ein Subjekt, fuer das die Regel nicht bejaht ist (bergersysteme P06:
    CDN-Kante in der Reputation). Nachgestellt ueber die Herkunft des Positivbefunds."""
    data = _kopie(BS)
    p = next(p for p in data.positives if "ip_reputation" in p.checks)
    herkunft = next(h for h in p.provenance if h.statement == "positive.text")
    herkunft.members = [*herkunft.members, "198.202.211.1"]
    defekte = VC.positiv_ohne_rohfakt(data, facts_for(BS), output_for(BS))
    assert [d.detail for d in defekte] == [{"regel": "ip_reputation", "subjekt": "198.202.211.1"}]


# ---------------------------------------------------------------- E25 Anmeldenamen

def test_anmeldename_im_kundentext_greift() -> None:
    """castenow VS-018 (27.09.): der WordPress-Anmeldename stand in Personenform im Kundentext."""
    data = _kopie(CA)
    name = _http(CA, "ubb-wiki.castenow.de").wordpress.users[0]
    f = next(f for f in data.findings if "wordpress_user_enumeration" in f.checks)
    assert VC.anmeldename_im_kundentext(data, facts_for(CA)) == []
    f.affected = f"ubb-wiki.castenow.de ({name})"
    defekte = VC.anmeldename_im_kundentext(data, facts_for(CA))
    assert [d.detail for d in defekte] == [{"wo": f"{f.id}.affected", "anzahl": 1}]
    assert name not in defekte[0].message


# ---------------------------------------------------------------- N13 IPv6-Text

def test_ipv6_ohne_inventar_nur_ipv6_und_neuer_wortlaut() -> None:
    (d,) = VC.ipv6_ohne_inventar(facts_for(LW))
    assert "nicht im Scan-Inventar, im Bericht als ungeprüft ausgewiesen: 2a01:4f8:d0a:668b::2" in d.message
    # huendgen: der weitere A-Eintrag 52.59.120.70 ist keine IPv6-Adresse.
    assert VC.ipv6_ohne_inventar(facts_for(HE)) == []


# ---------------------------------------------------------------- N2 HSTS nach E24

def test_hsts_eigene_messung_nach_e24() -> None:
    assert "mailstore.castenow.de@195.50.179.5" in VC._hsts_eigene_messung(facts_for(CA))
    assert not any(s.startswith("online.heuel.com@") for s in VC._hsts_eigene_messung(facts_for(HL)))
    assert not any(s.startswith("ftp.bergersysteme.com@") for s in VC._hsts_eigene_messung(facts_for(BS)))

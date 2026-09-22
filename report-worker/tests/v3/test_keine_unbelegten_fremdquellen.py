# -*- coding: utf-8 -*-
"""Der Bericht darf keine Fremdquelle nennen, die nichts beigetragen hat (S5b).

Zwei Stellen taten das, solange nie eine CVE zitiert wurde und es deshalb
niemandem auffiel:

1. Der Befundblock schrieb ``CISA KEV: nein`` zu jeder zitierten CVE. Das ist
   eine Aussage ueber den KEV-Katalog, und ohne Anreicherung hat niemand
   nachgesehen.
2. Der Werkzeuganhang fuehrte "NVD, EPSS, CISA KEV" als eingesetzte
   Fremdquelle, weil der Korrelator gelaufen ist. Der laeuft aber immer; der
   Abgleich passiert nur, wenn eine Schwachstellennummer zu pruefen war.
"""
from __future__ import annotations

import pytest

from reporter.facts import schema as FS
from reporter.v3.appendix import build_tools
from tests.v3.conftest import data_for
from reporter.v3.golden import order_ids

ORDERS = order_ids()


def _threat(**kw) -> FS.ThreatFact:
    basis = dict(id="threat:CVE-2011-3389", source="testssl", mode="active",
                 observed_at="2026-09-20T10:00:00Z", confidence=1.0,
                 cve_id="CVE-2011-3389")
    basis.update(kw)
    return FS.ThreatFact(**basis)


def _facts(threats, decisions=()) -> FS.Facts:
    """Nur die zwei Entitaeten, auf die ``build_tools`` schaut."""
    scan = FS.ScanFact(id="scan:x", source="meta", mode="active",
                       observed_at="2026-09-20T10:00:00Z", confidence=1.0,
                       order_id="x", package="perimeter", domain="example.test")
    leer = FS.Facts(generator=FS.Generator(name="test", version="0"), scan=scan)
    return leer.model_copy(update={"threats": list(threats),
                                   "decisions": list(decisions),
                                   "coverage": [FS.CoverageFact(
                                       id="cov:3:phase3_correlation:scan",
                                       source="scan_results", mode="active",
                                       observed_at="2026-09-20T10:00:00Z",
                                       confidence=1.0, scope="scan",
                                       tool="phase3_correlation", status="ok")]})


@pytest.mark.parametrize("order_id", ORDERS)
def test_kein_kev_urteil_ohne_fremdbewertung(order_id):
    """Zu einer werkzeuggenannten CVE steht kein Ja oder Nein zum KEV-Katalog."""
    for f in data_for(order_id).findings:
        if not f.threat:
            continue
        werkzeug = all("keine Fremdbewertung" in c for c in f.threat.cves)
        if werkzeug:
            assert f.threat.kev == "", (
                f"{order_id[:8]} {f.id}: KEV-Urteil {f.threat.kev!r} ohne Fremdbewertung")


@pytest.mark.parametrize("order_id", ORDERS)
def test_keine_fremdquellen_zeile_ohne_anreicherung(order_id):
    """Solange nichts angereichert wurde, steht NVD/EPSS/KEV nicht im Anhang.

    Gilt heute fuer alle Auftraege; ``cves_enriched`` ist ueberall 0. Faellt der
    Test, liefert die Anreicherung endlich etwas, und dann gehoert die Zeile
    auch in den Bericht (Issue #26).
    """
    werkzeuge = [t.t for t in data_for(order_id).appendix.tools]
    assert not [t for t in werkzeuge if "NVD" in t], werkzeuge


def test_fremdquellen_zeile_kommt_mit_echtem_fremdwert():
    """Die Gegenprobe: mit Fremdwert steht die Zeile da."""
    ohne = build_tools(_facts([_threat(source="testssl")]))
    assert not [t for t in ohne if "NVD" in t.t]

    mit = build_tools(_facts([_threat(source="enrichment",
                                      cvss_nvd=FS.CvssRef(score=7.5))]))
    assert [t for t in mit if "NVD" in t.t], [t.t for t in mit]


def test_bilanz_der_korrelation_zaehlt_auch():
    """Auch ohne Threat-Fakt genuegt die Bilanz mit cves_enriched ueber null."""
    entscheidung = FS.DecisionFact(
        id="dec:phase3_correlation:scan", source="phase3_correlation", mode="active",
        observed_at="2026-09-20T10:00:00Z", confidence=1.0,
        payload={"cves_enriched": 2})
    mit = build_tools(_facts([], [entscheidung]))
    assert [t for t in mit if "NVD" in t.t], [t.t for t in mit]

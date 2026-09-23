"""Abgefragte DKIM-Selektoren in den Fakten (S6a, #15 Teil 2).

Neue Scans schreiben die Liste nach dns_records.json (`dkim_selectors_probed`). Fuer
aeltere Laeufe gilt die eingefrorene Liste des Scanners ab ae5fa74, aber nur, wenn die
dns_security-Ausgabe desselben Laufs diesen Stand belegt. Sonst bleibt die Liste
unbekannt, und der Bericht nennt keine Selektoren (Entscheidung DC).
"""
from __future__ import annotations

from reporter.facts import build as B

DS_AB_AE5FA74 = {"dnssec": {"dnssec_signed": False, "nsec3param_present": False},
                 "tls_rpt": {"tlsrpt_present": False}}
DS_VORHER = {"dnssec": {"dnssec_signed": False, "dnssec_valid": False, "issues": []},
             "caa": {"has_caa": False}, "mta_sts": {"has_dns_record": False}}


def test_liste_aus_dem_scan_hat_vorrang():
    dr = {"dkim": False, "dkim_selectors": [], "dkim_selectors_probed": ["s1", "default", "s1"]}
    assert B._dkim_probed(dr, DS_AB_AE5FA74) == (["default", "s1"], "scan")


def test_ohne_liste_mit_merkmal_gilt_der_scanner_stand():
    probed, basis = B._dkim_probed({"dkim": False}, DS_AB_AE5FA74)
    assert basis == "scanner_stand"
    assert probed == list(B.DKIM_SELECTORS_AE5FA74)
    assert len(probed) == 62 and probed == sorted(set(probed))


def test_nur_eines_der_beiden_merkmale_genuegt():
    assert B._scanner_stand_ae5fa74({"tls_rpt": {"tlsrpt_present": True}})
    assert B._scanner_stand_ae5fa74({"dnssec": {"nsec3param_present": True}})


def test_ohne_merkmal_bleibt_die_liste_unbekannt():
    assert B._dkim_probed({"dkim": False}, DS_VORHER) == (None, None)
    assert B._dkim_probed({"dkim": False}, {}) == (None, None)


def test_eingefrorene_liste_ist_die_des_scanners_von_ae5fa74():
    # Stichproben aus den Provider-Gruppen des Scanners (phase0.py, ae5fa74).
    for sel in ("default", "selector1", "selector2", "google", "k1", "s1", "hse1", "hse2",
                "amazonses", "ionos1", "strato1", "t-online", "gmx", "dkim-1", "sig2"):
        assert sel in B.DKIM_SELECTORS_AE5FA74, sel

# -*- coding: utf-8 -*-
"""Konsolidierung: mehrere Pruefungen ergeben einen Sachverhalt.

Die Fixtures sind bewusst winzig und synthetisch. Sie zeigen genau das Verhalten, das
die Buendelung ausmacht: zusammenfuehren nach ``merge_by``, Einstufung vom schwersten
Mitglied, Positivbefund nur ohne Fehlschlag in derselben Gruppe.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from reporter.catalog import evaluate
from reporter.catalog.engine import load_catalog
from reporter.v3.bundles import GLOBAL_KEY, consolidate
from reporter.v3.findings import build_positives
from tests.catalog.conftest import make_facts


def _run(partial: dict):
    facts = make_facts(partial, coverage_default="ok")
    return consolidate(evaluate(facts))


def _by_key(items, key):
    return [i for i in items if i.key == key]


TLS_ZWEI_HOSTS = {
    "hosts": [{"ip": "10.0.0.1", "family": 4}, {"ip": "10.0.0.2", "family": 4}],
    "fqdns": [{"name": "a.example.test", "host_ip": "10.0.0.1"},
              {"name": "b.example.test", "host_ip": "10.0.0.2"}],
    "tls": [
        {"host_ip": "10.0.0.1", "fqdn": "a.example.test", "port": 443, "source": "testssl",
         "protocols": {"SSLv2": False, "SSLv3": False, "TLS1.0": True, "TLS1.1": True,
                       "TLS1.2": True, "TLS1.3": False}},
        {"host_ip": "10.0.0.2", "fqdn": "b.example.test", "port": 443, "source": "testssl",
         "protocols": {"SSLv2": False, "SSLv3": False, "TLS1.0": False, "TLS1.1": False,
                       "TLS1.2": True, "TLS1.3": True}},
    ],
}


def test_buendel_fuehrt_pruefungen_eines_hosts_zusammen():
    """Veraltete Protokolle und fehlendes aktuelles Protokoll auf einem Host: ein Befund."""
    findings, _ = _run(TLS_ZWEI_HOSTS)
    tls = _by_key(findings, "tls_hardening")
    assert len(tls) == 1, [f"{i.key}@{i.merge_key}" for i in tls]
    item = tls[0]
    assert item.merge_key == "10.0.0.1"
    assert {r.check_id for r in item.results} >= {"tls_legacy_protocols", "tls_no_13"}


def test_buendel_trennt_nach_host():
    """Derselbe Sachverhalt auf zwei Hosts ergibt zwei Befunde, nicht einen."""
    partial = {
        "hosts": [{"ip": "10.0.0.1", "family": 4}, {"ip": "10.0.0.2", "family": 4}],
        "fqdns": [{"name": "a.example.test", "host_ip": "10.0.0.1"},
                  {"name": "b.example.test", "host_ip": "10.0.0.2"}],
        "tls": [
            {"host_ip": ip, "fqdn": name, "port": 443, "source": "testssl",
             "protocols": {"SSLv2": False, "SSLv3": False, "TLS1.0": True, "TLS1.1": True,
                           "TLS1.2": True, "TLS1.3": False}}
            for ip, name in (("10.0.0.1", "a.example.test"), ("10.0.0.2", "b.example.test"))
        ],
    }
    findings, _ = _run(partial)
    assert {i.merge_key for i in _by_key(findings, "tls_hardening")} == {"10.0.0.1", "10.0.0.2"}


def test_buendel_erbt_die_schwerste_einstufung():
    """tls_legacy_protocols ist hoch, tls_no_13 niedrig: der Befund ist hoch."""
    findings, _ = _run(TLS_ZWEI_HOSTS)
    item = _by_key(findings, "tls_hardening")[0]
    assert (item.scale, item.level) == ("hygiene", "hoch")


def test_domain_buendel_laeuft_ueber_die_domain():
    partial = {"dns": [{"domain": "example.test", "dnssec": {"signed": False, "valid": False},
                        "caa": {"present": False}}]}
    findings, _ = _run(partial)
    dns = _by_key(findings, "dns_hygiene")
    assert len(dns) == 1
    assert dns[0].merge_key == "example.test"
    assert {r.check_id for r in dns[0].results} == {"dnssec_missing", "caa_missing"}


def test_positivbefund_nur_ohne_fehlschlag_in_derselben_gruppe():
    """Host 2 besteht die TLS-Pruefungen mit Daten und liefert Positivbefunde je Regel.

    S6b-2 (spec/09 Q12): der Sammeltitel des Buendels steht nur, wenn jedes Mitglied mit
    Positivtext bestanden hat. Hier fehlen Daten fuer Fallback-SCSV und HSTS, deshalb
    nennt jeder Positivbefund genau die Regel, die bestanden hat.
    """
    _, positives = _run(TLS_ZWEI_HOSTS)
    assert not _by_key(positives, "tls_hardening")
    tls = [p for p in positives if p.key in ("tls_legacy_protocols", "tls_no_13", "tls_weak_ciphers")]
    assert {p.key for p in tls} == {"tls_legacy_protocols", "tls_no_13", "tls_weak_ciphers"}
    for item in tls:
        assert item.merge_key == GLOBAL_KEY
        assert all(r.status == "pass" for r in item.results)
        assert "10.0.0.1" not in {str(r.vars.get("host_ip")) for r in item.results}


def test_pruefung_ohne_buendel_bleibt_ein_eigener_sachverhalt():
    partial = {
        "hosts": [{"ip": "10.0.0.1", "family": 4}],
        "services": [
            {"host_ip": "10.0.0.1", "port": 3306, "proto": "tcp", "state": "open",
             "service": "mysql", "product": "MariaDB"},
            {"host_ip": "10.0.0.1", "port": 5432, "proto": "tcp", "state": "open",
             "service": "postgresql", "product": "PostgreSQL"},
        ],
    }
    findings, _ = _run(partial)
    db = _by_key(findings, "db_exposed")
    assert len(db) == 1
    assert len(db[0].results[0].affected) == 2, "beide Ports gehoeren in einen Befund"


def test_anhang_buendel_landet_nicht_in_der_befundliste():
    catalog = load_catalog()
    appendix = [b for b in catalog.bundles if b.target == "appendix"]
    assert appendix, "mindestens ein Buendel gehoert in den Anhang"
    for bundle in appendix:
        for member in bundle.members:
            assert catalog.by_id[member].spec.bundle == bundle.id


@pytest.mark.parametrize("bundle_id", [b.id for b in load_catalog().bundles])
def test_jedes_buendel_hat_sammeltitel_und_mitglieder(bundle_id):
    """S6b-2 (spec/09 Q4): ein Buendel gruppiert nur; die Texte kommen aus den Regeln."""
    catalog = load_catalog()
    bundle = catalog.bundle_by_id[bundle_id]
    assert bundle.members
    assert not hasattr(bundle, "texts")
    if bundle.target == "findings":
        assert "{rules}" in bundle.title, "der Sammeltitel nennt die getroffenen Regeln"
        for member in bundle.members:
            assert catalog.by_id[member].spec.texts.short, f"{member}: Kurzform fuer den Sammeltitel fehlt"
    if any(catalog.by_id[m].spec.texts.positive for m in bundle.members):
        assert bundle.positive_title, "Buendel mit Positivtexten braucht einen Positivtitel"


# ---------------------------------------------------------------- Issue #30 (S6a)
# Der Positivbefund des Buendels remote_admin_closed prueft nur RDP und SMB. Neben FTP,
# einer Verwaltungsoberflaeche oder SSH ausserhalb Port 22 mit Befund las er sich wie
# eine Entwarnung fuer den ganzen Host. Der betroffene Host faellt heraus.

HUENDGEN = json.loads((Path(__file__).parent / "fixtures" / "huendgen_62c1e866.json")
                      .read_text(encoding="utf-8"))
HUENDGEN_FTP_HOST = "217.160.231.238"
NEUER_TITEL = ("Keine Windows-Fernwartung (RDP) und keine Windows-Dateifreigabe (SMB) "
               "aus dem Internet erreichbar")


def _huendgen(**aenderung) -> dict:
    partial = copy.deepcopy({k: v for k, v in HUENDGEN.items() if not k.startswith("_")})
    partial.update(aenderung)
    return partial


def _fernwartung(positives):
    treffer = _by_key(positives, "remote_admin_closed")
    assert len(treffer) <= 1
    return treffer[0] if treffer else None


def _hosts(item) -> set[str]:
    return {str(r.vars.get("host_ip")) for r in item.results}


def test_huendgen_ftp_host_faellt_aus_dem_positivbefund():
    """Regressionssperre #30: FTP auf 217.160.231.238:21 steht als Befund.

    S6b-2 (spec/08 Punkt 4): ohne Beleg fuer fehlenden TLS-Zwang meldet nicht mehr
    ``ftp_plaintext`` den Port, sondern ``legacy_protocols_present``.
    """
    findings, positives = _run(_huendgen())
    assert any(m.key == f"{HUENDGEN_FTP_HOST}:21" and m.status == "fail"
               for i in findings for r in i.results if r.check_id == "legacy_protocols_present"
               for m in r.members), "der FTP-Befund selbst muss bleiben"
    item = _fernwartung(positives)
    assert item is not None, "die zwei Hosts ohne Konflikt behalten den Positivbefund"
    assert item.title == NEUER_TITEL
    assert _hosts(item) == {"18.197.248.23", "80.90.145.166"}
    assert item.excluded_hosts == [HUENDGEN_FTP_HOST]
    (positiv,) = build_positives([item])
    assert positiv.title == NEUER_TITEL
    assert HUENDGEN_FTP_HOST not in positiv.text
    assert "18.197.248.23" in positiv.text and "80.90.145.166" in positiv.text


def test_huendgen_ohne_ftp_behaelt_der_host_den_positivbefund():
    services = [s for s in HUENDGEN["services"]
                if not (s["host_ip"] == HUENDGEN_FTP_HOST and s["port"] == 21)]
    _, positives = _run(_huendgen(services=services))
    item = _fernwartung(positives)
    assert HUENDGEN_FTP_HOST in _hosts(item)
    assert item.excluded_hosts == []


def test_ein_host_mit_ftp_ohne_rest_kein_positivbefund():
    """Wie dortmund-beach: ein einziger Host, FTP darauf, kein Positivbefund."""
    partial = {"services": [
        {"host_ip": "10.0.0.1", "port": 21, "service": "ftp", "product": "Pure-FTPd"},
        {"host_ip": "10.0.0.1", "port": 443, "service": "https", "tls_required": True},
    ]}
    _, positives = _run(partial)
    assert _fernwartung(positives) is None


def test_verwaltungsoberflaeche_als_befund_nimmt_den_host_heraus():
    partial = {"services": [
        {"host_ip": "10.0.0.1", "port": 10000, "service": "snet-sensor-mgmt", "tunnel_ssl": True},
        {"host_ip": "10.0.0.2", "port": 443, "service": "https", "tls_required": True},
    ]}
    findings, positives = _run(partial)
    # S6b-2 (Q13): Port 10000 ohne Fingerabdruck ist "Zweck klaeren", nicht Webmin.
    assert any(r.check_id == "admin_service_unconfirmed" and r.status == "fail"
               for i in findings for r in i.results)
    item = _fernwartung(positives)
    assert _hosts(item) == {"10.0.0.2"}
    assert item.excluded_hosts == ["10.0.0.1"]


def test_ssh_ausserhalb_22_nur_mit_befund():
    mit_banner = {"host_ip": "10.0.0.1", "port": 30000, "service": "ssh", "product": "OpenSSH",
                  "version_raw": "8.4p1", "version_norm": "8.4p1", "family": "openssh"}
    ohne_befund = {"host_ip": "10.0.0.1", "port": 30000, "service": "ssh"}
    https = {"host_ip": "10.0.0.1", "port": 443, "service": "https", "tls_required": True}

    # S6b-2 (spec/09 Q4): das SSH-Banner gehoert zum Protokoll und ist kein Befund mehr;
    # ohne Befund auf dem Port behaelt der Host den Positivbefund.
    findings, positives = _run({"services": [mit_banner, https]})
    assert not any(r.check_id == "service_banner_version" and r.status == "fail"
                   for i in findings for r in i.results)
    assert _hosts(_fernwartung(positives)) == {"10.0.0.1"}

    # Ein Befund auf dem SSH-Port (hier ein Verwaltungsport) nimmt den Host heraus.
    auf_verwaltungsport = dict(mit_banner, port=10000)
    findings, positives = _run({"services": [auf_verwaltungsport, https]})
    assert any(r.check_id == "admin_service_unconfirmed" and r.status == "fail"
               for i in findings for r in i.results)
    assert _fernwartung(positives) is None

    findings, positives = _run({"services": [ohne_befund, https]})
    fails_30000 = [m for i in findings for r in i.results for m in r.members
                   if m.status == "fail" and m.port == 30000]
    assert not fails_30000, "Vorbedingung: SSH auf 30000 ohne eigenen Befund"
    assert _hosts(_fernwartung(positives)) == {"10.0.0.1"}


def test_viele_hosts_nennen_den_herausgenommenen():
    """Ab vier Hosts steht die Sammelbezeichnung; sie darf den FTP-Host nicht mitmeinen."""
    services = [{"host_ip": f"10.0.0.{n}", "port": 443, "service": "https", "tls_required": True}
                for n in range(1, 6)]
    services.append({"host_ip": "10.0.0.3", "port": 21, "service": "ftp", "product": "vsftpd"})
    _, positives = _run({"services": services})
    item = _fernwartung(positives)
    assert item.excluded_hosts == ["10.0.0.3"]
    (positiv,) = build_positives([item])
    assert "außer 10.0.0.3" in positiv.text


def test_positive_conflicts_greifen_nur_beim_eigenen_buendel():
    """Andere Positivbefunde bleiben fuer den FTP-Host unberuehrt."""
    _, positives = _run(_huendgen())
    andere = [p for p in positives if p.key != "remote_admin_closed"]
    assert andere and all(not p.excluded_hosts for p in andere)

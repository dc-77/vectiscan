# -*- coding: utf-8 -*-
"""Konsolidierung: mehrere Pruefungen ergeben einen Sachverhalt.

Die Fixtures sind bewusst winzig und synthetisch. Sie zeigen genau das Verhalten, das
die Buendelung ausmacht: zusammenfuehren nach ``merge_by``, Einstufung vom schwersten
Mitglied, Positivbefund nur ohne Fehlschlag in derselben Gruppe.
"""
from __future__ import annotations

import pytest

from reporter.catalog import evaluate
from reporter.catalog.engine import load_catalog
from reporter.v3.bundles import GLOBAL_KEY, consolidate
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
    """Host 2 besteht alle TLS-Pruefungen und liefert deshalb einen Positivbefund."""
    _, positives = _run(TLS_ZWEI_HOSTS)
    tls = _by_key(positives, "tls_hardening")
    assert len(tls) == 1
    assert tls[0].merge_key == GLOBAL_KEY
    assert all(r.status == "pass" for r in tls[0].results)
    assert "10.0.0.1" not in {str(r.vars.get("host_ip")) for r in tls[0].results}


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
def test_jedes_buendel_hat_texte_und_mitglieder(bundle_id):
    bundle = load_catalog().bundle_by_id[bundle_id]
    assert bundle.members
    assert bundle.texts.observation and bundle.texts.meaning and bundle.texts.verify
    assert bundle.texts.recommendation
    if bundle.target == "findings":
        assert bundle.texts.positive is not None, "ein Buendel im Bericht braucht auch den Positivfall"

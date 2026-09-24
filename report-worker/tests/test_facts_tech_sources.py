"""S6a2 (spec/09 Q11): Namensgrenzen und Quelle der Softwarefakten.

Das Fixture ``tests/fixtures/facts/tech_quellen`` ist ein Host wie bei lumbeck-wolter
und junkerwerk: nmap liefert MariaDB mit dem Kompatibilitaetspraefix 5.5.5- und
PostgreSQL „9.6.0 or later", httpx meldet jQuery und jQuery Migrate, webtech hat
nichts geliefert. Das Tech-Profil aus phase1 fuehrt alles in einer Liste ohne Herkunft.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from reporter.facts.build import build_facts
from reporter.facts.versions import classify, normalize

FIXTURE = Path(__file__).parent / "fixtures" / "facts" / "tech_quellen"
IP = "203.0.113.10"


def _software(facts, family: str):
    return [s for s in facts.software if s.host_ip == IP and s.family == family]


@pytest.fixture(scope="module")
def facts():
    return build_facts(FIXTURE)


# ---------------------------------------------------------------- Namensgrenzen

@pytest.mark.parametrize("name,family,product", [
    ("jQuery Migrate", "jquery_migrate", "jQuery Migrate"),
    ("jQuery UI", "jquery_ui", "jQuery UI"),
    ("Apache Tomcat", "apache_tomcat", "Apache Tomcat"),
    ("ProFTPD or KnFTPD", "proftpd_or_knftpd", "ProFTPD or KnFTPD"),
    ("Express", "express", "Express"),
])
def test_nie_ueber_namensgrenzen(name, family, product):
    fam, kind, prod, eol_key = classify(name)
    assert (fam, prod, eol_key) == (family, product, None)
    assert kind == "component"


@pytest.mark.parametrize("name,family", [
    ("jQuery", "jquery"),
    ("PostgreSQL DB", "postgresql"),
    ("Apache httpd", "apache"),
    ("Apache HTTP Server", "apache"),
    ("Dovecot imapd", "dovecot"),
    ("Courier pop3d", "courier"),
    ("Postfix smtpd", "postfix"),
    ("Exim smtpd", "exim"),
    ("Microsoft IIS httpd", "iis"),
    ("Microsoft ASP.NET", "aspnet"),
    ("Microsoft SQL Server", "mssql"),
    ("ProFTPD mod_sftp", "proftpd_sftp"),
    ("Icecast streaming media server", "icecast"),
    ("Joomla! - Open Source Content Management", "joomla"),
    ("PleskLin", "plesk"),
])
def test_neutrale_zusaetze_behalten_die_familie(name, family):
    assert classify(name)[0] == family


def test_jquery_migrate_behaelt_seine_version_und_wird_nicht_jquery():
    n = normalize("jQuery Migrate", "3.4.1")
    assert (n.family, n.product, n.version) == ("jquery_migrate", "jQuery Migrate", "3.4.1")


def test_fakten_trennen_jquery_und_jquery_migrate(facts):
    migrate = _software(facts, "jquery_migrate")
    assert [(s.product, s.version_norm) for s in migrate] and all(
        (s.product, s.version_norm) == ("jQuery Migrate", "3.4.1") for s in migrate)
    assert all(s.version_norm != "3.4.1" for s in _software(facts, "jquery"))


# ---------------------------------------------------------------- Untergrenze

def test_or_later_ergibt_keine_version_und_kein_eol(facts):
    pg = _software(facts, "postgresql")
    assert pg and all(s.version_norm is None and s.eol.status == "unknown" and not s.eol.date for s in pg)


def test_mariadb_praefix_ist_mariadb_10_11(facts):
    assert not _software(facts, "mysql")
    maria = _software(facts, "mariadb")
    assert maria and all(s.version_norm == "10.11.18" and s.eol.status != "eol" for s in maria)


# ---------------------------------------------------------------- Quelle

def test_quelle_ist_das_liefernde_werkzeug(facts):
    by_family = {s.family: s for s in facts.software if s.host_ip == IP and not s.fqdn}
    for fam in ("mariadb", "postgresql", "proftpd", "courier", "dovecot", "exim", "iis"):
        assert by_family[fam].detection_sources == ["nmap"], fam
    # nginx meldet auch httpx als webserver; geliefert hat den Profileintrag aber nmap,
    # das in der Scanner-Reihenfolge zuerst kommt (phase1 vor tech_enricher).
    assert by_family["nginx"].detection_sources == ["nmap"]
    assert by_family["jquery_migrate"].detection_sources == ["httpx"]


def test_webtech_ohne_ergebnis_ist_nie_quelle(facts):
    assert all("webtech" not in s.detection_sources for s in facts.software)


def test_webtech_mit_ergebnis_bleibt_quelle(tmp_path):
    scan = tmp_path / "scan"
    shutil.copytree(FIXTURE, scan)
    (scan / "hosts" / IP / "phase1" / "webtech.json").write_text(
        json.dumps({"tech": [{"name": "jQuery", "version": ""}]}), encoding="utf-8")
    facts = build_facts(scan)
    jq = [s for s in facts.software if s.host_ip == IP and s.family == "jquery" and not s.fqdn]
    # webtech kommt in phase1 vor httpx (tech_enricher); beide melden jQuery.
    assert jq and jq[0].detection_sources == ["webtech"]
    maria = [s for s in facts.software if s.family == "mariadb" and not s.fqdn]
    assert maria[0].detection_sources == ["nmap"]


def test_eintrag_ohne_werkzeugbeleg_heisst_tech_profile(tmp_path):
    scan = tmp_path / "scan"
    shutil.copytree(FIXTURE, scan)
    tp_path = scan / "hosts" / IP / "phase1" / "tech_profile.json"
    tp = json.loads(tp_path.read_text(encoding="utf-8"))
    tp["technologies"].append({"name": "Grafana", "version": "9.1.0"})
    tp_path.write_text(json.dumps(tp), encoding="utf-8")
    facts = build_facts(scan)
    graf = [s for s in facts.software if s.family == "grafana"]
    assert graf and graf[0].detection_sources == ["tech_profile"]

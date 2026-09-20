"""Issue #9: testssl lief mit --severity MEDIUM, LOW- und OK-Zeilen fehlten.

Befund aus Session S1: phase2 las testssl_severity mit Default "MEDIUM"; nur
tlscompliance setzte den Filter leer. Das Tar-JSON (hosts/<ip>/phase2/testssl.json)
trug deshalb nur Eintraege ab MEDIUM. Der Pruefkatalog braucht beides: "TLS1.0
offered" ist LOW, "TLS1.0 not offered" ist OK. Ohne die OK-Zeilen bleibt
tls.protocols[...] None und es entsteht wegen der Dreiwertigkeit weder ein
Befund noch eine Positivaussage.

Nebenwirkung, die mitgetestet wird: der v2-Korrelator machte aus jedem
testssl-Eintrag einen Finding. Ohne Filter waeren das hunderte Info-Findings
je Host. extract_findings nimmt deshalb nur MEDIUM und hoeher.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from scanner.correlation.correlator import extract_findings
from scanner.packages import PACKAGE_CONFIG, get_config


PACKAGES = sorted(PACKAGE_CONFIG)


# ------------------------------------------------------------ Paketkonfig

@pytest.mark.parametrize("package", PACKAGES)
def test_kein_severity_filter_in_keinem_paket(package):
    """Der Filter ist ueberall leer; kein Paket faellt mehr auf MEDIUM."""
    assert get_config(package).get("testssl_severity") == ""


def test_default_ohne_konfig_ist_leer():
    """Auch ohne Schluessel in der Konfig darf nicht MEDIUM herauskommen."""
    config: dict = {}
    assert config.get("testssl_severity", "") == ""


# ------------------------------------------------- Kommandozeile in phase2

def _mock_zap():
    zap = MagicMock()
    zap.health_check.return_value = True
    zap.get_version.return_value = "2.17.0"
    zap.create_context.return_value = 1
    zap.start_spider.return_value = 1
    zap.spider_status.return_value = 100
    zap.spider_results.return_value = ["https://example.com/"]
    zap.ajax_spider_status.return_value = "stopped"
    zap.start_active_scan.return_value = 1
    zap.active_scan_status.return_value = 100
    zap.wait_for_passive_scan.return_value = True
    zap.get_alerts.return_value = []
    return zap


def _run_phase2_for(package: str, tmp_path):
    """run_phase2 mit gemockten Werkzeugen; liefert den run_testssl-Mock."""
    from scanner.phase2 import run_phase2

    tech_profile = {
        "fqdn": "example.com",
        "cms": None,
        "technologies": [],
        "has_web": True,
        "has_ssl": True,          # phase2.py:1037 gated den testssl-Runner darauf
        "open_ports": [80, 443],
    }
    # dict()-Copy: get_config liefert das geteilte Modul-Dict (vgl.
    # tests/test_phase2_packages.py).
    config = dict(get_config(package))
    config["package"] = package

    with patch("scanner.tools.zap_client.ZapClient", return_value=_mock_zap()), \
            patch("scanner.phase2.publish_tool_output"), \
            patch("scanner.phase2.publish_event"), \
            patch("scanner.phase2._save_result"), \
            patch("scanner.phase2.record_tool_run"), \
            patch("scanner.phase2.run_header_check", return_value={"score": "5/7"}), \
            patch("scanner.phase2.run_httpx", return_value={"status_code": 200}), \
            patch("scanner.phase2.run_testssl", return_value=[]) as mock_testssl:
        run_phase2(
            "1.2.3.4", ["example.com"], tech_profile,
            str(tmp_path / "scan"), "order-1", MagicMock(), config,
        )
    return mock_testssl


@pytest.mark.parametrize("package", PACKAGES)
def test_run_testssl_bekommt_leere_severity(package, tmp_path):
    """Jedes Paket fuehrt testssl (VEC-308) und darf keinen Filter setzen."""
    mock_testssl = _run_phase2_for(package, tmp_path)
    assert mock_testssl.called, f"{package} fuehrt testssl nicht mehr"
    assert mock_testssl.call_args.kwargs["severity"] == ""


# --------------------------------------------------- Korrelator-Filter

def _entry(sev: str, ident: str, finding: str = "some finding"):
    return {"id": ident, "severity": sev, "finding": finding}


def _host(entries):
    return [{"ip": "1.2.3.4", "fqdn": "example.com", "testssl": entries}]


def test_ok_und_info_zeilen_werden_keine_findings():
    """Genau die Zeilen, die neu im JSON stehen, duerfen v2 nicht fluten."""
    entries = [
        _entry("OK", "TLS1", "not offered"),
        _entry("INFO", "cipher_x", "TLS_AES_256_GCM_SHA384"),
    ]
    assert extract_findings(_host(entries)) == []


def test_low_zeilen_werden_keine_findings():
    """LOW gab es vor S2b im JSON nicht; der v2-Bericht bleibt unveraendert."""
    entries = [_entry("LOW", "TLS1", "offered (deprecated)")]
    assert extract_findings(_host(entries)) == []


def test_medium_und_hoeher_bleiben_findings():
    entries = [
        _entry("OK", "TLS1_3", "offered"),
        _entry("LOW", "TLS1", "offered"),
        _entry("MEDIUM", "BREACH", "potentially VULNERABLE"),
        _entry("HIGH", "SWEET32", "VULNERABLE"),
        _entry("CRITICAL", "heartbleed", "VULNERABLE (CVE-2014-0160)"),
    ]
    findings = extract_findings(_host(entries))
    assert [f.title for f in findings] == ["BREACH", "SWEET32", "heartbleed"]
    assert [f.severity for f in findings] == ["medium", "high", "high"]


def test_cve_wird_weiter_erkannt():
    entries = [_entry("CRITICAL", "heartbleed", "VULNERABLE (CVE-2014-0160)")]
    findings = extract_findings(_host(entries))
    assert findings[0].cve_id == "CVE-2014-0160"

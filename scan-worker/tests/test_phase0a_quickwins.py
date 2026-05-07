"""Tests for F-P0A-001 (Inner-Parallelization) + F-P0A-005 (IP-Cap konfigurierbar).

Audit-Eintraege: docs/scan-flow/Scan-Optimierung.md Sektionen 3.2.1, 3.2.3.
"""

from __future__ import annotations

import time
from unittest.mock import patch, MagicMock

import pytest

from scanner.packages import get_config


# ---------------------------------------------------------------------------
# F-P0A-005: phase0a_ip_cap paketabhaengig
# ---------------------------------------------------------------------------

def test_perimeter_phase0a_ip_cap_25():
    assert get_config("perimeter")["phase0a_ip_cap"] == 25


def test_compliance_phase0a_ip_cap_25():
    assert get_config("compliance")["phase0a_ip_cap"] == 25


def test_supplychain_phase0a_ip_cap_25():
    assert get_config("supplychain")["phase0a_ip_cap"] == 25


def test_insurance_phase0a_ip_cap_50():
    assert get_config("insurance")["phase0a_ip_cap"] == 50


# ---------------------------------------------------------------------------
# F-P0A-005: ENV-Override PHASE0A_IP_CAP wirksam in run_phase0a
# ---------------------------------------------------------------------------

def _shodan_stub(ports_lookup):
    """Liefert ein Mock-ShodanClient mit `available=True` und konfigurierbarem
    lookup_host-Resultat pro IP."""
    stub = MagicMock()
    stub.available = True
    stub.lookup_domain.return_value = None
    stub.lookup_host.side_effect = lambda ip: ports_lookup.get(ip)
    return stub


def test_phase0a_ip_cap_env_override_caps_below_paket_default(tmp_path):
    """ENV PHASE0A_IP_CAP=2 schneidet auf 2 IPs runter, auch wenn config 25 sagt."""
    from scanner import phase0a as ph

    ips = [f"1.2.3.{i}" for i in range(10)]
    seen_ips: list[str] = []

    def fake_lookup(ip):
        seen_ips.append(ip)
        return {"ports": [80]}

    shodan_stub = MagicMock()
    shodan_stub.available = True
    shodan_stub.lookup_domain.return_value = None
    shodan_stub.lookup_host.side_effect = fake_lookup

    abuse_stub = MagicMock()
    abuse_stub.available = False

    st_stub = MagicMock()
    st_stub.available = False

    whois_stub = MagicMock()
    whois_stub.lookup.return_value = None

    with patch.dict("os.environ", {"PHASE0A_IP_CAP": "2"}, clear=False), \
         patch.object(ph, "ShodanClient", return_value=shodan_stub), \
         patch.object(ph, "AbuseIPDBClient", return_value=abuse_stub), \
         patch.object(ph, "SecurityTrailsClient", return_value=st_stub), \
         patch.object(ph, "WhoisClient", return_value=whois_stub), \
         patch.object(ph, "run_all_dns_security", return_value={}), \
         patch.object(ph, "publish_event"):
        config = {
            "phase0a_tools": ["shodan", "abuseipdb", "securitytrails", "whois"],
            "phase0a_ip_cap": 25,  # config-default
            "package": "perimeter",
        }
        ph.run_phase0a("example.com", ips, str(tmp_path), "test-id", config)

    assert len(seen_ips) == 2, f"PHASE0A_IP_CAP=2 ignoriert: gesehen={seen_ips}"


def test_phase0a_ip_cap_uses_config_default_when_no_env(tmp_path, monkeypatch):
    """Ohne ENV: phase0a_ip_cap aus config wird genutzt."""
    from scanner import phase0a as ph

    monkeypatch.delenv("PHASE0A_IP_CAP", raising=False)

    ips = [f"1.2.3.{i}" for i in range(10)]
    seen_ips: list[str] = []

    def fake_lookup(ip):
        seen_ips.append(ip)
        return {"ports": [80]}

    shodan_stub = MagicMock()
    shodan_stub.available = True
    shodan_stub.lookup_domain.return_value = None
    shodan_stub.lookup_host.side_effect = fake_lookup

    abuse_stub = MagicMock()
    abuse_stub.available = False
    st_stub = MagicMock()
    st_stub.available = False
    whois_stub = MagicMock()
    whois_stub.lookup.return_value = None

    with patch.object(ph, "ShodanClient", return_value=shodan_stub), \
         patch.object(ph, "AbuseIPDBClient", return_value=abuse_stub), \
         patch.object(ph, "SecurityTrailsClient", return_value=st_stub), \
         patch.object(ph, "WhoisClient", return_value=whois_stub), \
         patch.object(ph, "run_all_dns_security", return_value={}), \
         patch.object(ph, "publish_event"):
        config = {
            "phase0a_tools": ["shodan"],
            "phase0a_ip_cap": 5,
            "package": "perimeter",
        }
        ph.run_phase0a("example.com", ips, str(tmp_path), "test-id", config)

    assert len(seen_ips) == 5, f"phase0a_ip_cap=5 ignoriert: gesehen={seen_ips}"


# ---------------------------------------------------------------------------
# F-P0A-001: Shodan IP-Loop parallel — slow lookups duerfen sich nicht summieren
# ---------------------------------------------------------------------------

def test_phase0a_shodan_ip_loop_parallel(tmp_path, monkeypatch):
    """6 IPs mit je 0.15s Lookup-Latenz duerfen nicht 0.9s sequenziell brauchen.

    Default-Concurrency ist 3, also ~0.3s parallel statt ~0.9s seriell.
    """
    from scanner import phase0a as ph

    monkeypatch.delenv("PHASE0A_IP_CAP", raising=False)
    monkeypatch.delenv("PASSIVE_INTEL_CONCURRENCY", raising=False)

    ips = [f"1.2.3.{i}" for i in range(6)]

    def slow_lookup(ip):
        time.sleep(0.15)
        return {"ports": [80]}

    shodan_stub = MagicMock()
    shodan_stub.available = True
    shodan_stub.lookup_domain.return_value = None
    shodan_stub.lookup_host.side_effect = slow_lookup

    abuse_stub = MagicMock()
    abuse_stub.available = False
    st_stub = MagicMock()
    st_stub.available = False
    whois_stub = MagicMock()
    whois_stub.lookup.return_value = None

    with patch.object(ph, "ShodanClient", return_value=shodan_stub), \
         patch.object(ph, "AbuseIPDBClient", return_value=abuse_stub), \
         patch.object(ph, "SecurityTrailsClient", return_value=st_stub), \
         patch.object(ph, "WhoisClient", return_value=whois_stub), \
         patch.object(ph, "run_all_dns_security", return_value={}), \
         patch.object(ph, "publish_event"):
        config = {
            "phase0a_tools": ["shodan"],
            "phase0a_ip_cap": 10,
            "package": "perimeter",
        }
        start = time.monotonic()
        ph.run_phase0a("example.com", ips, str(tmp_path), "test-id", config)
        duration = time.monotonic() - start

    # Sequentiell: 6 * 0.15 = 0.9s. Parallel mit max_workers=3: ~0.3-0.5s.
    assert duration < 0.75, f"Shodan-IP-Loop offenbar nicht parallel: {duration:.2f}s"


def test_phase0a_securitytrails_three_calls_parallel(tmp_path, monkeypatch):
    """SecurityTrails 3 Calls (lookup_domain + get_subdomains + get_dns_history)
    muessen parallel laufen — bei je 0.2s Latenz: ~0.2s statt 0.6s seriell."""
    from scanner import phase0a as ph

    monkeypatch.delenv("PHASE0A_IP_CAP", raising=False)
    monkeypatch.delenv("PASSIVE_INTEL_CONCURRENCY", raising=False)

    def slow(*_a, **_kw):
        time.sleep(0.2)
        return {}

    st_stub = MagicMock()
    st_stub.available = True
    st_stub.lookup_domain.side_effect = slow
    st_stub.get_subdomains.side_effect = slow
    st_stub.get_dns_history.side_effect = slow

    shodan_stub = MagicMock()
    shodan_stub.available = False
    abuse_stub = MagicMock()
    abuse_stub.available = False
    whois_stub = MagicMock()
    whois_stub.lookup.return_value = None

    with patch.object(ph, "ShodanClient", return_value=shodan_stub), \
         patch.object(ph, "AbuseIPDBClient", return_value=abuse_stub), \
         patch.object(ph, "SecurityTrailsClient", return_value=st_stub), \
         patch.object(ph, "WhoisClient", return_value=whois_stub), \
         patch.object(ph, "run_all_dns_security", return_value={}), \
         patch.object(ph, "publish_event"):
        config = {
            "phase0a_tools": ["securitytrails"],
            "phase0a_ip_cap": 25,
            "package": "perimeter",
        }
        start = time.monotonic()
        ph.run_phase0a("example.com", [], str(tmp_path), "test-id", config)
        duration = time.monotonic() - start

    # Sequentiell: 3 * 0.2 = 0.6s. Parallel: ~0.2-0.3s.
    assert duration < 0.5, f"SecurityTrails 3-Calls nicht parallel: {duration:.2f}s"

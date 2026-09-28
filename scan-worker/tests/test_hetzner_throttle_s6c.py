"""S6c/Q17 (spec/09, DC c): Hetzner-Drosselung + Sperrerkennung nach dem Portscan."""

from pathlib import Path
from unittest.mock import patch

from scanner import net_throttle, phase1, phase2


def test_is_throttled_host_rdns_your_server() -> None:
    assert net_throttle.is_throttled_host("116.202.77.64",
                                          rdns="static.64.77.202.116.clients.your-server.de") is True


def test_is_throttled_host_isp_hetzner() -> None:
    assert net_throttle.is_throttled_host("1.2.3.4", rdns="host.example.com",
                                          isp="Hetzner Online GmbH") is True


def test_is_throttled_host_konfigurierbare_netzliste(monkeypatch) -> None:
    monkeypatch.setenv("VECTISCAN_THROTTLE_NETS", "203.0.113.0/24")
    with patch.object(net_throttle, "_reverse_dns", return_value=""):
        assert net_throttle.is_throttled_host("203.0.113.9") is True
        assert net_throttle.is_throttled_host("198.51.100.9") is False


def test_is_throttled_host_negativ() -> None:
    with patch.object(net_throttle, "_reverse_dns", return_value="host.example.com"):
        assert net_throttle.is_throttled_host("198.51.100.9") is False


def test_nmap_throttle_flags() -> None:
    flags = phase1._nmap_throttle_flags()
    assert "--max-rate" in flags
    assert "--max-retries" in flags
    assert flags[flags.index("--max-retries") + 1] == "1"
    assert "--min-rate" not in flags
    assert "--defeat-rst-ratelimit" not in flags


def test_probe_reachable_blocked() -> None:
    with patch("socket.create_connection", side_effect=OSError("refused")), \
         patch("time.sleep", return_value=None):
        r = net_throttle.probe_reachable_after_portscan("116.202.77.64",
                                                        known_ports=[443], attempts=3)
    assert r["blocked"] is True
    assert r["reachable"] is False


def test_probe_reachable_ok() -> None:
    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("socket.create_connection", return_value=_Conn()):
        r = net_throttle.probe_reachable_after_portscan("116.202.77.64",
                                                        known_ports=[443], attempts=3)
    assert r["blocked"] is False
    assert r["time_to_reachable_s"] is not None


def test_phase2_provider_block_failed(tmp_path: Path) -> None:
    """Bleibt der Host gesperrt, sind alle Phase-2-Werkzeuge failed mit klarem Grund."""
    recorded = []

    def fake_record(order_id, ip, tool, status, reason):
        recorded.append((tool, status, reason))

    with patch.object(phase2, "_record_phase2_status", side_effect=fake_record):
        result = phase2.run_phase2(
            ip="116.202.77.64",
            fqdns=["www.lumbeck-wolter.de"],
            tech_profile={"has_ssl": True, "has_web": True,
                          "provider_block": {"blocked": True}},
            scan_dir=str(tmp_path),
            order_id="o",
            progress_callback=lambda *a: None,
            config={"phase2_tools": ["testssl", "headers", "httpx"]},
        )
    assert result.get("provider_blocked") is True
    assert recorded
    assert all(s == "failed" and "Portscan" in r for _, s, r in recorded)

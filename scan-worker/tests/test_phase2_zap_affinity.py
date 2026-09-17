"""S0b: Instanz-Affinitaet der ZAP-Aufrufe in Phase 2.

worker.py leaset einen ZAP aus dem Pool und legt die Instanz als
Thread-Local ab. Die ZAP-Arbeit laeuft aber in verschachtelten
ThreadPoolExecutors (p2s1, p2s2), und neue Threads erben keine
Thread-Locals: dort fiel ZapClient() auf den statischen ZAP_BASE_URL
zurueck. Kontext und Policy landeten damit auf einer anderen Instanz als der
Active Scan, und ZAP antwortete auf ascan/action/scan mit does_not_exist.

Der Test haelt fest, dass jede in Phase 2 erzeugte ZapClient-Instanz die
geleaste zap_id bekommt.
"""

from unittest.mock import MagicMock, patch

import pytest

from scanner.packages import get_config
from scanner.tools.zap_client import set_thread_zap_id


def _tech_profile():
    return {
        "ip": "1.2.3.4",
        "fqdns": ["example.com"],
        "has_ssl": True,
        "has_web": True,
        "open_ports": [80, 443],
    }


def _mock_zap():
    zap = MagicMock()
    zap.health_check.return_value = True
    zap.get_version.return_value = "2.17.0"
    zap.create_context.return_value = 1
    zap.context_exists.return_value = True
    zap.start_spider.return_value = 1
    zap.spider_status.return_value = 100
    zap.spider_results.return_value = ["https://example.com/",
                                       "https://example.com/about?q=1"]
    zap.ajax_spider_status.return_value = "stopped"
    zap.create_scan_policy.return_value = {40012}
    zap.last_dropped_scanner_ids = []
    zap.start_active_scan.return_value = 1
    zap.active_scan_status.return_value = 100
    zap.wait_for_passive_scan.return_value = True
    zap.get_alerts.return_value = []
    return zap


@pytest.fixture
def leased_thread_zap():
    set_thread_zap_id("zap-3")
    yield "zap-3"
    set_thread_zap_id(None)


@patch("scanner.phase2.publish_tool_output")
@patch("scanner.phase2.publish_event")
@patch("scanner.phase2._save_result")
@patch("scanner.phase2.record_tool_run")
@patch("scanner.phase2.run_testssl", return_value=[])
@patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
@patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
def test_alle_zap_clients_nutzen_die_geleaste_instanz(
    _httpx, _headers, _testssl, _record, _save, _event, _publish,
    leased_thread_zap, tmp_path,
):
    """Kontext, Spider, Policy, Active Scan und Alert-Sammlung: eine Instanz."""
    seen_zap_ids = []
    mock_zap = _mock_zap()

    def factory(*args, **kwargs):
        seen_zap_ids.append(kwargs.get("zap_id"))
        return mock_zap

    from scanner.phase2 import run_phase2

    with patch("scanner.tools.zap_client.ZapClient", side_effect=factory):
        config = dict(get_config("perimeter"))
        config["package"] = "perimeter"
        run_phase2("1.2.3.4", ["example.com"], _tech_profile(),
                   str(tmp_path / "scan"), "abcdefgh-1111", MagicMock(), config)

    assert seen_zap_ids, "in Phase 2 wurde gar kein ZapClient erzeugt"
    assert set(seen_zap_ids) == {"zap-3"}, (
        "mindestens ein ZAP-Aufruf ging nicht an die geleaste Instanz: "
        f"{seen_zap_ids}"
    )
    # Stage 1 (Kontext, Spider) und Stage 2 (Active Scan) muessen beide
    # stattgefunden haben, sonst prueft der Test nichts.
    mock_zap.create_context.assert_called()
    mock_zap.start_active_scan.assert_called()


@patch("scanner.phase2.publish_tool_output")
@patch("scanner.phase2.publish_event")
@patch("scanner.phase2._save_result")
@patch("scanner.phase2.record_tool_run")
@patch("scanner.phase2.run_testssl", return_value=[])
@patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
@patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
def test_ohne_pool_bleibt_zap_id_leer(
    _httpx, _headers, _testssl, _record, _save, _event, _publish, tmp_path,
):
    """Ohne Lease (ZAP_POOL_ENABLED=false) gilt weiter ZAP_BASE_URL."""
    set_thread_zap_id(None)
    seen_zap_ids = []
    mock_zap = _mock_zap()

    def factory(*args, **kwargs):
        seen_zap_ids.append(kwargs.get("zap_id"))
        return mock_zap

    from scanner.phase2 import run_phase2

    with patch("scanner.tools.zap_client.ZapClient", side_effect=factory):
        config = dict(get_config("perimeter"))
        config["package"] = "perimeter"
        run_phase2("1.2.3.4", ["example.com"], _tech_profile(),
                   str(tmp_path / "scan"), "abcdefgh-2222", MagicMock(), config)

    assert set(seen_zap_ids) == {None}


@patch("scanner.phase2.publish_tool_output")
@patch("scanner.phase2.publish_event")
@patch("scanner.phase2._save_result")
@patch("scanner.phase2.record_tool_run")
@patch("scanner.phase2.run_testssl", return_value=[])
@patch("scanner.phase2.run_header_check", return_value={"score": "3/7"})
@patch("scanner.phase2.run_httpx", return_value={"status_code": 200})
def test_active_scan_zielt_auf_einen_gespiderten_vhost(
    _httpx, _headers, _testssl, _record, _save, _event, _publish, tmp_path,
):
    """primary_fqdn ist nicht automatisch das Scanziel.

    Stage 1 spidert vhost_fqdns (VHosts mit 200er Antwort), Stage 2 scannte
    aber fqdns[0]. Waren beide verschieden, antwortete ZAP url_not_found
    bzw. url_not_in_context.
    """
    mock_zap = _mock_zap()
    from scanner.phase2 import run_phase2

    with patch("scanner.tools.zap_client.ZapClient", return_value=mock_zap):
        config = dict(get_config("perimeter"))
        config["package"] = "perimeter"
        run_phase2("1.2.3.4", ["nur-dns.example.com", "www.example.com"],
                   _tech_profile(), str(tmp_path / "scan"), "abcdefgh-3333",
                   MagicMock(), config, vhost_fqdns=["www.example.com"])

    target = mock_zap.start_active_scan.call_args[0][0]
    assert target == "https://www.example.com", (
        f"Active Scan zielte auf {target}, obwohl nur www.example.com gespidert wurde"
    )
    # Der Kontext muss den gescannten VHost abdecken.
    included = [c[0][1] for c in mock_zap.include_in_context.call_args_list]
    assert any("www\\.example\\.com" in pattern for pattern in included)

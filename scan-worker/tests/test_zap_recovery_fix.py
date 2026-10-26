"""Zwei Verlustpfade der ZAP-Befunde, gefunden in den Produktionslaeufen vom
Oktober 2026 (Auftraege 11aa6a3c rankingcoach und abcac6eb).

1. Scheiterte der Spider, blieb ``_zap_context`` leer, obwohl der Kontext in
   ZAP bereits bestand. Stage 3 verbuchte dann "no_zap_context" und warf die
   vom Passiv-Scanner schon erzeugten Alerts weg.
2. Das Warten auf die Passiv-Queue lief fest mit 30 Sekunden und sein Ergebnis
   wurde nicht ausgewertet. Auf grossen Zielen war die Queue danach nicht leer,
   die unvollstaendige Alertmenge ging aber als vollstaendig durch.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from scanner.packages import get_config
from scanner.tools.zap_client import PASSIVE_WAIT_TIMEOUT, READ_TIMEOUT, ZapError


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
    zap.spider_results.return_value = ["https://example.com/"]
    zap.ajax_spider_status.return_value = "stopped"
    zap.create_scan_policy.return_value = {40012}
    zap.last_dropped_scanner_ids = []
    zap.start_active_scan.return_value = 1
    zap.active_scan_status.return_value = 100
    zap.wait_for_passive_scan.return_value = True
    zap.get_alerts.return_value = []
    return zap


def _phase2_mit(mock_zap, order_id, tmp_path):
    """Phase 2 mit gemocktem ZAP fahren und die geschriebenen Zeilen liefern."""
    from scanner.phase2 import run_phase2

    with patch("scanner.phase2.publish_tool_output"), \
         patch("scanner.phase2.publish_event"), \
         patch("scanner.phase2._save_result"), \
         patch("scanner.phase2.record_tool_run") as rec, \
         patch("scanner.phase2.run_testssl", return_value=[]), \
         patch("scanner.phase2.run_header_check", return_value={"score": "3/7"}), \
         patch("scanner.phase2.run_httpx", return_value={"status_code": 200}), \
         patch("scanner.tools.zap_client.ZapClient", return_value=mock_zap):
        config = dict(get_config("perimeter"))
        config["package"] = "perimeter"
        run_phase2("1.2.3.4", ["example.com"], _tech_profile(),
                   str(tmp_path / "scan"), order_id, MagicMock(), config)
    return rec


def _zeilen(rec, tool_name):
    """Alle record_tool_run-Aufrufe zu einem Werkzeug."""
    treffer = []
    for call in rec.call_args_list:
        if len(call.args) >= 4 and call.args[3] == tool_name:
            treffer.append(call)
    return treffer


class TestKontextUeberlebtSpiderfehler:
    def test_alerts_werden_trotz_spiderfehler_geholt(self, tmp_path):
        """Der Kontext steht in ZAP, also bleibt die Alert-Sammlung moeglich."""
        zap = _mock_zap()
        zap.start_spider.side_effect = ZapError("ZAP request timed out")

        rec = _phase2_mit(zap, "aaaaaaaa-0001", tmp_path)

        zap.get_alerts.assert_called()
        zap_zeilen = _zeilen(rec, "zap")
        assert zap_zeilen, "keine zap-Zeile geschrieben"
        for call in zap_zeilen:
            assert call.kwargs.get("reason") != "no_zap_context", (
                "Alertsammlung wurde trotz bestehendem Kontext uebersprungen")

    def test_spider_bleibt_ein_ausfall(self, tmp_path):
        """Der Fehler wird nicht verschluckt: zap_spider ist weiterhin failed."""
        zap = _mock_zap()
        zap.start_spider.side_effect = ZapError("ZAP request timed out")

        rec = _phase2_mit(zap, "aaaaaaaa-0002", tmp_path)

        spider = _zeilen(rec, "zap_spider")
        assert any(c.args[4] == "failed" for c in spider if len(c.args) >= 5), (
            f"zap_spider nicht als failed verbucht: {[c.args for c in spider]}")

    def test_kein_active_scan_auf_leerem_site_tree(self, tmp_path):
        """Ohne gespiderte VHosts wird der Active Scan sauber uebersprungen,
        statt gegen einen leeren Site-Tree zu laufen (url_not_found)."""
        zap = _mock_zap()
        zap.start_spider.side_effect = ZapError("ZAP request timed out")

        rec = _phase2_mit(zap, "aaaaaaaa-0003", tmp_path)

        zap.start_active_scan.assert_not_called()
        aktiv = _zeilen(rec, "zap_active")
        assert any(c.kwargs.get("reason") == "no_spidered_vhost_in_context"
                   for c in aktiv), f"unerwarteter Grund: {[c.kwargs for c in aktiv]}"

    def test_kontext_wird_aufgeraeumt(self, tmp_path):
        """Der Kontext bleibt nach dem Fehler nicht als Leiche in ZAP zurueck."""
        zap = _mock_zap()
        zap.start_spider.side_effect = ZapError("ZAP request timed out")

        _phase2_mit(zap, "aaaaaaaa-0004", tmp_path)

        zap.remove_context.assert_called()


class TestPassivQueue:
    def test_default_timeout_ist_grosszuegig(self):
        """30 Sekunden reichten nur auf kleinen Zielen."""
        import inspect

        from scanner.tools.zap_client import ZapClient

        sig = inspect.signature(ZapClient.wait_for_passive_scan)
        assert sig.parameters["timeout"].default == PASSIVE_WAIT_TIMEOUT
        assert PASSIVE_WAIT_TIMEOUT > READ_TIMEOUT

    def test_phase2_uebergibt_keine_30_sekunden(self, tmp_path):
        """Die Aufrufstelle darf das Zeitlimit nicht wieder kleinrechnen."""
        zap = _mock_zap()

        _phase2_mit(zap, "aaaaaaaa-0005", tmp_path)

        zap.wait_for_passive_scan.assert_called()
        for call in zap.wait_for_passive_scan.call_args_list:
            assert call.kwargs.get("timeout", PASSIVE_WAIT_TIMEOUT) >= PASSIVE_WAIT_TIMEOUT
            assert not call.args or call.args[0] >= PASSIVE_WAIT_TIMEOUT

    @pytest.mark.parametrize("geleert", [True, False])
    def test_zeile_vermerkt_ob_die_queue_leer_wurde(self, geleert, tmp_path):
        """Eine unvollstaendige Passivmenge geht nicht als vollstaendig durch."""
        zap = _mock_zap()
        zap.wait_for_passive_scan.return_value = geleert
        zap.get_alerts.return_value = [
            {"name": "Test", "risk": "Low", "confidence": "High",
             "url": "https://example.com/", "pluginId": "10035"},
        ]

        rec = _phase2_mit(zap, "aaaaaaaa-0006", tmp_path)

        roh = [c for c in _zeilen(rec, "zap") if c.kwargs.get("raw_output")]
        assert roh, "keine zap-Zeile mit Rohdaten"
        summary = json.loads(roh[-1].kwargs["raw_output"])
        assert summary["passive_queue_drained"] is geleert

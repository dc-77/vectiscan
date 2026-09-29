"""S6d (C3): Per-Port-Sonden auf gedrosselten Hosts nacheinander mit Pause.

Messbefund aus JW f9a2a2f6 (S6c-Probe, 28.09.2026): auf dem gedrosselten
Hetzner-Host 188.40.3.130 erreichte die Einzel-Sperrprobe den Host, die
gleichzeitig gestarteten Per-Port-Sonden (testssl_21, _110, _143, _465, _587, _993,
_995 und smtp_ehlo_465, _587) brachen aber ab. Jetzt laufen auf gedrosselten Hosts
testssl je Port und je SNI allein vor den uebrigen Stage-1-Werkzeugen, mit Pause
vor jeder weiteren Sonde und konfigurierbarer Reihung; danach misst eine zweite
Sperrprobe (provider_block_probe_p2), ob der Host erreichbar blieb.
"""

from unittest.mock import MagicMock, patch

import pytest

from scanner import net_throttle
from scanner.packages import get_config

JW_PORTS = [21, 110, 143, 443, 465, 587, 993, 995]


# ------------------------------------------------------------ net_throttle

def test_pause_vorgabe_und_ungueltige_werte(monkeypatch):
    monkeypatch.delenv("VECTISCAN_THROTTLE_PROBE_PAUSE_S", raising=False)
    assert net_throttle.throttle_probe_pause_s() == 5.0
    monkeypatch.setenv("VECTISCAN_THROTTLE_PROBE_PAUSE_S", "12.5")
    assert net_throttle.throttle_probe_pause_s() == 12.5
    monkeypatch.setenv("VECTISCAN_THROTTLE_PROBE_PAUSE_S", "0")
    assert net_throttle.throttle_probe_pause_s() == 0.0
    for kaputt in ("abc", "-3"):
        monkeypatch.setenv("VECTISCAN_THROTTLE_PROBE_PAUSE_S", kaputt)
        assert net_throttle.throttle_probe_pause_s() == 5.0


@pytest.mark.parametrize("wert,erwartet", [
    ("", [21, 110, 587, 993]),
    ("asc", [21, 110, 587, 993]),
    ("desc", [993, 587, 110, 21]),
    ("993,587", [993, 587, 21, 110]),
    ("587, 25, 587", [587, 21, 110, 993]),
    ("587,x", [21, 110, 587, 993]),
])
def test_reihung_der_ports(monkeypatch, wert, erwartet):
    monkeypatch.setenv("VECTISCAN_THROTTLE_PROBE_ORDER", wert)
    assert net_throttle.throttle_probe_order([993, 21, 587, 110, 587]) == erwartet


def test_pause_nur_auf_gedrosselten_hosts(monkeypatch):
    monkeypatch.setenv("VECTISCAN_THROTTLE_PROBE_PAUSE_S", "7")
    with patch.object(net_throttle.time, "sleep") as schlaf:
        net_throttle.pause_between_probes(False)
        schlaf.assert_not_called()
        net_throttle.pause_between_probes(True)
        schlaf.assert_called_once_with(7.0)
    monkeypatch.setenv("VECTISCAN_THROTTLE_PROBE_PAUSE_S", "0")
    with patch.object(net_throttle.time, "sleep") as schlaf:
        net_throttle.pause_between_probes(True)
        schlaf.assert_not_called()


def test_sperrprobe_nennt_die_dauer_auch_bei_sperre():
    """S6d (A8): waited_s ist die Dauer der Messung, auch wenn der Host gesperrt
    bleibt (time_to_reachable_s ist dann None). Bestandsfelder bleiben."""
    uhr = iter([100.0, 100.0, 160.0, 175.0, 175.0])
    with patch("socket.create_connection", side_effect=OSError("refused")), \
            patch.object(net_throttle.time, "sleep"), \
            patch.object(net_throttle.time, "monotonic", side_effect=lambda: next(uhr)):
        r = net_throttle.probe_reachable_after_portscan("188.40.3.130", known_ports=[443],
                                                        attempts=2)
    assert r["blocked"] is True and r["reachable"] is False
    assert r["time_to_reachable_s"] is None
    assert r["waited_s"] == 75.0
    for feld in ("ip", "checked_ports", "attempts", "checked_at"):
        assert feld in r

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("socket.create_connection", return_value=_Conn()):
        ok = net_throttle.probe_reachable_after_portscan("188.40.3.130", known_ports=[443])
    assert ok["blocked"] is False
    assert isinstance(ok["waited_s"], float)


# ------------------------------------------------------------ run_phase2

def _mock_zap():
    zap = MagicMock()
    zap.health_check.return_value = True
    zap.get_version.return_value = "2.17.0"
    zap.create_context.return_value = 1
    zap.start_spider.return_value = 1
    zap.spider_status.return_value = 100
    zap.spider_results.return_value = ["https://junkerwerk.de/"]
    zap.ajax_spider_status.return_value = "stopped"
    zap.start_active_scan.return_value = 1
    zap.active_scan_status.return_value = 100
    zap.wait_for_passive_scan.return_value = True
    zap.get_alerts.return_value = []
    return zap


def _run(tmp_path, throttled: bool):
    """run_phase2 fuer den JW-Hetzner-Host mit gemockten Sonden; liefert die
    Ereignisfolge und die geschriebenen Zeilen."""
    from scanner.phase2 import run_phase2

    events: list[tuple] = []
    rows: list[tuple] = []
    tech_profile = {
        "fqdn": "junkerwerk.de", "cms": None, "technologies": [],
        "has_web": True, "has_ssl": True, "open_ports": list(JW_PORTS),
        "throttled": throttled,
    }
    config = dict(get_config("perimeter"))
    config["package"] = "perimeter"

    def _once(fqdn, ip, out, order_id, **kw):
        events.append(("testssl", kw.get("tool_name")))
        return []

    def _rec(order_id, ip, phase, tool, status, **kw):
        rows.append((tool, status, kw.get("reason")))

    with patch("scanner.tools.zap_client.ZapClient", return_value=_mock_zap()), \
            patch("scanner.phase2.publish_tool_output"), \
            patch("scanner.phase2.publish_event"), \
            patch("scanner.phase2._save_result"), \
            patch("scanner.phase2.record_tool_run", side_effect=_rec), \
            patch("scanner.phase2.run_header_check",
                  side_effect=lambda vh, *a, **k: events.append(("header_check", vh))
                  or {"score": "5/7"}), \
            patch("scanner.phase2.run_httpx", return_value={"status_code": 200}), \
            patch("scanner.phase2.run_testssl",
                  side_effect=lambda *a, **k: events.append(("testssl", "testssl")) or []), \
            patch("scanner.phase2._run_testssl_once", side_effect=_once), \
            patch("scanner.phase2.run_smtp_ehlo",
                  side_effect=lambda fqdn, ip, port, *a, **k: events.append(("smtp_ehlo", port))), \
            patch("scanner.phase2.pause_between_probes",
                  side_effect=lambda t: events.append(("pause", t)) if t else None), \
            patch("scanner.phase2.probe_reachable_after_portscan",
                  return_value={"ip": "188.40.3.130", "blocked": False, "reachable": True,
                                "time_to_reachable_s": 0.1, "checked_ports": [443],
                                "attempts": 3, "checked_at": "2026-09-28T16:40:00Z"}) as probe:
        run_phase2("188.40.3.130", ["junkerwerk.de", "www.junkerwerk.de"], tech_profile,
                   str(tmp_path / "scan"), "f9a2a2f6", MagicMock(), config,
                   vhost_fqdns=["junkerwerk.de", "www.junkerwerk.de"])
    return events, rows, probe


def test_gedrosselt_nacheinander_mit_pause(tmp_path, monkeypatch):
    monkeypatch.setenv("VECTISCAN_THROTTLE_PROBE_ORDER", "587,993")
    events, rows, probe = _run(tmp_path, throttled=True)

    testssl = [e[1] for e in events if e[0] == "testssl"]
    assert testssl == ["testssl", "testssl_587", "testssl_993", "testssl_21",
                       "testssl_110", "testssl_143", "testssl_465", "testssl_995",
                       "testssl_sni_www.junkerwerk.de"]
    # Vor jeder weiteren Sonde (7 Ports, 1 SNI) eine Pause, direkt davor.
    for i, e in enumerate(events):
        if e[0] == "testssl" and e[1] != "testssl":
            assert events[i - 1] == ("pause", True), (i, events[i - 1], e)
    # Der testssl-Block laeuft allein vor den uebrigen Stage-1-Werkzeugen.
    letzter_testssl = max(i for i, e in enumerate(events) if e[0] == "testssl")
    erster_header = min(i for i, e in enumerate(events) if e[0] == "header_check")
    assert letzter_testssl < erster_header
    # smtp_ehlo mit Reihung und Pause.
    smtp = [e[1] for e in events if e[0] == "smtp_ehlo"]
    assert smtp == [587, 465]
    for i, e in enumerate(events):
        if e[0] == "smtp_ehlo":
            assert events[i - 1] == ("pause", True)
    # Zweite Sperrmessung nach den Sonden.
    probe.assert_called_once()
    assert ("provider_block_probe_p2", "ok", None) in rows


def test_zweite_sperrmessung_meldet_die_sperre(tmp_path):
    from scanner.phase2 import record_provider_block_probe_p2

    rows: list[tuple] = []
    with patch("scanner.phase2.probe_reachable_after_portscan",
               return_value={"ip": "188.40.3.130", "blocked": True, "reachable": False,
                             "time_to_reachable_s": None, "checked_ports": [443, 587],
                             "attempts": 3, "checked_at": "2026-09-28T16:40:00Z"}) as probe, \
            patch("scanner.phase2.record_tool_run",
                  side_effect=lambda o, ip, ph, tool, st, **kw: rows.append(
                      (tool, st, kw.get("reason"), ph, kw.get("raw_output")))):
        result = record_provider_block_probe_p2("188.40.3.130", {"open_ports": [443, 587]},
                                                "f9a2a2f6")
    assert result["blocked"] is True
    probe.assert_called_once_with("188.40.3.130", known_ports=[443, 587])
    tool, status, reason, phase, raw = rows[0]
    assert (tool, status, reason, phase) == (
        "provider_block_probe_p2", "failed", "netz_sperrt_pruefadresse_nach_portscan", 2)
    assert '"blocked": true' in raw


def test_nicht_gedrosselt_unveraendert(tmp_path, monkeypatch):
    monkeypatch.setenv("VECTISCAN_THROTTLE_PROBE_ORDER", "587,993")
    events, rows, probe = _run(tmp_path, throttled=False)
    assert not any(e[0] == "pause" for e in events)
    # Aufsteigend wie bisher, die Reihung gilt nur fuer gedrosselte Hosts.
    testssl = [e[1] for e in events if e[0] == "testssl" and e[1].startswith("testssl_")
               and not e[1].startswith("testssl_sni")]
    assert testssl == ["testssl_21", "testssl_110", "testssl_143", "testssl_465",
                       "testssl_587", "testssl_993", "testssl_995"]
    assert [e[1] for e in events if e[0] == "smtp_ehlo"] == [465, 587]
    probe.assert_not_called()
    assert not any(r[0] == "provider_block_probe_p2" for r in rows)


def test_phase1_pausiert_vor_der_nachprobe():
    """Die Nachprobe nmap_versionall folgt auf gedrosselten Hosts nicht direkt auf
    Portscan und Sperrprobe."""
    import inspect

    from scanner import phase1
    src = inspect.getsource(phase1)
    idx_pause = src.index("pause_between_probes(throttle)")
    idx_reprobe = src.index("run_nmap_version_reprobe(ip, reprobe_ports")
    assert idx_pause < idx_reprobe

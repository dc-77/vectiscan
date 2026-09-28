"""S6c/Q16 (spec/09, spec/11 T7): Werkzeuge an die Inventar-IP binden,
IPv6 ohne Route in Phase 2 ueberspringen.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner import phase2


def test_testssl_bindet_an_inventar_ip(tmp_path: Path) -> None:
    """testssl bekommt --ip <inventar_ip>, nicht --ip one (DNS-Rotation HE/CA/HL)."""
    captured = {}

    def fake_run_tool(cmd, **kwargs):
        captured["cmd"] = cmd
        return (0, 100)

    with patch.object(phase2, "run_tool", side_effect=fake_run_tool):
        phase2.run_testssl("www.huendgen-entsorgung.de", "18.197.248.23",
                           str(tmp_path), "order-1")
    cmd = captured["cmd"]
    assert "--ip" in cmd
    assert cmd[cmd.index("--ip") + 1] == "18.197.248.23"
    assert "one" not in cmd


def test_header_check_hauptaufruf_bindet_an_ip(tmp_path: Path) -> None:
    """HEAD/GET curl bekommen --resolve auf die Inventar-IP."""
    (tmp_path / "phase2").mkdir()
    cmds = []

    def fake_popen(cmd, **kwargs):
        cmds.append(cmd)
        proc = MagicMock()
        # HEAD leer -> GET-Fallback -> auch leer -> unreachable (kein 3. curl).
        proc.communicate.return_value = ("", "")
        proc.pid = 1
        return proc

    with patch.object(phase2.subprocess, "Popen", side_effect=fake_popen):
        phase2.run_header_check("www.castenow.de", "195.50.179.4",
                                str(tmp_path), "order-1")
    assert any("--resolve" in c and "www.castenow.de:443:195.50.179.4" in c for c in cmds)


def test_phase2_ueberspringt_ipv6_ohne_route(tmp_path: Path) -> None:
    """IPv6-Adresse ohne Route: Phase 2 failed mit no_ipv6_route, kein leeres ok."""
    recorded = []

    def fake_record(order_id, ip, tool, status, reason):
        recorded.append((tool, status, reason))

    with patch.object(phase2, "_record_phase2_status", side_effect=fake_record), \
         patch("scanner.phase1._ipv6_route_available", return_value=False):
        result = phase2.run_phase2(
            ip="2a01:4f8:d0a:668b::2",
            fqdns=["www.lumbeck-wolter.de"],
            tech_profile={"has_ssl": True, "has_web": True},
            scan_dir=str(tmp_path),
            order_id="order-1",
            progress_callback=lambda *a: None,
            config={"phase2_tools": ["testssl", "headers", "httpx", "zap_spider",
                                     "zap_active", "ffuf", "feroxbuster", "wpscan"]},
        )
    assert result.get("no_ipv6_route") is True
    tools = {t for t, _, _ in recorded}
    assert "testssl" in tools and "header_check" in tools
    assert all(status == "failed" and reason == "no_ipv6_route"
               for _, status, reason in recorded)

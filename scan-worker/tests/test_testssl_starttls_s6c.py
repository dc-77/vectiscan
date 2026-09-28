"""S6c/Q17 (spec/09, spec/10 R3): testssl je TLS-Port mit --starttls, nicht nur 443."""

from pathlib import Path
from unittest.mock import patch

from scanner import phase2


def _capture_cmd(**kwargs):
    captured = {}

    def fake_run_tool(cmd, **kw):
        captured["cmd"] = cmd
        captured["tool_name"] = kw.get("tool_name")
        return (0, 100)

    with patch.object(phase2, "run_tool", side_effect=fake_run_tool):
        phase2._run_testssl_once(**kwargs)
    return captured


def test_starttls_port_587_hat_starttls_smtp(tmp_path: Path) -> None:
    cap = _capture_cmd(fqdn="mail.dortmund-beach.com", ip="1.2.3.4",
                       output_path=str(tmp_path / "testssl_587.json"),
                       order_id="o", severity="", tool_name="testssl_587",
                       port=587, starttls="smtp")
    cmd = cap["cmd"]
    assert "--starttls" in cmd
    assert cmd[cmd.index("--starttls") + 1] == "smtp"
    assert cmd[-1] == "mail.dortmund-beach.com:587"
    assert cap["tool_name"] == "testssl_587"


def test_direkter_tls_port_993_ohne_starttls(tmp_path: Path) -> None:
    cap = _capture_cmd(fqdn="mail.dortmund-beach.com", ip="1.2.3.4",
                       output_path=str(tmp_path / "testssl_993.json"),
                       order_id="o", severity="", tool_name="testssl_993",
                       port=993, starttls="")
    cmd = cap["cmd"]
    assert "--starttls" not in cmd
    assert cmd[-1] == "mail.dortmund-beach.com:993"


def test_443_bleibt_unveraendert(tmp_path: Path) -> None:
    """Der Bestandslauf (443) benutzt weiter https://host und heisst testssl."""
    cap = _capture_cmd(fqdn="www.dortmund-beach.com", ip="1.2.3.4",
                       output_path=str(tmp_path / "testssl.json"),
                       order_id="o", severity="")
    cmd = cap["cmd"]
    assert "--starttls" not in cmd
    assert cmd[-1] == "https://www.dortmund-beach.com"
    assert cap["tool_name"] == "testssl"
    # An die Inventar-IP gebunden (Q16).
    assert cmd[cmd.index("--ip") + 1] == "1.2.3.4"


def test_port_maps_decken_dortmund_beach_ab() -> None:
    """DB hat 8 TLS-Dienste (21,110,143,465,587,993,995,10000) neben 443."""
    for p in (21, 110, 143, 587):
        assert p in phase2.TLS_PORTS_STARTTLS
    for p in (465, 993, 995, 10000, 8443, 444):
        assert p in phase2.TLS_PORTS_DIRECT
    assert phase2.TLS_PORTS_STARTTLS[25] == "smtp"

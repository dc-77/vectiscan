"""S6c/Q17 (spec/09): Pfadsuche auf die Endadresse, Exchange-Liste, nmap keine Antwort."""

from pathlib import Path
from unittest.mock import patch

from scanner import phase1, phase2


# ---- E5: content_fqdn und Exchange-Liste ---------------------------------

def test_content_fqdn_folgt_endadresse_gleicher_domain() -> None:
    tp = {"final_url": "https://www.huendgen-entsorgung.de/de/"}
    assert phase2._content_fqdn(tp, "huendgen-entsorgung.de") == "www.huendgen-entsorgung.de"


def test_content_fqdn_bleibt_bei_fremddomain() -> None:
    """E3: Weiterleitung auf eine Fremddomain wird nicht aktiv geprueft."""
    tp = {"final_url": "https://cdn.fremd-cms.com/x"}
    assert phase2._content_fqdn(tp, "www.kunde.de") == "www.kunde.de"


def test_is_exchange_host_erkennt_owa() -> None:
    assert phase2._is_exchange_host({"cms": "Microsoft Exchange"}) is True
    assert phase2._is_exchange_host({"server": "Microsoft-IIS/10.0", "technologies": ["Outlook Web App"]}) is True
    assert phase2._is_exchange_host({"cms": "WordPress"}) is False


def test_ffuf_exchange_mode_nutzt_exchange_pfade(tmp_path: Path) -> None:
    """ffuf mode=exchange schreibt die Exchange-Wordlist und heisst ffuf_sensitive."""
    (tmp_path / "phase2").mkdir()
    captured = {}

    def fake_run_tool(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["tool_name"] = kwargs.get("tool_name")
        return (0, 100)

    with patch.object(phase2, "run_tool", side_effect=fake_run_tool):
        phase2.run_ffuf("exchange.huendgen-entsorgung.de", "80.90.145.166",
                        str(tmp_path), "order-1",
                        adaptive_config={"ffuf_mode": "exchange"})
    wl = tmp_path / "phase2" / "exchange_wordlist.txt"
    assert wl.exists()
    content = wl.read_text()
    assert "ecp" in content and "EWS" in content and "Microsoft-Server-ActiveSync" in content
    assert captured["tool_name"] == "ffuf_sensitive"
    assert "-w" in captured["cmd"]


# ---- E6: nmap keine Antwort ---------------------------------------------

_XML_NO_RESPONSE = (
    '<?xml version="1.0"?><nmaprun>'
    '<runstats><finished/><hosts up="0" down="0" total="1"/></runstats></nmaprun>'
)
_XML_OPEN_PORT = (
    '<?xml version="1.0"?><nmaprun>'
    '<host><status state="up"/><address addr="195.225.241.75"/>'
    '<ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host>'
    '<runstats><finished/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
)


def test_nmap_keine_antwort_ist_failed(tmp_path: Path) -> None:
    """HL 195.225.241.75: hosts up=0, kein Hostblock -> failed/nmap_no_response."""
    xml = tmp_path / "nmap.xml"
    xml.write_text(_XML_NO_RESPONSE)
    check = phase1._nmap_status_check("195.225.241.75", str(xml))
    assert check(0, "") == ("failed", "nmap_no_response")


def test_nmap_offener_port_ist_ok(tmp_path: Path) -> None:
    xml = tmp_path / "nmap.xml"
    xml.write_text(_XML_OPEN_PORT)
    check = phase1._nmap_status_check("195.225.241.75", str(xml))
    assert check(0, "") is None

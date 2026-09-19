"""Issue #8: nmap lief ohne `-6`, IPv6-Ziele wurden still uebersprungen.

Befund aus Session S1 (Golden-Tar 0bf16342, Host 2a01:4f8:d0a:3124::2): nmap
schreibt `<target status="skipped" reason="invalid"/>` und `<hosts total="0"/>`,
endet aber mit Exit 0. Die Zeile in scan_results stand dadurch auf `ok`, obwohl
der Host in keinem Lauf geprueft wurde.

Die Tests decken beide Haelften ab: den fehlenden Schalter und den falschen
Status.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scanner.common import nmap_utils


IPV6 = "2a01:4f8:d0a:3124::2"
IPV4 = "217.243.248.28"

# Hostverzeichnisse heissen nach der IP; der Doppelpunkt ist unter Windows kein
# zulaessiges Pfadzeichen. Vollstaendig laeuft die Suite auf Linux, also im
# CI-Job test-scan-worker (gleiche Einschraenkung wie bei den Golden-Tars,
# report-worker/tests/test_golden_fixtures.py).
ipv6_on_disk = pytest.mark.skipif(
    os.name == "nt",
    reason="IPv6-Hostverzeichnis mit Doppelpunkt, unter Windows kein zulaessiger Pfadname",
)

# Genau die Form, die nmap ohne -6 fuer eine IPv6-Adresse schreibt.
XML_SKIPPED = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
<target specification="2a01:4f8:d0a:3124::2" status="skipped" reason="invalid"/>
<runstats><finished elapsed="0.01"/><hosts up="0" down="0" total="0"/></runstats>
</nmaprun>
"""

XML_SCANNED = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><address addr="2a01:4f8:d0a:3124::2" addrtype="ipv6"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="nginx" version="1.24.0"/></port></ports></host>
<runstats><finished elapsed="9.1"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""


def _capture_nmap_cmd(xml_body: str):
    """Patcht run_tool in phase1, faengt die Kommandozeile, legt XML ab."""
    captured: dict = {}

    def fake_run_tool(**kwargs):
        captured["cmd"] = list(kwargs["cmd"])
        captured["status_check"] = kwargs.get("status_check")
        Path(kwargs["output_path"]).write_text(xml_body, encoding="utf-8")
        return 0, 1234

    return captured, fake_run_tool


# --------------------------------------------------------------- Schalter -6

@ipv6_on_disk
def test_ipv6_target_bekommt_minus_6(tmp_path):
    from scanner import phase1

    captured, fake = _capture_nmap_cmd(XML_SCANNED)
    with patch("scanner.phase1.run_tool", side_effect=fake):
        phase1.run_nmap(IPV6, str(tmp_path), "order-1")
    assert "-6" in captured["cmd"]
    assert captured["cmd"][-1] == IPV6


def test_ipv4_target_ohne_minus_6(tmp_path):
    """nmap verweigert -6 zusammen mit einer IPv4-Adresse."""
    from scanner import phase1

    captured, fake = _capture_nmap_cmd(XML_SCANNED)
    with patch("scanner.phase1.run_tool", side_effect=fake):
        phase1.run_nmap(IPV4, str(tmp_path), "order-1")
    assert "-6" not in captured["cmd"]


# ------------------------------------------------------- Status statt "ok"

@ipv6_on_disk
def test_status_check_meldet_failed_bei_null_hosts(tmp_path):
    """Der Defekt: Exit 0, aber `hosts total=0` — das ist kein Erfolg."""
    from scanner import phase1

    captured, fake = _capture_nmap_cmd(XML_SKIPPED)
    with patch("scanner.phase1.run_tool", side_effect=fake):
        result = phase1.run_nmap(IPV6, str(tmp_path), "order-1")

    check = captured["status_check"]
    assert check is not None, "run_nmap uebergibt keinen status_check"
    assert check(0, "") == ("failed", "target_invalid_ipv6")
    assert result == {"open_ports": [], "services": []}


def test_status_check_meldet_target_skipped_bei_ipv4(tmp_path):
    from scanner import phase1

    captured, fake = _capture_nmap_cmd(XML_SKIPPED)
    with patch("scanner.phase1.run_tool", side_effect=fake):
        phase1.run_nmap(IPV4, str(tmp_path), "order-1")
    assert captured["status_check"](0, "") == ("failed", "target_skipped")


@ipv6_on_disk
def test_status_check_schweigt_bei_gescanntem_host(tmp_path):
    from scanner import phase1

    captured, fake = _capture_nmap_cmd(XML_SCANNED)
    with patch("scanner.phase1.run_tool", side_effect=fake):
        result = phase1.run_nmap(IPV6, str(tmp_path), "order-1")
    assert captured["status_check"](0, "") is None
    assert result["open_ports"] == [443]


@ipv6_on_disk
def test_status_check_greift_nicht_bei_exit_ungleich_null(tmp_path):
    """Bei Exit != 0 gilt der Regelpfad von classify_exit."""
    from scanner import phase1

    captured, fake = _capture_nmap_cmd(XML_SKIPPED)
    with patch("scanner.phase1.run_tool", side_effect=fake):
        phase1.run_nmap(IPV6, str(tmp_path), "order-1")
    assert captured["status_check"](2, "") is None


# --------------------------------------------------- run_tool-Verdrahtung

def test_run_tool_uebernimmt_status_check():
    """Genau eine Zeile je Lauf: der Haken ersetzt den Status, er ergaenzt nicht."""
    from scanner import tools

    proc = MagicMock()
    proc.communicate.return_value = ("", "")
    proc.returncode = 0

    with patch("scanner.tools.subprocess.Popen", return_value=proc), \
            patch("scanner.tools._host_block_reason", return_value=None), \
            patch("scanner.tools.record_tool_run") as rec:
        tools.run_tool(
            cmd=["nmap", "-6", IPV6], timeout=10, order_id="order-1",
            host_ip=IPV6, phase=1, tool_name="nmap",
            status_check=lambda code, raw: ("failed", "target_invalid_ipv6"),
        )

    assert rec.call_count == 1
    args, kwargs = rec.call_args
    assert args[4] == "failed"
    assert kwargs["reason"] == "target_invalid_ipv6"


def test_run_tool_ohne_status_check_unveraendert():
    from scanner import tools

    proc = MagicMock()
    proc.communicate.return_value = ("Nmap done", "")
    proc.returncode = 0

    with patch("scanner.tools.subprocess.Popen", return_value=proc), \
            patch("scanner.tools._host_block_reason", return_value=None), \
            patch("scanner.tools.record_tool_run") as rec:
        tools.run_tool(cmd=["nmap", IPV4], timeout=10, order_id="order-1",
                       host_ip=IPV4, phase=1, tool_name="nmap")

    assert rec.call_count == 1
    assert rec.call_args[0][4] == "ok"
    assert rec.call_args[1]["reason"] is None


def test_run_tool_faengt_fehler_im_status_check():
    """Ein kaputter Haken darf keinen Scan kippen."""
    from scanner import tools

    proc = MagicMock()
    proc.communicate.return_value = ("Nmap done", "")
    proc.returncode = 0

    def boom(code, raw):
        raise RuntimeError("kaputt")

    with patch("scanner.tools.subprocess.Popen", return_value=proc), \
            patch("scanner.tools._host_block_reason", return_value=None), \
            patch("scanner.tools.record_tool_run") as rec:
        tools.run_tool(cmd=["nmap", IPV4], timeout=10, order_id="order-1",
                       host_ip=IPV4, phase=1, tool_name="nmap",
                       status_check=boom)

    assert rec.call_args[0][4] == "ok"


# ------------------------------------------------------ Precheck-Sweep

def _capture_subprocess():
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        result = MagicMock()
        result.stdout = ""
        result.returncode = 0
        return result

    return calls, fake_run


def test_precheck_ipv6_bekommt_minus_6():
    calls, fake = _capture_subprocess()
    with patch("scanner.common.nmap_utils.subprocess.run", side_effect=fake):
        nmap_utils.run_top_ports([IPV6])
    assert len(calls) == 1
    assert "-6" in calls[0]


def test_precheck_gemischte_liste_ergibt_zwei_laeufe():
    """nmap nimmt -6 nicht zusammen mit einer IPv4-Adresse."""
    calls, fake = _capture_subprocess()
    with patch("scanner.common.nmap_utils.subprocess.run", side_effect=fake):
        nmap_utils.run_top_ports([IPV4, IPV6])
    assert len(calls) == 2
    v4_call = [c for c in calls if IPV4 in c][0]
    v6_call = [c for c in calls if IPV6 in c][0]
    assert "-6" not in v4_call
    assert "-6" in v6_call


def test_precheck_reine_ipv4_liste_unveraendert():
    calls, fake = _capture_subprocess()
    with patch("scanner.common.nmap_utils.subprocess.run", side_effect=fake):
        nmap_utils.run_top_ports([IPV4, "1.2.3.4"])
    assert len(calls) == 1
    assert "-6" not in calls[0]


def test_parse_open_ports_liest_ipv6_host():
    """Ohne diesen Zweig faellt das Ergebnis eines -6-Laufs wieder heraus."""
    out = nmap_utils.parse_open_ports(XML_SCANNED)
    assert out == {IPV6: [443]}

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

# S2c: nmap bricht ab, bevor es die Bilanz schreibt. Kein `runstats`, also
# auch kein `hosts total` — und trotzdem Exit 0.
XML_OHNE_RUNSTATS = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
<target specification="2a01:4f8:d0a:3124::2" status="skipped" reason="invalid"/>
</nmaprun>
"""

# Abgeschnittene Datei, wie sie ein harter Abbruch hinterlaesst.
XML_KAPUTT = """<?xml version="1.0"?>
<nmaprun scanner="nmap"><runstats><finished"""

# S2c, Junkerwerk-Rescan 860d0d5a: nmap laeuft mit -6, zaehlt den Host wegen
# -Pn als erreichbar und endet mit exit="success", schreibt aber keinen
# Hostblock. Am XML ist das nicht von "Host lebt, kein Port offen" zu
# unterscheiden (mit --open laesst nmap den Block dann ebenfalls weg, siehe
# 217.243.248.27 im Golden-Tar 0bf16342). Unterschieden wird ueber die Route.
XML_UP_OHNE_HOSTBLOCK = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
<scaninfo type="connect" protocol="tcp" numservices="1000"/>
<runstats><finished elapsed="0.32" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
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


# -------------------------------------------- Exit 0 ohne Bilanz (S2c)

@pytest.mark.parametrize(
    "xml_body, label",
    [(XML_OHNE_RUNSTATS, "ohne runstats"), (XML_KAPUTT, "abgeschnittenes XML")],
    ids=["ohne_runstats", "kaputtes_xml"],
)
def test_status_check_meldet_failed_ohne_bilanz(tmp_path, xml_body, label):
    """Exit 0, aber nmap hat keine Bilanz hinterlassen: kein Erfolg.

    Bis S2c lieferte `_nmap_hosts_total` hier `None`, und der Haken wertete
    das als Erfolg. Der leere IPv6-Lauf im Junkerwerk-Rescan 860d0d5a stand
    dadurch auf `ok`, also stiller als vor dem Fix zu Issue #8.
    """
    from scanner import phase1

    captured, fake = _capture_nmap_cmd(xml_body)
    with patch("scanner.phase1.run_tool", side_effect=fake):
        result = phase1.run_nmap(IPV4, str(tmp_path), "order-1")

    assert captured["status_check"](0, "") == ("failed", "nmap_no_runstats"), label
    assert result == {"open_ports": [], "services": []}


def test_status_check_meldet_failed_ohne_xml_datei(tmp_path):
    """Gar keine Datei ist derselbe Fall wie eine unlesbare."""
    from scanner import phase1

    check = phase1._nmap_status_check(IPV4, str(tmp_path / "fehlt.xml"))
    assert check(0, "") == ("failed", "nmap_no_runstats")


# ------------------------------------------------- IPv6 ohne Route (S2c)

def _xml_at(tmp_path, body: str) -> str:
    path = tmp_path / "nmap.xml"
    path.write_text(body, encoding="utf-8")
    return str(path)


def test_ipv6_ohne_route_meldet_no_ipv6_route(tmp_path):
    """Bilanz sagt erreichbar, es gibt keinen Hostblock, und es fehlt die Route."""
    from scanner import phase1

    check = phase1._nmap_status_check(IPV6, _xml_at(tmp_path, XML_UP_OHNE_HOSTBLOCK))
    with patch("scanner.phase1._ipv6_route_available", return_value=False):
        assert check(0, "") == ("failed", "no_ipv6_route")


def test_ipv6_mit_route_und_ohne_offenen_port_bleibt_ok(tmp_path):
    """Derselbe XML-Befund ist bei vorhandener Route der legitime Fall."""
    from scanner import phase1

    check = phase1._nmap_status_check(IPV6, _xml_at(tmp_path, XML_UP_OHNE_HOSTBLOCK))
    with patch("scanner.phase1._ipv6_route_available", return_value=True):
        assert check(0, "") is None


def test_ipv4_ohne_hostblock_bleibt_ok(tmp_path):
    """217.243.248.27 im Tar 0bf16342: 23 Sekunden Scan, kein offener Port.

    Die Routenpruefung gilt nur fuer IPv6-Ziele und darf hier nicht greifen.
    """
    from scanner import phase1

    check = phase1._nmap_status_check(IPV4, _xml_at(tmp_path, XML_UP_OHNE_HOSTBLOCK))
    with patch("scanner.phase1._ipv6_route_available", return_value=False) as route:
        assert check(0, "") is None
    route.assert_not_called()


def test_ipv6_mit_hostblock_wird_nicht_angefasst(tmp_path):
    """Sobald nmap einen Hostblock liefert, ist die Route offensichtlich da."""
    from scanner import phase1

    check = phase1._nmap_status_check(IPV6, _xml_at(tmp_path, XML_SCANNED))
    with patch("scanner.phase1._ipv6_route_available", return_value=False) as route:
        assert check(0, "") is None
    route.assert_not_called()


def test_route_pruefung_schickt_kein_paket():
    """connect auf einem UDP-Socket loest nur die Routenwahl aus."""
    from scanner import phase1

    sock = MagicMock()
    with patch("scanner.phase1.socket.socket", return_value=sock):
        assert phase1._ipv6_route_available("2a01:4f8:d0a:3124::2") is True
    sock.connect.assert_called_once_with(("2a01:4f8:d0a:3124::2", 80))
    sock.send.assert_not_called()
    sock.sendto.assert_not_called()
    sock.close.assert_called_once()


def test_route_pruefung_meldet_fehlende_route():
    from scanner import phase1

    sock = MagicMock()
    sock.connect.side_effect = OSError(101, "Network is unreachable")
    with patch("scanner.phase1.socket.socket", return_value=sock):
        assert phase1._ipv6_route_available("2a01:4f8:d0a:3124::2") is False
    sock.close.assert_called_once()


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

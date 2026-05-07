"""Tests for F-PRE-004 (Performance-Flags) und F-PRE-005 (57-Port-Liste).

Audit-Eintraege: docs/scan-flow/Scan-Optimierung.md Sektionen 3.1.1, 3.1.4.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

from scanner.common import nmap_utils
from scanner.precheck import nmap_light


def _capture_cmd():
    """Helper: patcht subprocess.run, faengt das `cmd`-Argument."""
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        result = MagicMock()
        result.stdout = ""
        result.returncode = 0
        return result

    return captured, fake_run


def test_run_top_ports_includes_performance_flags():
    """F-PRE-004: --max-retries 2, --host-timeout 30s, -n, --open muessen drin sein."""
    captured, fake_run = _capture_cmd()
    with patch("scanner.common.nmap_utils.subprocess.run", side_effect=fake_run):
        nmap_utils.run_top_ports(["1.2.3.4"])
    cmd = captured["cmd"]
    assert "--max-retries" in cmd
    idx = cmd.index("--max-retries")
    assert cmd[idx + 1] == "2"
    assert "--host-timeout" in cmd
    idx = cmd.index("--host-timeout")
    assert cmd[idx + 1] == "30s"
    assert "-n" in cmd
    assert "--open" in cmd


def test_run_top_ports_uses_57_port_list_by_default():
    """F-PRE-005: Default-Aufruf nutzt -p PRECHECK_PORTS (57 Ports)."""
    captured, fake_run = _capture_cmd()
    with patch("scanner.common.nmap_utils.subprocess.run", side_effect=fake_run):
        nmap_utils.run_top_ports(["1.2.3.4"])
    cmd = captured["cmd"]
    assert "-p" in cmd
    idx = cmd.index("-p")
    port_arg = cmd[idx + 1]
    # 57 Ports, comma-separated → 56 Kommas
    assert port_arg.count(",") == 56
    # Spot-Checks auf Port-Liste
    for port in ("22", "443", "2375", "6443", "5986", "8200", "1883", "27017"):
        assert port in port_arg.split(","), f"Port {port} fehlt in PRECHECK_PORTS"
    # --top-ports darf nicht gleichzeitig dabei sein
    assert "--top-ports" not in cmd


def test_run_top_ports_top_ports_kwarg_still_works():
    """Backwards-Compat: explizites top_ports=10 nutzt --top-ports."""
    captured, fake_run = _capture_cmd()
    with patch("scanner.common.nmap_utils.subprocess.run", side_effect=fake_run):
        nmap_utils.run_top_ports(["1.2.3.4"], top_ports=10)
    cmd = captured["cmd"]
    assert "--top-ports" in cmd
    idx = cmd.index("--top-ports")
    assert cmd[idx + 1] == "10"
    # Default-Port-Liste darf hier nicht zusaetzlich gesetzt sein
    assert "-p" not in cmd


def test_nmap_light_default_uses_57_port_list():
    """precheck/nmap_light.scan ohne top_ports nutzt 57-Port-Default."""
    captured, fake_run = _capture_cmd()
    with patch("scanner.common.nmap_utils.subprocess.run", side_effect=fake_run):
        nmap_light.scan(["1.2.3.4"])
    cmd = captured["cmd"]
    assert "-p" in cmd
    idx = cmd.index("-p")
    assert cmd[idx + 1] == nmap_utils.PRECHECK_PORTS


def test_precheck_ports_constant_has_57_entries():
    """F-PRE-005 Sanity: Konstante enthaelt exakt 57 Ports."""
    ports = nmap_utils.PRECHECK_PORTS.split(",")
    assert len(ports) == 57
    # Alle Eintraege sind reine Port-Numbers
    for p in ports:
        assert p.isdigit()

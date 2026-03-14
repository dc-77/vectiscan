"""Tests for Phase 0 — DNS Reconnaissance."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_merge_and_group_basic_structure(tmp_path: Path) -> None:
    """merge_and_group returns a well-formed host_inventory dict."""
    from scanner.phase0 import merge_and_group

    scan_dir = str(tmp_path)
    (tmp_path / "phase0").mkdir()

    all_subdomains = ["example.com", "www.example.com", "mail.example.com"]
    dnsx_results = [
        {"host": "example.com", "a": ["1.2.3.4"]},
        {"host": "www.example.com", "a": ["1.2.3.4"]},
        {"host": "mail.example.com", "a": ["5.6.7.8"]},
    ]
    dns_records = {"spf": "v=spf1 include:_spf.example.com ~all", "dmarc": None, "dkim": False, "mx": [], "ns": []}
    zone_transfer = {"success": False, "data": ""}

    with patch("scanner.phase0.socket.gethostbyaddr", side_effect=OSError):
        inventory = merge_and_group(
            domain="example.com",
            all_subdomains=all_subdomains,
            dnsx_results=dnsx_results,
            dns_records=dns_records,
            zone_transfer=zone_transfer,
            scan_dir=scan_dir,
        )

    assert inventory["domain"] == "example.com"
    assert isinstance(inventory["hosts"], list)
    assert isinstance(inventory["skipped_hosts"], list)
    assert isinstance(inventory["dns_findings"], dict)

    # Verify IP grouping: example.com and www.example.com share 1.2.3.4
    ips = {h["ip"] for h in inventory["hosts"]}
    assert "1.2.3.4" in ips
    assert "5.6.7.8" in ips

    host_1234 = next(h for h in inventory["hosts"] if h["ip"] == "1.2.3.4")
    assert "example.com" in host_1234["fqdns"]
    assert "www.example.com" in host_1234["fqdns"]


def test_merge_and_group_max_10_hosts(tmp_path: Path) -> None:
    """merge_and_group limits hosts to 10 and puts the rest in skipped_hosts."""
    from scanner.phase0 import merge_and_group

    scan_dir = str(tmp_path)
    (tmp_path / "phase0").mkdir()

    # Create 15 unique IPs (include base domain to avoid DNS fallback)
    all_subdomains = ["example.com"] + [f"host{i}.example.com" for i in range(14)]
    dnsx_results = [
        {"host": "example.com", "a": ["10.0.0.100"]},
    ] + [
        {"host": f"host{i}.example.com", "a": [f"10.0.0.{i}"]}
        for i in range(14)
    ]

    with patch("scanner.phase0.socket.gethostbyaddr", side_effect=OSError):
        inventory = merge_and_group(
            domain="example.com",
            all_subdomains=all_subdomains,
            dnsx_results=dnsx_results,
            dns_records={},
            zone_transfer={"success": False},
            scan_dir=scan_dir,
        )

    assert len(inventory["hosts"]) == 10
    assert len(inventory["skipped_hosts"]) == 5


def test_merge_and_group_skipped_hosts_empty_when_under_limit(tmp_path: Path) -> None:
    """skipped_hosts is empty when total hosts <= 10."""
    from scanner.phase0 import merge_and_group

    scan_dir = str(tmp_path)
    (tmp_path / "phase0").mkdir()

    dnsx_results = [{"host": "a.example.com", "a": ["1.1.1.1"]}]

    with patch("scanner.phase0.socket.gethostbyaddr", side_effect=OSError):
        inventory = merge_and_group(
            domain="example.com",
            all_subdomains=["a.example.com"],
            dnsx_results=dnsx_results,
            dns_records={},
            zone_transfer={"success": False},
            scan_dir=scan_dir,
        )

    assert inventory["skipped_hosts"] == []


def test_run_crtsh_parses_subdomains(tmp_path: Path) -> None:
    """run_crtsh extracts subdomains from crt.sh JSON output."""
    from scanner.phase0 import run_crtsh

    scan_dir = str(tmp_path)
    phase0_dir = tmp_path / "phase0"
    phase0_dir.mkdir()

    crtsh_json = json.dumps([
        {"name_value": "example.com"},
        {"name_value": "www.example.com\nmail.example.com"},
        {"name_value": "*.example.com"},  # wildcard — should strip *. prefix
    ])

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = crtsh_json

    with patch("scanner.phase0.run_tool", return_value=(0, 100)), \
         patch("scanner.phase0.subprocess.run", return_value=mock_proc):
        subs = run_crtsh("example.com", scan_dir, "test-scan-id")

    assert "example.com" in subs
    assert "www.example.com" in subs
    assert "mail.example.com" in subs
    # Wildcards should not appear (*.example.com gets stripped to example.com)
    assert not any(s.startswith("*") for s in subs)


def test_run_crtsh_returns_empty_on_failure(tmp_path: Path) -> None:
    """run_crtsh returns empty list when the tool fails."""
    from scanner.phase0 import run_crtsh

    scan_dir = str(tmp_path)
    (tmp_path / "phase0").mkdir()

    with patch("scanner.phase0.run_tool", return_value=(1, 50)):
        subs = run_crtsh("example.com", scan_dir, "test-scan-id")

    assert subs == []


def test_phase0_tools_called_with_correct_timeouts(tmp_path: Path) -> None:
    """Phase 0 tool invocations use the expected timeout values."""
    from scanner.phase0 import run_crtsh, run_subfinder, run_amass, run_gobuster_dns

    scan_dir = str(tmp_path)
    (tmp_path / "phase0").mkdir()

    mock_run = MagicMock(return_value=(1, 50))

    with patch("scanner.phase0.run_tool", mock_run):
        run_crtsh("example.com", scan_dir, "scan-1")
        # crtsh timeout = 30
        assert mock_run.call_args_list[-1][1]["timeout"] == 30 or mock_run.call_args_list[-1][0][1] == 30

    mock_run.reset_mock()
    with patch("scanner.phase0.run_tool", mock_run):
        run_subfinder("example.com", scan_dir, "scan-1")
        call_kwargs = mock_run.call_args
        assert call_kwargs[1].get("timeout", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else None) == 120

    mock_run.reset_mock()
    with patch("scanner.phase0.run_tool", mock_run):
        run_amass("example.com", scan_dir, "scan-1")
        call_kwargs = mock_run.call_args
        assert call_kwargs[1].get("timeout", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else None) == 300

    mock_run.reset_mock()
    with patch("scanner.phase0.run_tool", mock_run):
        run_gobuster_dns("example.com", scan_dir, "scan-1")
        call_kwargs = mock_run.call_args
        assert call_kwargs[1].get("timeout", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else None) == 180


def test_merge_and_group_dangling_cnames(tmp_path: Path) -> None:
    """merge_and_group detects dangling CNAMEs (CNAME without A record)."""
    from scanner.phase0 import merge_and_group

    scan_dir = str(tmp_path)
    (tmp_path / "phase0").mkdir()

    dnsx_results = [
        {"host": "ok.example.com", "a": ["1.2.3.4"]},
        {"host": "dangling.example.com", "cname": ["old.cdn.example.com"], "a": []},
    ]

    with patch("scanner.phase0.socket.gethostbyaddr", side_effect=OSError):
        inventory = merge_and_group(
            domain="example.com",
            all_subdomains=["ok.example.com", "dangling.example.com"],
            dnsx_results=dnsx_results,
            dns_records={},
            zone_transfer={"success": False},
            scan_dir=scan_dir,
        )

    assert "dangling.example.com" in inventory["dns_findings"]["dangling_cnames"]


def test_merge_and_group_saves_inventory_file(tmp_path: Path) -> None:
    """merge_and_group writes host_inventory.json to scan_dir/phase0/."""
    from scanner.phase0 import merge_and_group

    scan_dir = str(tmp_path)
    (tmp_path / "phase0").mkdir()

    with patch("scanner.phase0.socket.gethostbyaddr", side_effect=OSError):
        merge_and_group(
            domain="example.com",
            all_subdomains=["example.com"],
            dnsx_results=[{"host": "example.com", "a": ["1.1.1.1"]}],
            dns_records={},
            zone_transfer={"success": False},
            scan_dir=scan_dir,
        )

    inventory_path = tmp_path / "phase0" / "host_inventory.json"
    assert inventory_path.exists()
    data = json.loads(inventory_path.read_text())
    assert data["domain"] == "example.com"

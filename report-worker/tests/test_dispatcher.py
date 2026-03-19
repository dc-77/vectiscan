"""Tests for map_to_report_data() dispatcher."""
import json
from pathlib import Path
from unittest.mock import patch
import pytest
from reporter.report_mapper import map_to_report_data

FIXTURES = Path(__file__).parent / "fixtures"

@pytest.fixture
def pro_output():
    return json.loads((FIXTURES / "claude_output_professional.json").read_text())

@pytest.fixture
def scan_meta():
    return json.loads((FIXTURES / "scan_meta.json").read_text())

@pytest.fixture
def host_inventory():
    return json.loads((FIXTURES / "host_inventory.json").read_text())

def test_default_is_professional(pro_output, scan_meta, host_inventory):
    """Default package should use professional mapper."""
    result = map_to_report_data(pro_output, scan_meta, host_inventory)
    cover_meta = result["cover"]["cover_meta"]
    paket_rows = [row for row in cover_meta if row[0] == "Paket:"]
    assert paket_rows[0][1] == "PerimeterScan"

def test_basic_dispatch(scan_meta, host_inventory):
    """package='basic' should use basic mapper."""
    basic_output = json.loads((FIXTURES / "claude_output_basic.json").read_text())
    result = map_to_report_data(basic_output, scan_meta, host_inventory, package="basic")
    assert result["appendices"] == []

def test_professional_dispatch(pro_output, scan_meta, host_inventory):
    """package='professional' should use professional mapper."""
    result = map_to_report_data(pro_output, scan_meta, host_inventory, package="professional")
    assert len(result["appendices"]) >= 1

def test_nis2_dispatch(scan_meta, host_inventory):
    """package='nis2' should use nis2 mapper."""
    nis2_output = json.loads((FIXTURES / "claude_output_nis2.json").read_text())
    result = map_to_report_data(nis2_output, scan_meta, host_inventory, package="nis2")
    assert "nis2" in result

def test_unknown_package_defaults_to_professional(pro_output, scan_meta, host_inventory):
    """Unknown package should default to professional mapper."""
    result = map_to_report_data(pro_output, scan_meta, host_inventory, package="enterprise")
    cover_meta = result["cover"]["cover_meta"]
    paket_rows = [row for row in cover_meta if row[0] == "Paket:"]
    assert paket_rows[0][1] == "PerimeterScan"

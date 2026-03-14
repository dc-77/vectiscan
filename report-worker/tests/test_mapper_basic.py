"""Tests for map_basic_report()."""
import json
from pathlib import Path
import pytest
from reporter.report_mapper import map_basic_report

FIXTURES = Path(__file__).parent / "fixtures"

@pytest.fixture
def basic_output():
    return json.loads((FIXTURES / "claude_output_basic.json").read_text())

@pytest.fixture
def scan_meta():
    return json.loads((FIXTURES / "scan_meta.json").read_text())

@pytest.fixture
def host_inventory():
    return json.loads((FIXTURES / "host_inventory.json").read_text())

def test_basic_has_cvss(basic_output, scan_meta, host_inventory):
    """Basic findings should have CVSS scores from Claude."""
    result = map_basic_report(basic_output, scan_meta, host_inventory)
    for f in result["findings"]:
        if f["severity"] != "INFO":  # skip positive findings
            assert f["cvss_score"] != "\u2014", f"Finding {f['id']} should have a CVSS score"
            assert f["cvss_vector"].startswith("CVSS:3.1/")

def test_basic_no_appendices(basic_output, scan_meta, host_inventory):
    """Basic report should have empty appendices."""
    result = map_basic_report(basic_output, scan_meta, host_inventory)
    assert result["appendices"] == []

def test_basic_max_3_recommendations(basic_output, scan_meta, host_inventory):
    """Basic report should have max 3 recommendations."""
    result = map_basic_report(basic_output, scan_meta, host_inventory)
    rec_section = result["recommendations"]
    rows = rec_section["table"]["rows"]
    assert len(rows) <= 3

def test_basic_simple_toc(basic_output, scan_meta, host_inventory):
    """Basic TOC should have no sub-items (is_sub=True)."""
    result = map_basic_report(basic_output, scan_meta, host_inventory)
    toc = result["toc"]
    assert all(not entry[2] for entry in toc)

def test_basic_cover_meta_has_paket(basic_output, scan_meta, host_inventory):
    """Basic cover should mention 'Basic' as package."""
    result = map_basic_report(basic_output, scan_meta, host_inventory)
    cover_meta = result["cover"]["cover_meta"]
    paket_rows = [row for row in cover_meta if row[0] == "Paket:"]
    assert len(paket_rows) == 1
    assert paket_rows[0][1] == "Basic"

def test_basic_evidence_optional(basic_output, scan_meta, host_inventory):
    """Basic findings may or may not have evidence."""
    result = map_basic_report(basic_output, scan_meta, host_inventory)
    for f in result["findings"]:
        # evidence field should exist (may be "—" or actual content)
        assert "evidence" in f

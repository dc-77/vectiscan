"""Tests for map_professional_report()."""
import json
from pathlib import Path
import pytest
from reporter.report_mapper import map_professional_report

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

def test_professional_has_cvss(pro_output, scan_meta, host_inventory):
    """Professional findings should have CVSS scores."""
    result = map_professional_report(pro_output, scan_meta, host_inventory)
    finding = result["findings"][0]  # first non-positive finding
    assert finding["cvss_score"] != "N/A"
    assert finding["cvss_vector"] != "N/A"

def test_professional_has_appendices(pro_output, scan_meta, host_inventory):
    """Professional report should have appendices (CVSS reference, tool list)."""
    result = map_professional_report(pro_output, scan_meta, host_inventory)
    assert len(result["appendices"]) >= 1

def test_professional_has_evidence(pro_output, scan_meta, host_inventory):
    """Professional findings should include evidence."""
    result = map_professional_report(pro_output, scan_meta, host_inventory)
    finding = result["findings"][0]
    assert finding["evidence"] != "\u2014"
    assert "nmap" in finding["evidence"] or "curl" in finding["evidence"] or len(finding["evidence"]) > 5

def test_professional_toc_has_sub_items(pro_output, scan_meta, host_inventory):
    """Professional TOC should have sub-items for findings."""
    result = map_professional_report(pro_output, scan_meta, host_inventory)
    toc = result["toc"]
    sub_items = [entry for entry in toc if entry[2]]
    assert len(sub_items) > 0

def test_professional_cover_meta_has_paket(pro_output, scan_meta, host_inventory):
    """Professional cover should mention 'Professional' as package."""
    result = map_professional_report(pro_output, scan_meta, host_inventory)
    cover_meta = result["cover"]["cover_meta"]
    paket_rows = [row for row in cover_meta if row[0] == "Paket:"]
    assert len(paket_rows) == 1
    assert paket_rows[0][1] == "Professional"

"""Tests for map_nis2_report()."""
import json
from pathlib import Path
import pytest
from reporter.report_mapper import map_nis2_report

FIXTURES = Path(__file__).parent / "fixtures"

@pytest.fixture
def nis2_output():
    return json.loads((FIXTURES / "claude_output_nis2.json").read_text())

@pytest.fixture
def scan_meta():
    return json.loads((FIXTURES / "scan_meta.json").read_text())

@pytest.fixture
def host_inventory():
    return json.loads((FIXTURES / "host_inventory.json").read_text())

def test_nis2_has_compliance_summary(nis2_output, scan_meta, host_inventory):
    """NIS2 report should include compliance summary."""
    result = map_nis2_report(nis2_output, scan_meta, host_inventory)
    assert "nis2" in result
    assert "compliance_summary" in result["nis2"]

def test_nis2_has_audit_trail(nis2_output, scan_meta, host_inventory):
    """NIS2 report should include audit trail."""
    result = map_nis2_report(nis2_output, scan_meta, host_inventory)
    assert "audit_trail" in result["nis2"]
    assert result["nis2"]["audit_trail"]["orderId"] == scan_meta["orderId"]

def test_nis2_has_supply_chain(nis2_output, scan_meta, host_inventory):
    """NIS2 report should include supply chain summary."""
    result = map_nis2_report(nis2_output, scan_meta, host_inventory)
    assert "supply_chain" in result["nis2"]
    assert result["nis2"]["supply_chain"]["overall_rating"] == "MEDIUM"

def test_nis2_findings_have_nis2_ref(nis2_output, scan_meta, host_inventory):
    """NIS2 findings should include nis2_ref field."""
    result = map_nis2_report(nis2_output, scan_meta, host_inventory)
    # Check that at least some findings have nis2_ref
    findings_with_ref = [f for f in result["findings"] if f.get("nis2_ref")]
    assert len(findings_with_ref) >= 2

def test_nis2_cover_meta_has_regulatorik(nis2_output, scan_meta, host_inventory):
    """NIS2 cover should mention regulatorik."""
    result = map_nis2_report(nis2_output, scan_meta, host_inventory)
    cover_meta = result["cover"]["cover_meta"]
    reg_rows = [row for row in cover_meta if row[0] == "Regulatorik:"]
    assert len(reg_rows) == 1
    assert "BSIG" in reg_rows[0][1]

def test_nis2_toc_has_nis2_sections(nis2_output, scan_meta, host_inventory):
    """NIS2 TOC should have compliance, audit trail, supply chain sections."""
    result = map_nis2_report(nis2_output, scan_meta, host_inventory)
    toc = result["toc"]
    toc_titles = [entry[1] for entry in toc]
    assert any("Compliance" in t or "compliance" in t.lower() for t in toc_titles)
    assert any("Audit" in t for t in toc_titles)
    assert any("Lieferkette" in t or "Supply" in t.lower() for t in toc_titles)

def test_nis2_has_professional_base(nis2_output, scan_meta, host_inventory):
    """NIS2 report should have all professional sections."""
    result = map_nis2_report(nis2_output, scan_meta, host_inventory)
    assert "executive_summary" in result
    assert "scope" in result
    assert "findings" in result
    assert "recommendations" in result
    assert "appendices" in result

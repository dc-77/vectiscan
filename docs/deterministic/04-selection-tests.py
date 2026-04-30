"""
report-worker/tests/test_selection.py

Tests für selection.py.
Spec: docs/specs/2026-Q2-determinism/04-deterministic-selection.md

Property-Tests für die Garantien aus Spec §7:
- Determinismus
- Top-N-Bound
- No-Duplicates
- Stable-Sort
- Critical-First
- No-Loss
"""

from copy import deepcopy

import pytest

# TODO(claude-code): Pfad anpassen
from reporter.selection import (
    TOP_N_PER_PACKAGE,
    SelectionResult,
    consolidate,
    select_findings,
    prepare_for_reporter,
)


# ====================================================================
# FIXTURES
# ====================================================================
def make_finding(
    finding_id: str = "f-001",
    finding_type: str = "csp_missing",
    policy_id: str = "SP-CSP-002",
    severity: str = "low",
    cvss_score: float = 3.8,
    business_impact_score: float = 50.0,
    confidence: float = 0.9,
    epss_score: float = 0.0,
    host: str = "example.com",
    title: str = "CSP missing",
    **extra,
) -> dict:
    finding = {
        "finding_id": finding_id,
        "finding_type": finding_type,
        "type": finding_type,  # Legacy-Feld
        "policy_id": policy_id,
        "severity": severity,
        "cvss_score": cvss_score,
        "business_impact_score": business_impact_score,
        "confidence": confidence,
        "epss_score": epss_score,
        "host": host,
        "title": title,
    }
    finding.update(extra)
    return finding


# ====================================================================
# 1. KONSOLIDIERUNG
# ====================================================================
class TestConsolidation:
    def test_single_finding_unchanged(self):
        f = make_finding()
        result, groups = consolidate([f])
        assert len(result) == 1
        assert groups == 1
        assert result[0]["affected_hosts"] == ["example.com"]

    def test_same_finding_different_hosts_consolidates(self):
        f1 = make_finding(finding_id="f-001", host="host1.com")
        f2 = make_finding(finding_id="f-002", host="host2.com")
        f3 = make_finding(finding_id="f-003", host="host3.com")
        result, groups = consolidate([f1, f2, f3])
        assert len(result) == 1
        assert groups == 1
        assert sorted(result[0]["affected_hosts"]) == ["host1.com", "host2.com", "host3.com"]

    def test_different_finding_types_not_consolidated(self):
        f1 = make_finding(finding_type="csp_missing", policy_id="SP-CSP-002")
        f2 = make_finding(finding_id="f-002", finding_type="hsts_missing", policy_id="SP-HDR-001")
        result, groups = consolidate([f1, f2])
        assert len(result) == 2
        assert groups == 2

    def test_consolidation_picks_max_business_impact(self):
        f1 = make_finding(finding_id="f-001", host="a", business_impact_score=10.0)
        f2 = make_finding(finding_id="f-002", host="b", business_impact_score=80.0)
        f3 = make_finding(finding_id="f-003", host="c", business_impact_score=50.0)
        result, _ = consolidate([f1, f2, f3])
        assert len(result) == 1
        assert result[0]["business_impact_score"] == 80.0

    def test_consolidation_picks_max_confidence(self):
        f1 = make_finding(finding_id="f-001", host="a", confidence=0.5)
        f2 = make_finding(finding_id="f-002", host="b", confidence=0.95)
        result, _ = consolidate([f1, f2])
        assert result[0]["confidence"] == 0.95

    def test_evidence_difference_separates_groups(self):
        """Selbe finding_type, aber unterschiedliches header_name → nicht konsolidieren."""
        f1 = make_finding(
            finding_id="f-001", host="a",
            evidence={"header_name": "X-Frame-Options"}
        )
        f2 = make_finding(
            finding_id="f-002", host="b",
            evidence={"header_name": "Content-Security-Policy"}
        )
        result, groups = consolidate([f1, f2])
        assert groups == 2


# ====================================================================
# 2. SELEKTION: TOP-N
# ====================================================================
class TestSelection:
    def test_empty_input(self):
        result = select_findings([], package="perimeter")
        assert isinstance(result, SelectionResult)
        assert len(result.selected) == 0
        assert len(result.additional) == 0

    def test_top_n_perimeter(self):
        findings = [
            make_finding(finding_id=f"f-{i:03d}", host=f"h{i}",
                         business_impact_score=100 - i,
                         finding_type=f"type_{i}",  # Verhindert Consolidation
                         policy_id=f"SP-X-{i:03d}")
            for i in range(30)
        ]
        result = select_findings(findings, package="perimeter")
        assert len(result.selected) == 15  # Perimeter Top-N
        assert len(result.additional) == 15

    def test_top_n_webcheck(self):
        findings = [
            make_finding(finding_id=f"f-{i:03d}", finding_type=f"t{i}", policy_id=f"SP-{i:03d}",
                         business_impact_score=100 - i)
            for i in range(30)
        ]
        result = select_findings(findings, package="webcheck")
        assert len(result.selected) == 8  # WebCheck Top-N

    def test_top_n_compliance(self):
        findings = [
            make_finding(finding_id=f"f-{i:03d}", finding_type=f"t{i}", policy_id=f"SP-{i:03d}",
                         business_impact_score=100 - i)
            for i in range(50)
        ]
        result = select_findings(findings, package="compliance")
        assert len(result.selected) == 20

    def test_top_n_override(self):
        findings = [
            make_finding(finding_id=f"f-{i:03d}", finding_type=f"t{i}",
                         policy_id=f"SP-{i:03d}",
                         business_impact_score=100 - i)
            for i in range(30)
        ]
        result = select_findings(findings, package="perimeter", top_n_override=5)
        assert len(result.selected) == 5

    def test_unknown_package_uses_default(self):
        findings = [
            make_finding(finding_id=f"f-{i:03d}", finding_type=f"t{i}",
                         policy_id=f"SP-{i:03d}",
                         business_impact_score=100 - i)
            for i in range(20)
        ]
        result = select_findings(findings, package="unknown_pkg")
        assert len(result.selected) == 10  # DEFAULT_TOP_N


# ====================================================================
# 3. SORTIERUNG
# ====================================================================
class TestSorting:
    def test_business_impact_primary_sort(self):
        findings = [
            make_finding(finding_id="f-low", finding_type="t1", policy_id="SP-A",
                         business_impact_score=10),
            make_finding(finding_id="f-high", finding_type="t2", policy_id="SP-B",
                         business_impact_score=90),
            make_finding(finding_id="f-mid", finding_type="t3", policy_id="SP-C",
                         business_impact_score=50),
        ]
        result = select_findings(findings, package="perimeter")
        assert result.selected[0]["finding_id"] == "f-high"
        assert result.selected[1]["finding_id"] == "f-mid"
        assert result.selected[2]["finding_id"] == "f-low"

    def test_cvss_secondary_sort(self):
        """Bei gleichem business_impact entscheidet CVSS."""
        findings = [
            make_finding(finding_id="f-cvss-low", finding_type="t1", policy_id="SP-A",
                         business_impact_score=50, cvss_score=3.0),
            make_finding(finding_id="f-cvss-high", finding_type="t2", policy_id="SP-B",
                         business_impact_score=50, cvss_score=8.0),
        ]
        result = select_findings(findings, package="perimeter")
        assert result.selected[0]["finding_id"] == "f-cvss-high"

    def test_finding_id_tiebreaker(self):
        """Bei sonst identischen Findings: finding_id ASC entscheidet."""
        findings = [
            make_finding(finding_id="f-zzz", finding_type="t1", policy_id="SP-A",
                         business_impact_score=50, cvss_score=5.0,
                         epss_score=0.1, confidence=0.9),
            make_finding(finding_id="f-aaa", finding_type="t2", policy_id="SP-B",
                         business_impact_score=50, cvss_score=5.0,
                         epss_score=0.1, confidence=0.9),
        ]
        result = select_findings(findings, package="perimeter")
        # f-aaa kommt zuerst (alphabetisch)
        assert result.selected[0]["finding_id"] == "f-aaa"
        assert result.selected[1]["finding_id"] == "f-zzz"


# ====================================================================
# 4. PROPERTY-TESTS aus Spec §7
# ====================================================================
class TestProperties:
    def test_determinism(self):
        """Zweimal gleicher Input → identisches Output."""
        findings = [
            make_finding(finding_id=f"f-{i:03d}", finding_type=f"t{i}",
                         policy_id=f"SP-X-{i:03d}",
                         business_impact_score=50 + i % 20)
            for i in range(30)
        ]
        r1 = select_findings(deepcopy(findings), package="perimeter")
        r2 = select_findings(deepcopy(findings), package="perimeter")
        ids1 = [f["finding_id"] for f in r1.selected]
        ids2 = [f["finding_id"] for f in r2.selected]
        assert ids1 == ids2

    def test_top_n_bound(self):
        """len(selected) ≤ TOP_N_PER_PACKAGE[package]."""
        for package, top_n in TOP_N_PER_PACKAGE.items():
            findings = [
                make_finding(finding_id=f"f-{i:03d}", finding_type=f"t_{i}",
                             policy_id=f"SP-X-{i:03d}")
                for i in range(top_n + 10)
            ]
            result = select_findings(findings, package=package)
            assert len(result.selected) <= top_n, \
                f"{package}: {len(result.selected)} > {top_n}"

    def test_no_loss(self):
        """selected + additional == consolidated_input."""
        findings = [
            make_finding(finding_id=f"f-{i:03d}", finding_type=f"t_{i}",
                         policy_id=f"SP-X-{i:03d}")
            for i in range(30)
        ]
        result = select_findings(findings, package="perimeter")
        assert (len(result.selected) + len(result.additional)
                == 30)  # Keine Konsolidierung in dieser Liste

    def test_critical_first(self):
        """Wenn ≥1 critical existiert, ist das erste Element critical (sofern
        business_impact entsprechend hoch)."""
        findings = [
            make_finding(finding_id="f-low", finding_type="t1", policy_id="SP-A",
                         severity="low", business_impact_score=50,
                         cvss_score=3.0),
            make_finding(finding_id="f-crit", finding_type="t2", policy_id="SP-B",
                         severity="critical", business_impact_score=999.0,
                         cvss_score=9.8),
            make_finding(finding_id="f-med", finding_type="t3", policy_id="SP-C",
                         severity="medium", business_impact_score=70,
                         cvss_score=5.5),
        ]
        result = select_findings(findings, package="perimeter")
        assert result.selected[0]["severity"] == "critical"
        assert result.selected[0]["finding_id"] == "f-crit"

    def test_consolidation_works_on_real_findings(self):
        """Selber CSP-Issue auf 5 Hosts → 1 Finding mit 5 affected_hosts."""
        findings = [
            make_finding(finding_id=f"f-{i}",
                         host=f"sub{i}.example.com",
                         finding_type="csp_missing",
                         policy_id="SP-CSP-002")
            for i in range(5)
        ]
        result = select_findings(findings, package="perimeter")
        assert len(result.selected) == 1
        assert len(result.selected[0]["affected_hosts"]) == 5


# ====================================================================
# 5. REPORTER-INTEGRATION
# ====================================================================
class TestPrepareForReporter:
    def test_prepare_returns_required_keys(self):
        findings = [
            make_finding(finding_id="f-001", finding_type="csp_missing",
                         policy_id="SP-CSP-002")
        ]
        result = select_findings(findings, package="perimeter")
        prepared = prepare_for_reporter(result, scan_summary={"total_hosts": 5})
        assert "package" in prepared
        assert "selected_findings" in prepared
        assert "additional_findings" in prepared
        assert "scan_summary" in prepared

    def test_prepare_strips_unnecessary_fields(self):
        f = make_finding(
            finding_id="f-001",
            finding_type="csp_missing",
            policy_id="SP-CSP-002",
            tool_metrics={"runtime_ms": 100},  # Sollte raus
            internal_debug={"foo": "bar"},      # Sollte raus
        )
        result = select_findings([f], package="perimeter")
        prepared = prepare_for_reporter(result, scan_summary={})
        assert "tool_metrics" not in prepared["selected_findings"][0]
        assert "internal_debug" not in prepared["selected_findings"][0]

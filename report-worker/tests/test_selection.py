"""Tests fuer reporter/selection.py.

Spec: docs/deterministic/04-deterministic-selection.md
Skeleton: docs/deterministic/04-selection-tests.py

Property-Tests fuer Garantien aus Spec §7:
- Determinismus
- Top-N-Bound
- No-Duplicates
- Stable-Sort
- Critical-First
- No-Loss
"""

from copy import deepcopy

import pytest

from reporter.selection import (
    DEFAULT_TOP_N,
    TOP_N_PER_PACKAGE,
    SelectionResult,
    consolidate,
    prepare_for_reporter,
    select_findings,
)


def make_finding(
    finding_id: str = "f-001",
    finding_type: str = "csp_missing",
    policy_id: str = "SP-CSP-002",
    severity: str = "low",
    cvss_score: float = 3.8,
    business_impact_score: float = 5.0,
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
        assert sorted(result[0]["affected_hosts"]) == [
            "host1.com", "host2.com", "host3.com"
        ]

    def test_different_finding_types_not_consolidated(self):
        f1 = make_finding(finding_type="csp_missing", policy_id="SP-CSP-002")
        f2 = make_finding(finding_id="f-002", finding_type="hsts_missing",
                          policy_id="SP-HDR-001")
        result, groups = consolidate([f1, f2])
        assert len(result) == 2
        assert groups == 2

    def test_consolidation_picks_max_business_impact(self):
        f1 = make_finding(finding_id="f-001", host="a", business_impact_score=1.0)
        f2 = make_finding(finding_id="f-002", host="b", business_impact_score=8.0)
        f3 = make_finding(finding_id="f-003", host="c", business_impact_score=5.0)
        result, _ = consolidate([f1, f2, f3])
        assert len(result) == 1
        assert result[0]["business_impact_score"] == 8.0

    def test_consolidation_picks_max_confidence(self):
        f1 = make_finding(finding_id="f-001", host="a", confidence=0.5)
        f2 = make_finding(finding_id="f-002", host="b", confidence=0.95)
        result, _ = consolidate([f1, f2])
        assert result[0]["confidence"] == 0.95

    def test_evidence_difference_separates_groups(self):
        f1 = make_finding(finding_id="f-001", host="a",
                          evidence={"header_name": "X-Frame-Options"})
        f2 = make_finding(finding_id="f-002", host="b",
                          evidence={"header_name": "Content-Security-Policy"})
        result, groups = consolidate([f1, f2])
        assert groups == 2

    # ----------------------------------------------------------------
    # F-RPT-002: title_vars-Diskriminierung (Mai 2026)
    # ----------------------------------------------------------------
    def test_eol_different_tech_not_consolidated(self):
        """F-RPT-002: software_eol-Findings mit verschiedenen tech in title_vars
        duerfen NICHT konsolidieren."""
        f1 = make_finding(
            finding_id="f-001", finding_type="software_eol",
            policy_id="SP-EOL-002",
            title_vars={"tech": "php", "version": "5.6"},
        )
        f2 = make_finding(
            finding_id="f-002", finding_type="software_eol",
            policy_id="SP-EOL-002",
            title_vars={"tech": "python", "version": "2.7"},
        )
        result, groups = consolidate([f1, f2])
        assert groups == 2, f"erwartet 2 separate Gruppen, bekam {groups}"

    def test_db_port_different_ports_not_consolidated(self):
        """F-RPT-002: database_port_exposed mit verschiedenen Ports trennen."""
        f1 = make_finding(
            finding_id="f-001", finding_type="database_port_exposed",
            policy_id="SP-DB-001",
            title_vars={"port": "3306"},
        )
        f2 = make_finding(
            finding_id="f-002", finding_type="database_port_exposed",
            policy_id="SP-DB-001",
            title_vars={"port": "5432"},
        )
        result, groups = consolidate([f1, f2])
        assert groups == 2

    def test_eol_same_tech_different_hosts_consolidates(self):
        """F-RPT-002: gleiches tech+version auf 2 Hosts -> immer noch 1 Gruppe."""
        f1 = make_finding(
            finding_id="f-001", host="host1.com", finding_type="software_eol",
            policy_id="SP-EOL-001",
            title_vars={"tech": "exchange", "version": "15.1"},
        )
        f2 = make_finding(
            finding_id="f-002", host="host2.com", finding_type="software_eol",
            policy_id="SP-EOL-001",
            title_vars={"tech": "exchange", "version": "15.1"},
        )
        result, groups = consolidate([f1, f2])
        assert groups == 1
        assert sorted(result[0]["affected_hosts"]) == ["host1.com", "host2.com"]

    def test_consolidate_ignores_question_mark_title_vars(self):
        """F-RPT-002: '?'-Platzhalter aus apply_titles soll NICHT als
        Differenzierung gelten."""
        f1 = make_finding(
            finding_id="f-001", finding_type="csp_unsafe_inline",
            policy_id="SP-CSP-002",
            title_vars={"directive": "?"},
        )
        f2 = make_finding(
            finding_id="f-002", finding_type="csp_unsafe_inline",
            policy_id="SP-CSP-002",
            title_vars={"directive": ""},
        )
        f3 = make_finding(
            finding_id="f-003", finding_type="csp_unsafe_inline",
            policy_id="SP-CSP-002",
            # kein title_vars
        )
        result, groups = consolidate([f1, f2, f3])
        assert groups == 1, "?/empty/missing title_vars sollten zusammen gruppieren"


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
                         business_impact_score=10.0 - i * 0.1,
                         finding_type=f"type_{i}",
                         policy_id=f"SP-X-{i:03d}")
            for i in range(30)
        ]
        result = select_findings(findings, package="perimeter")
        assert len(result.selected) == 15
        assert len(result.additional) == 15
        assert result.top_n == 15

    def test_top_n_webcheck(self):
        findings = [
            make_finding(finding_id=f"f-{i:03d}", finding_type=f"t{i}",
                         policy_id=f"SP-{i:03d}",
                         business_impact_score=10.0 - i * 0.1)
            for i in range(30)
        ]
        result = select_findings(findings, package="webcheck")
        assert len(result.selected) == 8

    def test_top_n_compliance(self):
        findings = [
            make_finding(finding_id=f"f-{i:03d}", finding_type=f"t{i}",
                         policy_id=f"SP-{i:03d}",
                         business_impact_score=10.0 - i * 0.1)
            for i in range(50)
        ]
        result = select_findings(findings, package="compliance")
        assert len(result.selected) == 20

    def test_top_n_override(self):
        findings = [
            make_finding(finding_id=f"f-{i:03d}", finding_type=f"t{i}",
                         policy_id=f"SP-{i:03d}",
                         business_impact_score=10.0 - i * 0.1)
            for i in range(30)
        ]
        result = select_findings(findings, package="perimeter", top_n_override=5)
        assert len(result.selected) == 5

    def test_unknown_package_uses_default(self):
        findings = [
            make_finding(finding_id=f"f-{i:03d}", finding_type=f"t{i}",
                         policy_id=f"SP-{i:03d}",
                         business_impact_score=10.0 - i * 0.1)
            for i in range(20)
        ]
        result = select_findings(findings, package="unknown_pkg")
        assert len(result.selected) == DEFAULT_TOP_N

    def test_legacy_alias_resolves(self):
        findings = [
            make_finding(finding_id=f"f-{i:03d}", finding_type=f"t{i}",
                         policy_id=f"SP-{i:03d}")
            for i in range(20)
        ]
        # 'professional' ist Legacy fuer 'perimeter' (15)
        result = select_findings(findings, package="professional")
        assert result.package == "perimeter"
        assert len(result.selected) == 15

    def test_drops_false_positives_by_default(self):
        findings = [
            make_finding(finding_id="f-keep", finding_type="t1", policy_id="SP-A",
                         business_impact_score=5.0),
            make_finding(finding_id="f-fp", finding_type="t2", policy_id="SP-B",
                         business_impact_score=9.0, is_false_positive=True),
        ]
        result = select_findings(findings, package="perimeter")
        ids = [f["finding_id"] for f in result.selected]
        assert "f-keep" in ids
        assert "f-fp" not in ids


# ====================================================================
# 3. SORTIERUNG
# ====================================================================
class TestSorting:
    def test_business_impact_primary_sort(self):
        findings = [
            make_finding(finding_id="f-low", finding_type="t1", policy_id="SP-A",
                         business_impact_score=1.0),
            make_finding(finding_id="f-high", finding_type="t2", policy_id="SP-B",
                         business_impact_score=9.0),
            make_finding(finding_id="f-mid", finding_type="t3", policy_id="SP-C",
                         business_impact_score=5.0),
        ]
        result = select_findings(findings, package="perimeter")
        assert result.selected[0]["finding_id"] == "f-high"
        assert result.selected[1]["finding_id"] == "f-mid"
        assert result.selected[2]["finding_id"] == "f-low"

    def test_cvss_secondary_sort(self):
        findings = [
            make_finding(finding_id="f-cvss-low", finding_type="t1", policy_id="SP-A",
                         business_impact_score=5.0, cvss_score=3.0),
            make_finding(finding_id="f-cvss-high", finding_type="t2", policy_id="SP-B",
                         business_impact_score=5.0, cvss_score=8.0),
        ]
        result = select_findings(findings, package="perimeter")
        assert result.selected[0]["finding_id"] == "f-cvss-high"

    def test_finding_id_tiebreaker(self):
        findings = [
            make_finding(finding_id="f-zzz", finding_type="t1", policy_id="SP-A",
                         business_impact_score=5.0, cvss_score=5.0,
                         epss_score=0.1, confidence=0.9),
            make_finding(finding_id="f-aaa", finding_type="t2", policy_id="SP-B",
                         business_impact_score=5.0, cvss_score=5.0,
                         epss_score=0.1, confidence=0.9),
        ]
        result = select_findings(findings, package="perimeter")
        assert result.selected[0]["finding_id"] == "f-aaa"
        assert result.selected[1]["finding_id"] == "f-zzz"


# ====================================================================
# 4. PROPERTY-TESTS
# ====================================================================
class TestProperties:
    def test_determinism(self):
        findings = [
            make_finding(finding_id=f"f-{i:03d}", finding_type=f"t{i}",
                         policy_id=f"SP-X-{i:03d}",
                         business_impact_score=5.0 + (i % 5) * 0.1)
            for i in range(30)
        ]
        r1 = select_findings(deepcopy(findings), package="perimeter")
        r2 = select_findings(deepcopy(findings), package="perimeter")
        ids1 = [f["finding_id"] for f in r1.selected]
        ids2 = [f["finding_id"] for f in r2.selected]
        assert ids1 == ids2

    def test_top_n_bound(self):
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
        findings = [
            make_finding(finding_id=f"f-{i:03d}", finding_type=f"t_{i}",
                         policy_id=f"SP-X-{i:03d}")
            for i in range(30)
        ]
        result = select_findings(findings, package="perimeter")
        # Keine Konsolidierung in dieser Liste (alle finding_types verschieden)
        assert (len(result.selected) + len(result.additional)) == 30

    def test_critical_first(self):
        findings = [
            make_finding(finding_id="f-low", finding_type="t1", policy_id="SP-A",
                         severity="low", business_impact_score=5.0,
                         cvss_score=3.0),
            make_finding(finding_id="f-crit", finding_type="t2", policy_id="SP-B",
                         severity="critical", business_impact_score=10.0,
                         cvss_score=9.8),
            make_finding(finding_id="f-med", finding_type="t3", policy_id="SP-C",
                         severity="medium", business_impact_score=7.0,
                         cvss_score=5.5),
        ]
        result = select_findings(findings, package="perimeter")
        assert result.selected[0]["severity"] == "critical"
        assert result.selected[0]["finding_id"] == "f-crit"

    def test_consolidation_works_on_real_findings(self):
        """Selber CSP-Issue auf 5 Hosts -> 1 Finding mit 5 affected_hosts."""
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
            tool_metrics={"runtime_ms": 100},
            internal_debug={"foo": "bar"},
        )
        result = select_findings([f], package="perimeter")
        prepared = prepare_for_reporter(result, scan_summary={})
        first = prepared["selected_findings"][0]
        assert "tool_metrics" not in first
        assert "internal_debug" not in first
        assert "finding_id" in first
        assert "policy_id" in first
        assert "severity" in first

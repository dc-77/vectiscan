"""Tests fuer reporter/business_impact.py — Recompute auf Policy-Severity."""

from __future__ import annotations

import pytest

from reporter.business_impact import (
    PACKAGE_WEIGHTS,
    SEVERITY_CVSS_MAP,
    order_score,
    recompute,
)


class TestRecompute:
    def test_uses_explicit_cvss(self):
        findings = [{
            "finding_type": "phpinfo_exposed",
            "severity": "high",
            "cvss_score": 7.5,
        }]
        recompute(findings, package="perimeter", domain="example.com")
        # base = 7.5, kein EPSS/KEV/Asset/Package → score = 7.5
        assert findings[0]["business_impact_score"] == 7.5

    def test_falls_back_to_severity_when_no_cvss(self):
        findings = [{
            "finding_type": "hsts_missing",
            "severity": "low",
        }]
        recompute(findings, package="perimeter")
        # severity=low → SEVERITY_CVSS_MAP[low]=2.5
        assert findings[0]["business_impact_score"] == 2.5

    def test_kev_multiplier_applied(self):
        findings = [{
            "finding_type": "cve_finding",
            "severity": "high",
            "cvss_score": 7.0,
            "enrichment": {"cisa_kev": {"cveID": "CVE-2024-12345"}},
        }]
        recompute(findings, package="perimeter")
        # 7.0 * 1.5 (KEV) = 10.5 → cap auf 10.0
        assert findings[0]["business_impact_score"] == 10.0

    def test_epss_high_multiplier(self):
        findings = [{
            "finding_type": "cve_finding",
            "severity": "medium",
            "cvss_score": 5.0,
            "enrichment": {"epss": {"epss": 0.7}},
        }]
        recompute(findings, package="perimeter")
        # 5.0 * 1.3 (EPSS>0.5) = 6.5
        assert findings[0]["business_impact_score"] == 6.5

    def test_base_domain_asset_multiplier(self):
        findings = [{
            "finding_type": "tls_below_tr03116_minimum",
            "severity": "high",
            "cvss_score": 7.0,
            "fqdn": "example.com",
        }]
        recompute(findings, package="perimeter", domain="example.com")
        # 7.0 * 1.2 (base domain) = 8.4
        assert findings[0]["business_impact_score"] == 8.4

    def test_insurance_package_rdp_smb_weight(self):
        findings = [{
            "finding_type": "open_port",
            "severity": "high",
            "cvss_score": 6.0,
            "title": "RDP exposed",
            "port": 3389,
        }]
        recompute(findings, package="insurance")
        # 6.0 * 2.0 (rdp_smb in insurance) = 12.0 → cap 10.0
        assert findings[0]["business_impact_score"] == 10.0

    def test_low_confidence_dampens_score(self):
        findings = [{
            "finding_type": "phpinfo_exposed",
            "severity": "high",
            "cvss_score": 7.0,
            "confidence": 0.3,  # low confidence → 0.7x
        }]
        recompute(findings, package="perimeter")
        # 7.0 * 0.7 = 4.9
        assert findings[0]["business_impact_score"] == 4.9

    def test_false_positive_zero_score(self):
        findings = [{
            "finding_type": "phpinfo_exposed",
            "severity": "high",
            "cvss_score": 7.5,
            "is_false_positive": True,
        }]
        recompute(findings, package="perimeter")
        assert findings[0]["business_impact_score"] == 0.0


class TestOrderScore:
    def test_empty_returns_zero(self):
        assert order_score([]) == 0.0

    def test_top5_weighted_average(self):
        findings = [
            {"business_impact_score": 9.0, "is_false_positive": False},
            {"business_impact_score": 8.0, "is_false_positive": False},
            {"business_impact_score": 7.0, "is_false_positive": False},
            {"business_impact_score": 6.0, "is_false_positive": False},
            {"business_impact_score": 5.0, "is_false_positive": False},
            {"business_impact_score": 4.0, "is_false_positive": False},
        ]
        # Top 5: 9, 8, 7, 6, 5 — Gewichte 1.0, 0.8, 0.6, 0.4, 0.2
        # weighted_sum = 9*1.0 + 8*0.8 + 7*0.6 + 6*0.4 + 5*0.2 = 9+6.4+4.2+2.4+1.0 = 23.0
        # weight_total = 3.0 → 23/3 = 7.66...
        assert abs(order_score(findings) - 7.7) < 0.05

    def test_ignores_false_positives(self):
        findings = [
            {"business_impact_score": 9.0, "is_false_positive": True},
            {"business_impact_score": 5.0, "is_false_positive": False},
        ]
        assert order_score(findings) == 5.0

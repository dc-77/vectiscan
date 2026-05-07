"""Tests fuer reporter/business_impact.py — Recompute auf Policy-Severity."""

from __future__ import annotations

import pytest

from reporter.business_impact import (
    PACKAGE_WEIGHTS,
    POLICY_ID_TO_CATEGORIES,
    RANSOMWARE_PORTS,
    SEVERITY_CVSS_MAP,
    _classify_finding,
    order_score,
    recompute,
)
from reporter.severity_policy import SEVERITY_POLICIES


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


class TestClassifyFinding:
    """F-RPT-003: deterministische policy_id-basierte Klassifikation."""

    def test_policy_id_categories_complete(self):
        """F-RPT-003: jeder policy_id aus SEVERITY_POLICIES ist im Mapping
        (verhindert silent gaps bei neuen Regeln)."""
        severity_pids = {p.policy_id for p in SEVERITY_POLICIES}
        mapping_pids = set(POLICY_ID_TO_CATEGORIES.keys())
        missing = severity_pids - mapping_pids
        assert not missing, f"policy_ids ohne Categories-Mapping: {sorted(missing)}"

    def test_classify_finding_db_port_via_policy_id(self):
        """F-RPT-003: SP-DB-001 -> data_exposure + default_login,
        plus rdp_smb durch Port-Match wenn port in RANSOMWARE_PORTS."""
        finding = {"policy_id": "SP-DB-001", "title": "Datenbank-Port 3306 erreichbar"}
        cats = _classify_finding(finding)
        assert "data_exposure" in cats
        assert "default_login" in cats
        # Port 3306 ist NICHT in RANSOMWARE_PORTS
        assert "rdp_smb" not in cats

    def test_classify_finding_ransomware_port_match(self):
        """F-RPT-003: Port 3389 (RDP) -> rdp_smb auch ohne policy_id-Mapping."""
        finding = {"policy_id": "SP-FALLBACK", "port": 3389}
        cats = _classify_finding(finding)
        assert "rdp_smb" in cats

    def test_classify_finding_telnet_port_in_ransomware_set(self):
        """F-RPT-003: Port 23 (Telnet) und 5800 (VNC alt) sind neu in
        RANSOMWARE_PORTS."""
        assert 23 in RANSOMWARE_PORTS
        assert 5800 in RANSOMWARE_PORTS

    def test_classify_finding_german_text_does_not_matter(self):
        """F-RPT-003: deutsche Titel + Description matchen trotzdem korrekt
        weil Klassifikation NUR ueber policy_id."""
        f1 = {"policy_id": "SP-TLS-001", "title": "TLS-Konfiguration unsicher",
              "description": "Veraltete Verschluesselung erkannt."}
        f2 = {"policy_id": "SP-TLS-001", "title": "TLS configuration insecure",
              "description": "Outdated encryption detected."}
        assert _classify_finding(f1) == _classify_finding(f2)
        assert "encryption" in _classify_finding(f1)

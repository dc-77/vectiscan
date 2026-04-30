"""Tests fuer reporter/severity_policy.py.

Spec: docs/deterministic/02-severity-policy.md
Skeleton: docs/deterministic/02-severity-policy-tests.py

Struktur:
1. Schema-Validation (POLICY_VERSION, Severity-Enum, CVSS-Mapping)
2. Policy-Registry-Sanity (Eindeutigkeit, Format, Konsistenz)
3. lookup_policy() — pro Policy-Familie ein Test
4. extract_context_flags() — pro Flag ein Test
5. apply_policy() — End-to-End auf Findings
6. Determinismus
7. Smoke (1000 Findings, Performance)

Hinweis: Wenn ein Test rot ist, NICHT die Policy-Regel anpassen damit der
Test gruen wird. Erst entscheiden ob die Regel oder der Test falsch ist.
Die Regeln sind gegen Rapid7-/Acunetix-Baselines kalibriert.
"""

from copy import deepcopy

import pytest

from reporter.severity_policy import (
    POLICY_VERSION,
    SEVERITY_POLICIES,
    Severity,
    SeverityPolicy,
    SeverityProvenance,
    apply_policy,
    extract_context_flags,
    lookup_policy,
)


# ====================================================================
# 1. SCHEMA-VALIDATION
# ====================================================================
class TestSchema:
    def test_policy_version_format(self):
        assert "." in POLICY_VERSION
        # Erwartung: YYYY-MM-DD.N (mind. 3 Bindestriche-Sektionen)
        assert len(POLICY_VERSION.split("-")) == 3

    def test_severity_enum_complete(self):
        assert {s.value for s in Severity} == {
            "critical", "high", "medium", "low", "info"
        }

    def test_severity_from_cvss(self):
        assert Severity.from_cvss(9.8) == Severity.CRITICAL
        assert Severity.from_cvss(7.5) == Severity.HIGH
        assert Severity.from_cvss(5.3) == Severity.MEDIUM
        assert Severity.from_cvss(3.1) == Severity.LOW
        assert Severity.from_cvss(0.0) == Severity.INFO

    def test_severity_rank_ordering(self):
        assert Severity.CRITICAL.rank() > Severity.HIGH.rank()
        assert Severity.HIGH.rank() > Severity.MEDIUM.rank()
        assert Severity.MEDIUM.rank() > Severity.LOW.rank()
        assert Severity.LOW.rank() > Severity.INFO.rank()


# ====================================================================
# 2. POLICY-REGISTRY-SANITY
# ====================================================================
class TestPolicyRegistry:
    def test_at_least_35_policies(self):
        assert len(SEVERITY_POLICIES) >= 35, \
            f"Erwartet >=35 Policies, sind {len(SEVERITY_POLICIES)}"

    def test_unique_policy_ids(self):
        ids = [p.policy_id for p in SEVERITY_POLICIES]
        assert len(ids) == len(set(ids)), \
            f"Duplikate: {[i for i in ids if ids.count(i) > 1]}"

    def test_all_have_rationale(self):
        missing = [p.policy_id for p in SEVERITY_POLICIES
                   if not p.rationale.strip()]
        assert not missing, f"Policies ohne rationale: {missing}"

    def test_policy_id_format(self):
        import re
        pattern = re.compile(r"^SP-[A-Z]+-\d{3}$")
        bad = [p.policy_id for p in SEVERITY_POLICIES
               if not pattern.match(p.policy_id)]
        assert not bad, f"Falsches policy_id-Format: {bad}"

    def test_cvss_score_consistency(self):
        """CVSS-Score (wenn gesetzt) sollte zur Severity passen.

        Policy darf abweichen, aber nur in eine Richtung (hoeher als
        CVSS-derived ist OK weil Context KEV/Ransomware bumpt; niedriger
        nicht weil dann das CVSS-Cap-Mapping inkonsistent waere).
        """
        for policy in SEVERITY_POLICIES:
            if policy.cvss_score is None:
                continue
            derived = Severity.from_cvss(policy.cvss_score)
            assert policy.final_severity.rank() >= derived.rank(), (
                f"{policy.policy_id}: severity {policy.final_severity} "
                f"< CVSS-derived {derived}"
            )

    def test_critical_policies_have_kev_or_eol_or_env(self):
        critical = [p for p in SEVERITY_POLICIES
                    if p.final_severity == Severity.CRITICAL]
        for p in critical:
            assert (
                "KEV" in str(p.references)
                or "Ransomware" in str(p.references)
                or p.policy_id.startswith("SP-DISC-008")  # .env exposure
            ), f"{p.policy_id} ist critical ohne KEV/Ransomware/.env-Ref"


# ====================================================================
# 3. lookup_policy() — pro Regel-Familie
# ====================================================================
class TestHeaderPolicies:
    def test_hsts_missing_static(self):
        p = lookup_policy("hsts_missing", {"is_session_path": False})
        assert p is not None and p.policy_id == "SP-HDR-001"
        assert p.final_severity == Severity.INFO

    def test_hsts_missing_session(self):
        p = lookup_policy("hsts_missing", {"is_session_path": True})
        assert p is not None and p.policy_id == "SP-HDR-002"
        assert p.final_severity == Severity.LOW

    def test_xcto_missing_no_context(self):
        p = lookup_policy("xcto_missing", {})
        assert p is not None and p.policy_id == "SP-HDR-005"
        assert p.final_severity == Severity.INFO

    def test_xfo_missing_static(self):
        p = lookup_policy("xfo_missing", {"is_session_path": False})
        assert p is not None and p.policy_id == "SP-HDR-006"
        assert p.final_severity == Severity.INFO

    def test_xfo_missing_session(self):
        p = lookup_policy("xfo_missing", {"is_session_path": True})
        assert p is not None and p.policy_id == "SP-HDR-007"
        assert p.final_severity == Severity.LOW


class TestCSPPolicies:
    def test_csp_missing_static_page(self):
        p = lookup_policy("csp_missing",
                          {"inline_scripts": False, "form_present": False})
        assert p is not None and p.policy_id == "SP-CSP-001"
        assert p.final_severity == Severity.INFO

    def test_csp_missing_with_form(self):
        # Spezifischere Regel gewinnt: SP-CSP-002 (1 condition matched)
        p = lookup_policy("csp_missing", {"form_present": True})
        assert p is not None and p.policy_id == "SP-CSP-002"
        assert p.final_severity == Severity.LOW

    def test_csp_unsafe_inline_with_form(self):
        p = lookup_policy("csp_unsafe_inline", {"form_present": True})
        assert p is not None and p.policy_id == "SP-CSP-003"
        assert p.final_severity == Severity.MEDIUM

    def test_csp_unsafe_eval(self):
        p = lookup_policy("csp_unsafe_eval", {})
        assert p is not None and p.policy_id == "SP-CSP-004"
        assert p.final_severity == Severity.MEDIUM


class TestCookiePolicies:
    def test_cookie_no_secure_session(self):
        p = lookup_policy("cookie_no_secure",
                          {"cookie_session": True, "https_in_use": True})
        assert p is not None and p.policy_id == "SP-COOK-001"
        assert p.final_severity == Severity.MEDIUM

    def test_cookie_no_secure_static(self):
        p = lookup_policy("cookie_no_secure", {"cookie_session": False})
        assert p is not None and p.policy_id == "SP-COOK-004"
        assert p.final_severity == Severity.INFO

    def test_cookie_no_httponly_session(self):
        p = lookup_policy("cookie_no_httponly", {"cookie_session": True})
        assert p is not None and p.policy_id == "SP-COOK-002"
        assert p.final_severity == Severity.MEDIUM

    def test_cookie_no_samesite_session(self):
        p = lookup_policy("cookie_no_samesite", {"cookie_session": True})
        assert p is not None and p.policy_id == "SP-COOK-003"
        assert p.final_severity == Severity.LOW

    def test_cookie_no_samesite_tracking(self):
        p = lookup_policy("cookie_no_samesite", {"cookie_session": False})
        assert p is not None and p.policy_id == "SP-COOK-005"
        assert p.final_severity == Severity.INFO


class TestCSRFPolicies:
    def test_csrf_get_only(self):
        p = lookup_policy("csrf_token_missing", {"state_change": False})
        assert p is not None and p.policy_id == "SP-CSRF-001"
        assert p.final_severity == Severity.INFO

    def test_csrf_state_change_no_auth(self):
        p = lookup_policy("csrf_token_missing",
                          {"state_change": True, "auth_present": False})
        assert p is not None and p.policy_id == "SP-CSRF-002"
        assert p.final_severity == Severity.LOW

    def test_csrf_state_change_with_auth(self):
        p = lookup_policy("csrf_token_missing",
                          {"state_change": True, "auth_present": True})
        assert p is not None and p.policy_id == "SP-CSRF-003"
        assert p.final_severity == Severity.MEDIUM


class TestDisclosurePolicies:
    def test_phpinfo_high(self):
        p = lookup_policy("phpinfo_exposed", {})
        assert p is not None and p.policy_id == "SP-DISC-004"
        assert p.final_severity == Severity.HIGH

    def test_env_file_critical(self):
        p = lookup_policy("env_file_exposed", {})
        assert p is not None and p.policy_id == "SP-DISC-008"
        assert p.final_severity == Severity.CRITICAL

    def test_server_banner_with_version_low(self):
        p = lookup_policy("server_banner_with_version", {})
        assert p is not None and p.policy_id == "SP-DISC-001"
        assert p.final_severity == Severity.LOW

    def test_server_banner_no_version_info(self):
        p = lookup_policy("server_banner_no_version", {})
        assert p is not None and p.policy_id == "SP-DISC-002"
        assert p.final_severity == Severity.INFO


class TestTLSPolicies:
    def test_tls_below_tr03116(self):
        p = lookup_policy("tls_below_tr03116_minimum", {})
        assert p is not None and p.policy_id == "SP-TLS-001"
        assert p.final_severity == Severity.HIGH

    def test_tls_certificate_expired(self):
        p = lookup_policy("tls_certificate_expired", {})
        assert p is not None and p.policy_id == "SP-TLS-004"
        assert p.final_severity == Severity.HIGH


class TestDNSPolicies:
    def test_spf_missing_with_mx(self):
        p = lookup_policy("spf_missing", {"mx_present": True})
        assert p is not None and p.policy_id == "SP-DNS-004"
        assert p.final_severity == Severity.MEDIUM

    def test_dmarc_missing_with_mx(self):
        p = lookup_policy("dmarc_missing", {"mx_present": True})
        assert p is not None and p.policy_id == "SP-DNS-006"
        assert p.final_severity == Severity.MEDIUM

    def test_dnssec_missing(self):
        p = lookup_policy("dnssec_missing", {})
        assert p is not None and p.policy_id == "SP-DNS-001"
        assert p.final_severity == Severity.LOW


class TestEOLPolicies:
    def test_exchange_eol(self):
        p = lookup_policy("software_eol", {"tech": "exchange"})
        assert p is not None and p.policy_id == "SP-EOL-001"
        assert p.final_severity == Severity.HIGH

    def test_php_eol(self):
        p = lookup_policy("software_eol", {"tech": "php"})
        assert p is not None and p.policy_id == "SP-EOL-002"
        assert p.final_severity == Severity.MEDIUM


# ====================================================================
# 4. extract_context_flags()
# ====================================================================
class TestContextFlags:
    def test_session_path_detection_login(self):
        flags = extract_context_flags({"url": "https://example.com/login"}, {})
        assert flags["is_session_path"] is True

    def test_session_path_detection_static(self):
        flags = extract_context_flags({"url": "https://example.com/about-us"}, {})
        assert flags["is_session_path"] is False

    def test_https_in_use(self):
        flags_https = extract_context_flags({"url": "https://example.com/"}, {})
        assert flags_https["https_in_use"] is True
        flags_http = extract_context_flags({"url": "http://example.com/"},
                                           {"https_default": False})
        assert flags_http["https_in_use"] is False

    def test_state_change_detection(self):
        flags_post = extract_context_flags(
            {"url": "https://example.com/", "evidence": {"http_method": "POST"}}, {})
        assert flags_post["state_change"] is True
        flags_get = extract_context_flags(
            {"url": "https://example.com/", "evidence": {"http_method": "GET"}}, {})
        assert flags_get["state_change"] is False

    def test_mx_present_from_dns(self):
        scan_context = {"dns_records": {"mx": ["mx01.example.com"]}}
        flags = extract_context_flags({"url": "https://example.com/"}, scan_context)
        assert flags["mx_present"] is True

    def test_kev_threat_intel_simple_shape(self):
        finding = {
            "url": "https://example.com/",
            "threat_intel": {"in_kev": True, "epss_score": 0.7},
        }
        flags = extract_context_flags(finding, {})
        assert flags["cve_in_kev"] is True
        assert flags["cve_epss_high"] is True

    def test_kev_threat_intel_structured_shape(self):
        finding = {
            "url": "https://example.com/",
            "enrichment": {
                "cisa_kev": {"cveID": "CVE-2024-12345",
                             "knownRansomwareCampaignUse": "Known"},
                "epss": {"epss": 0.6},
            },
        }
        flags = extract_context_flags(finding, {})
        assert flags["cve_in_kev"] is True
        assert flags["cve_ransomware"] is True
        assert flags["cve_epss_high"] is True


# ====================================================================
# 5. apply_policy() — End-to-End
# ====================================================================
class TestApplyPolicy:
    def test_apply_modifies_severity(self):
        findings = [{
            "finding_type": "hsts_missing",
            "url": "https://example.com/about",
            "severity": "medium",
            "tool_source": "zap_passive",
        }]
        apply_policy(findings, scan_context={})
        # SP-HDR-001 sollte greifen → info
        assert findings[0]["severity"] == "info"
        assert findings[0]["policy_id"] == "SP-HDR-001"
        assert "severity_provenance" in findings[0]

    def test_apply_session_path_uses_low(self):
        findings = [{
            "finding_type": "hsts_missing",
            "url": "https://example.com/login",
            "severity": "medium",
            "tool_source": "zap_passive",
        }]
        apply_policy(findings, scan_context={})
        assert findings[0]["severity"] == "low"
        assert findings[0]["policy_id"] == "SP-HDR-002"

    def test_apply_unknown_finding_type_fallback(self):
        findings = [{
            "finding_type": "some_unknown_type",
            "url": "https://example.com/",
            "severity": "high",
            "tool_source": "custom_tool",
        }]
        apply_policy(findings, scan_context={})
        assert findings[0]["policy_id"] == "SP-FALLBACK"
        # Severity bleibt erhalten
        assert findings[0]["severity"] == "high"

    def test_apply_cve_with_kev(self):
        findings = [{
            "finding_type": "cve_finding",
            "url": "https://example.com/",
            "cvss_score": 7.5,
            "threat_intel": {"in_kev": True},
            "tool_source": "nvd",
        }]
        apply_policy(findings, scan_context={})
        assert findings[0]["severity"] == "critical"
        assert findings[0]["policy_id"] == "SP-CVE-001"

    def test_apply_cve_fallback_to_cvss(self):
        findings = [{
            "finding_type": "cve_finding",
            "url": "https://example.com/",
            "cvss_score": 5.3,
            "threat_intel": {"in_kev": False, "epss_score": 0.05},
            "tool_source": "nvd",
        }]
        apply_policy(findings, scan_context={})
        assert findings[0]["severity"] == "medium"
        assert findings[0]["policy_id"] == "SP-CVE-004"

    def test_provenance_contains_policy_version(self):
        findings = [{
            "finding_type": "hsts_missing",
            "url": "https://example.com/login",
            "severity": "medium",
        }]
        apply_policy(findings, {})
        prov = findings[0]["severity_provenance"]
        assert prov["policy_version"] == POLICY_VERSION
        assert prov["policy_id"] == "SP-HDR-002"
        assert prov["rule_references"]


# ====================================================================
# 6. DETERMINISMUS
# ====================================================================
class TestDeterminism:
    def test_lookup_is_idempotent(self):
        flags = {"form_present": True, "is_session_path": True}
        p1 = lookup_policy("csp_missing", flags)
        p2 = lookup_policy("csp_missing", flags)
        assert p1 is p2 or p1.policy_id == p2.policy_id

    def test_apply_is_idempotent(self):
        findings = [{
            "finding_type": "hsts_missing",
            "url": "https://example.com/admin",
            "severity": "medium",
            "tool_source": "zap_passive",
        }]
        f1 = deepcopy(findings)
        f2 = deepcopy(findings)
        apply_policy(f1, {})
        apply_policy(f2, {})
        assert f1[0]["severity"] == f2[0]["severity"]
        assert f1[0]["policy_id"] == f2[0]["policy_id"]

    def test_specificity_tiebreak_alphabetical(self):
        flags = {}
        p = lookup_policy("xcto_missing", flags)
        assert p.policy_id == "SP-HDR-005"  # einzige fuer xcto_missing


# ====================================================================
# 7. Smoke
# ====================================================================
class TestSmoke:
    def test_apply_to_1000_findings(self):
        import time

        findings = [
            {
                "finding_type": "hsts_missing",
                "url": f"https://example.com/page{i}",
                "severity": "medium",
                "tool_source": "zap_passive",
            }
            for i in range(1000)
        ]
        start = time.perf_counter()
        apply_policy(findings, {})
        duration = time.perf_counter() - start
        assert duration < 1.0, f"Zu langsam: {duration:.3f}s fuer 1000 Findings"
        assert all("policy_id" in f for f in findings)

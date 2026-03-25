"""Tests for BSI TR-03116-4 TLS compliance checker."""

import pytest

from reporter.tr03116_checker import (
    check_tr03116_compliance,
    TR_02102_2_ALLOWED_CIPHERS,
    TR_02102_2_ALLOWED_CURVES,
)


def _entry(id: str, finding: str, severity: str = "OK", **kw) -> dict:
    """Build a testssl entry."""
    return {"id": id, "finding": finding, "severity": severity, "cve": "", "port": "443", **kw}


def _compliant_base() -> list[dict]:
    """Minimal fully compliant testssl output."""
    return [
        # 2.1 TLS Versions
        _entry("TLS1_2", "offered"),
        _entry("TLS1_3", "offered"),
        _entry("SSLv2", "not offered"),
        _entry("SSLv3", "not offered"),
        _entry("TLS1", "not offered"),
        _entry("TLS1_1", "not offered"),
        # 2.2 Cipher Suites
        _entry("RC4", "not offered"),
        _entry("3DES_IDEA", "not offered"),
        _entry("NULL", "not offered"),
        _entry("EXPORT", "not offered"),
        _entry("aNULL", "not offered"),
        _entry("PFS", "offered, server supports ECDHE"),
        _entry("cipherorder_tls13_1", "TLS_AES_256_GCM_SHA384"),
        _entry("cipherorder_tls12_1", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        # 2.3 Certificate
        _entry("cert_keySize", "RSA 4096 bits"),
        _entry("cert_signatureAlgorithm", "SHA256withRSA"),
        _entry("cert_notAfter", "2027-12-31 23:59"),
        _entry("cert_chain_of_trust", "passed"),
        _entry("cert_commonName", "example.com"),
        _entry("cert_subjectAltName", "example.com, www.example.com"),
        _entry("cert_trust", "certificate trusted"),
        _entry("cert_ocspURL", "http://ocsp.letsencrypt.org"),
        # 2.4 Key Exchange
        _entry("PFS_ECDHE_curves", "secp256r1 secp384r1 x25519"),
        _entry("DH_groups", "RFC 7919/ffdhe4096"),
        _entry("LOGJAM", "not vulnerable"),
        _entry("secure_renego", "supported"),
        _entry("secure_client_renego", "not vulnerable"),
        # 2.5 Extensions
        _entry("CRIME_TLS", "not vulnerable"),
        _entry("heartbleed", "not vulnerable"),
        # 2.6 Recommendations
        _entry("OCSP_stapling", "offered"),
    ]


class TestFullyCompliant:
    """Test 1: Fully compliant testssl output → PASS."""

    def test_overall_pass(self):
        result = check_tr03116_compliance(_compliant_base(), host="example.com")
        assert result["overall_status"] == "PASS"
        assert result["mandatory_pass"] is True
        assert result["host"] == "example.com"

    def test_all_mandatory_checks_pass(self):
        result = check_tr03116_compliance(_compliant_base())
        for sec_id in ("2.1", "2.2", "2.3", "2.4", "2.5"):
            section = result["sections"][sec_id]
            for check in section["checks"]:
                assert check["status"] in ("PASS", "WARN"), \
                    f"Check {check['check_id']} expected PASS, got {check['status']}: {check['detail']}"

    def test_score_format(self):
        result = check_tr03116_compliance(_compliant_base())
        score = result["score"]
        assert "/" in score
        passed, total = score.split("/")
        assert int(passed) > 0
        assert int(total) > 0
        assert int(passed) <= int(total)


class TestTLS10Active:
    """Test 2: TLS 1.0 still active → Check 2.1.5 FAIL."""

    def test_tls10_fails(self):
        findings = _compliant_base()
        # Override TLS1 to "offered"
        for f in findings:
            if f["id"] == "TLS1":
                f["finding"] = "offered"
                f["severity"] = "HIGH"
        result = check_tr03116_compliance(findings)
        assert result["overall_status"] == "FAIL"
        assert result["mandatory_pass"] is False
        check = result["sections"]["2.1"]["checks"][4]  # 2.1.5
        assert check["check_id"] == "2.1.5"
        assert check["status"] == "FAIL"


class TestSSLv3Active:
    """Test 3: SSLv3 still active → Check 2.1.4 FAIL."""

    def test_sslv3_fails(self):
        findings = _compliant_base()
        for f in findings:
            if f["id"] == "SSLv3":
                f["finding"] = "offered"
                f["severity"] = "CRITICAL"
        result = check_tr03116_compliance(findings)
        assert result["overall_status"] == "FAIL"
        check = result["sections"]["2.1"]["checks"][3]  # 2.1.4
        assert check["check_id"] == "2.1.4"
        assert check["status"] == "FAIL"


class TestRC4Cipher:
    """Test 4: RC4 cipher offered → Check 2.2.1 FAIL."""

    def test_rc4_fails(self):
        findings = _compliant_base()
        for f in findings:
            if f["id"] == "RC4":
                f["finding"] = "offered"
                f["severity"] = "HIGH"
        result = check_tr03116_compliance(findings)
        assert result["overall_status"] == "FAIL"
        check = result["sections"]["2.2"]["checks"][0]  # 2.2.1
        assert check["check_id"] == "2.2.1"
        assert check["status"] == "FAIL"


class TestExpiredCertificate:
    """Test 5: Expired certificate → Check 2.3.3 FAIL."""

    def test_expired_cert_fails(self):
        findings = _compliant_base()
        for f in findings:
            if f["id"] == "cert_notAfter":
                f["finding"] = "2024-01-01 00:00 expired!"
                f["severity"] = "CRITICAL"
        result = check_tr03116_compliance(findings)
        assert result["overall_status"] == "FAIL"
        check = result["sections"]["2.3"]["checks"][2]  # 2.3.3
        assert check["check_id"] == "2.3.3"
        assert check["status"] == "FAIL"


class TestNoPFS:
    """Test 6: No PFS → Check 2.2.6 FAIL."""

    def test_no_pfs_fails(self):
        findings = _compliant_base()
        for f in findings:
            if f["id"] == "PFS":
                f["finding"] = "not offered"
                f["severity"] = "MEDIUM"
        result = check_tr03116_compliance(findings)
        assert result["overall_status"] == "FAIL"
        check = result["sections"]["2.2"]["checks"][5]  # 2.2.6
        assert check["check_id"] == "2.2.6"
        assert check["status"] == "FAIL"


class TestNoData:
    """Test 7: Empty findings → all checks N/A."""

    def test_empty_findings_all_na(self):
        result = check_tr03116_compliance([])
        for sec_id, section in result["sections"].items():
            for check in section["checks"]:
                assert check["status"] == "N/A", \
                    f"Check {check['check_id']} expected N/A, got {check['status']}"
        # No checks evaluated → PASS (no failures)
        assert result["score"] == "0/0"

    def test_none_like_findings(self):
        result = check_tr03116_compliance([{"id": "", "finding": "", "severity": ""}])
        # Should not crash
        assert result["overall_status"] in ("PASS", "FAIL", "PARTIAL")


class TestOCSPStaplingMissing:
    """Test 8: OCSP stapling not offered → Check 2.6.2 WARN (optional, not FAIL)."""

    def test_ocsp_stapling_warn(self):
        findings = _compliant_base()
        for f in findings:
            if f["id"] == "OCSP_stapling":
                f["finding"] = "not offered"
                f["severity"] = "INFO"
        result = check_tr03116_compliance(findings)
        check = result["sections"]["2.6"]["checks"][1]  # 2.6.2
        assert check["check_id"] == "2.6.2"
        assert check["status"] == "WARN"
        # Should NOT cause overall FAIL since 2.6 is optional
        assert result["mandatory_pass"] is True


class TestHSTSMissing:
    """Test 9: HSTS missing but header_data provided → Check 2.6.3 WARN."""

    def test_hsts_missing_warn(self):
        findings = _compliant_base()
        header_data = {
            "url": "https://example.com",
            "score": "5/7",
            "present": ["x-frame-options", "x-content-type-options"],
            "missing": ["strict-transport-security", "referrer-policy"],
            "details": {},
        }
        result = check_tr03116_compliance(findings, header_data=header_data, host="example.com")
        check = result["sections"]["2.6"]["checks"][2]  # 2.6.3
        assert check["check_id"] == "2.6.3"
        assert check["status"] == "WARN"

    def test_hsts_present_pass(self):
        findings = _compliant_base()
        header_data = {
            "url": "https://example.com",
            "score": "7/7",
            "present": ["strict-transport-security", "x-frame-options"],
            "missing": [],
            "details": {
                "security_headers": {
                    "Strict-Transport-Security": {
                        "present": True,
                        "value": "max-age=31536000; includeSubDomains",
                    }
                }
            },
        }
        result = check_tr03116_compliance(findings, header_data=header_data)
        check = result["sections"]["2.6"]["checks"][2]  # 2.6.3
        assert check["check_id"] == "2.6.3"
        assert check["status"] == "PASS"


class TestBrainpoolCurves:
    """Test 10: Brainpool curves present → mentioned in detail."""

    def test_brainpool_mentioned(self):
        findings = _compliant_base()
        for f in findings:
            if f["id"] == "PFS_ECDHE_curves":
                f["finding"] = "brainpoolP256r1 secp256r1 x25519"
        result = check_tr03116_compliance(findings)
        check = result["sections"]["2.4"]["checks"][1]  # 2.4.2
        assert check["check_id"] == "2.4.2"
        assert check["status"] == "PASS"
        assert "Brainpool" in check["detail"]

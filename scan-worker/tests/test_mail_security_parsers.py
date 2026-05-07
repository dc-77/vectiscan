"""Tests for scanner/passive/mail_security_parsers.py (F-P0A-002).

Covers:
  - parse_tls_rpt   (RFC 8460)
  - parse_bimi      (RFC 9091 draft)
  - parse_dmarc     (RFC 7489) — structured policy
  - parse_nsec3param (RFC 9276)
  - check_*  (mocked dig)
"""

from unittest.mock import patch

import pytest

from scanner.passive.mail_security_parsers import (
    check_bimi,
    check_dmarc_policy,
    check_nsec3_iterations,
    check_tls_rpt,
    parse_bimi,
    parse_dmarc,
    parse_nsec3param,
    parse_tls_rpt,
)


# ---------------------------------------------------------------------------
# parse_tls_rpt
# ---------------------------------------------------------------------------
class TestParseTlsRpt:
    def test_valid_record_with_mailto(self):
        r = parse_tls_rpt("v=TLSRPTv1; rua=mailto:reports@example.com")
        assert r["tlsrpt_present"] is True
        assert r["rua_targets"] == ["mailto:reports@example.com"]
        assert r["issues"] == []

    def test_valid_record_with_multiple_rua(self):
        r = parse_tls_rpt(
            "v=TLSRPTv1; rua=mailto:a@example.com,https://reports.example.com"
        )
        assert r["tlsrpt_present"] is True
        assert "mailto:a@example.com" in r["rua_targets"]
        assert "https://reports.example.com" in r["rua_targets"]

    def test_missing_record(self):
        r = parse_tls_rpt("")
        assert r["tlsrpt_present"] is False
        assert r["rua_targets"] == []

    def test_record_without_rua_flagged_as_issue(self):
        r = parse_tls_rpt("v=TLSRPTv1;")
        assert r["tlsrpt_present"] is True
        assert any("no rua" in i.lower() for i in r["issues"])

    def test_check_tls_rpt_via_mock(self):
        """check_tls_rpt drives DNS-Lookup via _dig — mock it."""
        with patch("scanner.passive.mail_security_parsers._dig",
                   return_value='"v=TLSRPTv1; rua=mailto:rep@x.com"'):
            r = check_tls_rpt("example.com")
        assert r["tlsrpt_present"] is True
        assert r["rua_targets"] == ["mailto:rep@x.com"]


# ---------------------------------------------------------------------------
# parse_bimi
# ---------------------------------------------------------------------------
class TestParseBimi:
    def test_valid_record_with_logo(self):
        r = parse_bimi("v=BIMI1; l=https://example.com/logo.svg")
        assert r["bimi_present"] is True
        assert r["logo_url"] == "https://example.com/logo.svg"
        assert r["vmc_url"] is None

    def test_valid_record_with_vmc(self):
        r = parse_bimi(
            "v=BIMI1; l=https://e.com/l.svg; a=https://e.com/cert.pem"
        )
        assert r["bimi_present"] is True
        assert r["logo_url"] == "https://e.com/l.svg"
        assert r["vmc_url"] == "https://e.com/cert.pem"

    def test_missing_record(self):
        r = parse_bimi("")
        assert r["bimi_present"] is False

    def test_bimi_without_logo_flagged(self):
        r = parse_bimi("v=BIMI1;")
        assert r["bimi_present"] is True
        assert any("logo" in i.lower() for i in r["issues"])

    def test_check_bimi_via_mock(self):
        with patch("scanner.passive.mail_security_parsers._dig",
                   return_value='"v=BIMI1; l=https://x.com/logo.svg"'):
            r = check_bimi("example.com")
        assert r["bimi_present"] is True
        assert r["logo_url"] == "https://x.com/logo.svg"


# ---------------------------------------------------------------------------
# parse_dmarc
# ---------------------------------------------------------------------------
class TestParseDmarc:
    def test_full_record(self):
        r = parse_dmarc(
            "v=DMARC1; p=reject; sp=quarantine; pct=100; "
            "rua=mailto:agg@x.com; ruf=mailto:f@x.com; aspf=s; adkim=s"
        )
        assert r["dmarc_present"] is True
        assert r["p"] == "reject"
        assert r["sp"] == "quarantine"
        assert r["pct"] == 100
        assert r["aspf"] == "s"
        assert r["adkim"] == "s"
        assert r["rua"] == ["mailto:agg@x.com"]
        assert r["ruf"] == ["mailto:f@x.com"]

    def test_p_none_default_pct(self):
        r = parse_dmarc("v=DMARC1; p=none")
        assert r["dmarc_present"] is True
        assert r["p"] == "none"
        assert r["pct"] == 100  # default

    def test_pct_partial(self):
        r = parse_dmarc("v=DMARC1; p=quarantine; pct=50")
        assert r["pct"] == 50
        assert r["p"] == "quarantine"

    def test_missing_record(self):
        r = parse_dmarc("")
        assert r["dmarc_present"] is False
        assert r["p"] is None
        assert r["pct"] == 100

    def test_invalid_pct_recorded_as_issue(self):
        r = parse_dmarc("v=DMARC1; p=reject; pct=abc")
        assert r["dmarc_present"] is True
        assert any("pct" in i.lower() for i in r["issues"])

    def test_check_dmarc_policy_via_mock(self):
        with patch("scanner.passive.mail_security_parsers._dig",
                   return_value='"v=DMARC1; p=reject; pct=100; rua=mailto:r@x.com"'):
            r = check_dmarc_policy("example.com")
        assert r["dmarc_present"] is True
        assert r["p"] == "reject"


# ---------------------------------------------------------------------------
# parse_nsec3param
# ---------------------------------------------------------------------------
class TestParseNsec3Param:
    def test_iterations_zero_compliant(self):
        r = parse_nsec3param("1 0 0 -")
        assert r["nsec3param_present"] is True
        assert r["iterations"] == 0
        assert r["rfc9276_violation"] is False

    def test_iterations_nonzero_violation(self):
        r = parse_nsec3param("1 0 5 ABCD1234")
        assert r["nsec3param_present"] is True
        assert r["iterations"] == 5
        assert r["rfc9276_violation"] is True

    def test_empty_record(self):
        r = parse_nsec3param("")
        assert r["nsec3param_present"] is False
        assert r["iterations"] is None
        assert r["rfc9276_violation"] is False

    def test_malformed_record(self):
        r = parse_nsec3param("1 0")  # missing iterations field
        assert r["nsec3param_present"] is False
        assert any("malformed" in i.lower() for i in r["issues"])

    def test_check_nsec3_via_mock(self):
        with patch("scanner.passive.mail_security_parsers._dig",
                   return_value="1 0 10 ABCD"):
            r = check_nsec3_iterations("example.com")
        assert r["iterations"] == 10
        assert r["rfc9276_violation"] is True

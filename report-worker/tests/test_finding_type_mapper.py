"""Tests fuer reporter/finding_type_mapper.py."""

import pytest

from reporter.finding_type_mapper import annotate_finding_types, map_finding_type


@pytest.mark.parametrize("finding,expected", [
    # CVE
    ({"title": "Apache Struts RCE", "cve": "CVE-2017-5638"}, "cve_finding"),
    ({"title": "CVE-2024-12345 detected"}, "cve_finding"),
    ({"cve_id": "CVE-2023-9999"}, "cve_finding"),

    # Information Disclosure
    ({"title": ".env file exposed publicly"}, "env_file_exposed"),
    ({"title": ".git directory accessible"}, "git_directory_exposed"),
    ({"title": "phpinfo() page exposed"}, "phpinfo_exposed"),
    ({"title": "Directory listing enabled on /uploads"}, "directory_listing_enabled"),
    ({"description": "Stack trace visible in error page"}, "error_message_with_stack"),
    ({"title": "Nginx status endpoint open"}, "nginx_status_endpoint_open"),
    ({"title": "Server banner reveals nginx 1.18 version"}, "server_banner_with_version"),

    # Cookies
    ({"title": "Cookie without Secure flag missing"}, "cookie_no_secure"),
    ({"title": "Session Cookie HttpOnly attribute fehlt"}, "cookie_no_httponly"),
    ({"description": "Cookie SameSite missing"}, "cookie_no_samesite"),

    # CSP
    ({"title": "CSP unsafe-inline allowed"}, "csp_unsafe_inline"),
    ({"title": "CSP allows unsafe-eval"}, "csp_unsafe_eval"),
    ({"description": "CSP wildcard * in script-src"}, "csp_wildcard_source"),
    ({"title": "Content Security Policy fehlt"}, "csp_missing"),
    ({"title": "CSP not set"}, "csp_missing"),

    # HSTS
    ({"title": "HSTS preload missing"}, "hsts_preload_missing"),
    ({"title": "HSTS includeSubDomains fehlt"}, "hsts_no_includesubdomains"),
    ({"title": "HSTS max-age too short (6 month)"}, "hsts_short_maxage"),
    ({"title": "HSTS not set"}, "hsts_missing"),
    ({"title": "Strict-Transport-Security fehlt"}, "hsts_missing"),

    # Andere Header
    ({"title": "X-Content-Type-Options not set"}, "xcto_missing"),
    ({"title": "X-Frame-Options fehlt"}, "xfo_missing"),
    ({"title": "Referrer-Policy missing"}, "referrer_policy_missing"),
    ({"title": "Permissions-Policy fehlt"}, "permissions_policy_missing"),

    # CSRF
    ({"title": "CSRF token missing on state-change form"}, "csrf_token_missing"),
    ({"description": "Cross-Site Request Forgery vulnerability"}, "csrf_token_missing"),

    # TLS
    ({"title": "TLS 1.0 enabled"}, "tls_below_tr03116_minimum"),
    ({"title": "Weak cipher suite available"}, "tls_weak_cipher_suites"),
    ({"description": "Perfect Forward Secrecy fehlt"}, "tls_no_pfs"),
    ({"title": "Certificate expired"}, "tls_certificate_expired"),
    ({"title": "Self-signed certificate"}, "tls_self_signed"),

    # DNS / Mail
    ({"title": "DNSSEC missing"}, "dnssec_missing"),
    ({"title": "DNSSEC chain broken"}, "dnssec_chain_broken"),
    ({"title": "CAA record missing"}, "caa_missing"),
    ({"title": "SPF softfail (~all)"}, "spf_softfail"),
    ({"title": "SPF record missing for mail domain"}, "spf_missing"),
    ({"title": "DMARC p=none policy"}, "dmarc_p_none"),
    ({"title": "DMARC missing"}, "dmarc_missing"),
    ({"title": "DKIM not configured"}, "dkim_missing"),

    # EOL
    ({"title": "End-of-life software detected"}, "software_eol"),
    ({"description": "PHP 5.6 is unsupported version"}, "software_eol"),
])
def test_map_finding_type(finding, expected):
    assert map_finding_type(finding) == expected


def test_returns_none_for_unmappable():
    assert map_finding_type({"title": "Some random custom thing"}) is None
    assert map_finding_type({}) is None


def test_annotate_skips_already_set():
    findings = [
        {"title": "HSTS missing", "finding_type": "custom_override"},
        {"title": "CSP missing"},
    ]
    annotate_finding_types(findings)
    assert findings[0]["finding_type"] == "custom_override"
    assert findings[1]["finding_type"] == "csp_missing"


def test_real_claude_response_finding():
    """Smoke-Test mit dem realen Fixture-Response."""
    finding = {
        "id": "VS-2026-002",
        "title": "Fehlende Security-Header",
        "severity": "LOW",
        "description": "Mehrere empfohlene Security-Header fehlen: "
                       "X-Frame-Options, Content-Security-Policy, "
                       "Referrer-Policy, Permissions-Policy.",
        "cwe": "CWE-693",
    }
    # Pattern-Reihenfolge bestimmt das Ergebnis — XFO matcht zuerst.
    result = map_finding_type(finding)
    # Akzeptiere alle plausiblen Treffer (XFO/CSP/Referrer/Permissions sind
    # alle "miss"), Hauptsache nicht None
    assert result in {"xfo_missing", "csp_missing", "referrer_policy_missing",
                      "permissions_policy_missing"}

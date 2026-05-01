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

    # ── Deutsche Claude-Output-Strings (Bug #2 Regression-Tests) ──
    # WordPress Plugin/Theme
    ({"title": "Slider Revolution — Authentifiziertes Arbitrary File Read"},
     "wordpress_plugin_vulnerability"),
    ({"title": "Unauthentifizierte Offenlegung privater Inhalte über Complianz-Plugin"},
     "wordpress_plugin_vulnerability"),
    ({"title": "Betheme — Mehrere Stored XSS und PHP Object Injection"},
     "wordpress_plugin_vulnerability"),
    ({"title": "Burst Statistics — Cross-Site Request Forgery"},
     "wordpress_plugin_vulnerability"),
    ({"title": "Yoast SEO authentifizierter SSRF"}, "wordpress_plugin_vulnerability"),
    ({"description": "WooCommerce Plugin XSS Schwachstelle in Cart"},
     "wordpress_plugin_vulnerability"),

    # WordPress User-Enumeration / Login
    ({"title": "WordPress-Login und Benutzerenumeration öffentlich zugänglich"},
     "wordpress_user_enumeration"),
    ({"title": "Generic User Enumeration via WP-JSON"}, "user_enumeration"),

    # Server-Banner mit Version
    ({"title": "Apache-Versionsinformation im Server-Header"},
     "server_banner_with_version"),
    ({"title": "PHP-Versionsinformation preisgegeben"}, "server_banner_with_version"),
    ({"title": "OpenSSH-Version verraet System"}, "server_banner_with_version"),
    ({"description": "Server-Header zeigt Version"}, "server_banner_with_version"),

    # Cookie-Sicherheitsattribute (deutsch)
    ({"title": "Cookie-Sicherheitsattribute fehlen auf Login-Seite"},
     "cookie_no_secure"),
    ({"title": "Secure-Flag fehlt auf Session-Cookie"}, "cookie_no_secure"),
    ({"title": "HttpOnly-Attribut nicht gesetzt"}, "cookie_no_httponly"),
    ({"title": "SameSite-Flag fehlt"}, "cookie_no_samesite"),

    # Header (deutsch)
    ({"title": "Fehlende Security-Header auf der Hauptdomain"}, "xfo_missing"),
    ({"title": "X-Frame-Options nicht gesetzt"}, "xfo_missing"),
    ({"title": "Clickjacking-Schutz fehlt"}, "xfo_missing"),
    ({"title": "Content-Security-Policy nicht gesetzt"}, "csp_missing"),

    # DMARC quarantine (war Lücke!)
    ({"title": "DMARC-Policy auf 'quarantine' statt 'reject'"}, "dmarc_p_quarantine"),
    ({"description": "DMARC p=quarantine konfiguriert"}, "dmarc_p_quarantine"),
    ({"title": "DMARC-Policy auf 'none' — kein E-Mail-Spoofing-Schutz"},
     "dmarc_p_none"),

    # SPF (deutsch)
    ({"title": "SPF mit Softfail (~all) statt Hardfail (-all)"}, "spf_softfail"),
    ({"title": "Kein SPF-Record konfiguriert"}, "spf_missing"),

    # DKIM (deutsch)
    ({"title": "Fehlende DKIM-Konfiguration für E-Mail-Authentifizierung"},
     "dkim_missing"),
    ({"title": "Kein DKIM für E-Mail-Authentifizierung konfiguriert"},
     "dkim_missing"),

    # SSH
    ({"title": "SSH auf nicht-standardmäßigem Port ohne erkennbaren Brute-Force-Schutz"},
     "ssh_no_brute_force_protection"),

    # TLS (deutsch)
    ({"title": "TLS-Zertifikat abgelaufen"}, "tls_certificate_expired"),
    ({"title": "Schwache Cipher-Suiten verfügbar"}, "tls_weak_cipher_suites"),

    # Disclosure (deutsch)
    ({"title": "Verzeichnis-Listing aktiv auf /uploads"},
     "directory_listing_enabled"),
    ({"description": "Stack-Trace in Fehlermeldung sichtbar"},
     "error_message_with_stack"),

    # ── PR1 / M3 — Fallback-Treiber-Patterns (2026-05-01) ──
    # Datenbank-Port-Exposition
    ({"title": "MySQL-Port (3306) auf Subdomain-Host exponiert"},
     "database_port_exposed"),
    ({"title": "MySQL-Datenbank öffentlich erreichbar mit veralteter Version"},
     "database_port_exposed"),
    ({"title": "PostgreSQL-Server publicly accessible"},
     "database_port_exposed"),
    ({"title": "Redis-Service offen auf Port 6379"},
     "database_port_exposed"),
    ({"title": "MongoDB-Datenbank exponiert"},
     "database_port_exposed"),

    # CORS / Cross-Domain
    ({"title": "Cross-Domain-Fehlkonfiguration auf ose.heuel.com"},
     "cors_misconfiguration"),
    ({"description": "CORS Wildcard Access-Control-Allow-Origin"},
     "cors_misconfiguration"),
    ({"title": "Access-Control-Allow-Origin wildcard mit Credentials"},
     "cors_misconfiguration"),

    # JS-Library
    ({"title": "Verwundbare JavaScript-Bibliothek auf ose.heuel.com"},
     "js_library_vulnerable"),
    ({"title": "Veraltete JavaScript-Bibliothek eingebunden"},
     "js_library_vulnerable"),
    ({"description": "Vulnerable JS library jQuery 1.12 bekannte CVE"},
     "js_library_vulnerable"),

    # Private-IP-Disclosure
    ({"title": "Private IP-Adressen in HTTP-Antworten offengelegt"},
     "private_ip_disclosure"),
    ({"title": "Private IP-Adressen in öffentlichen Antworten"},
     "private_ip_disclosure"),
    ({"description": "RFC1918-Adresse 10.0.5.12 leak in Header"},
     "private_ip_disclosure"),

    # SRI
    ({"title": "Fehlende Sub Resource Integrity (SRI) für externe Ressourcen"},
     "sri_missing"),
    ({"title": "Fehlende Sub Resource Integrity (SRI) auf externen Skripten"},
     "sri_missing"),
    ({"description": "SRI-Hash fehlt auf CDN-eingebundenem JS"},
     "sri_missing"),
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

"""Tests fuer B1 — gehaertete finding_type_mapper-Patterns.

Test-Driven aus realen securess.de-Findings die heute SP-FALLBACK landeten.
"""

import pytest
from reporter.finding_type_mapper import map_finding_type


@pytest.mark.parametrize("title,expected", [
    # securess Perim-A
    ("Server- und Technologie-Versionsinformationen in HTTP-Headern",
     "server_banner_with_version"),
    ("Versionsinformationen in HTTP-Headern", "server_banner_with_version"),
    ("Server-Versionsinformationen in HTTP-Headern auf mehreren Hosts",
     "server_banner_with_version"),

    # securess Perim-B
    ("Server-Banner mit Versions-Info auf owa.securess.de",
     "server_banner_with_version"),

    # nginx/apache/iis als Banner-Marker
    ("nginx/1.22.1 detected", "server_banner_with_version"),
    ("Apache/2.4.49 disclosure", "server_banner_with_version"),
    ("PHP/8.4.20 in Header", "server_banner_with_version"),

    # Cookie
    ("Unsichere Cookie-Konfiguration auf dem Webmail-Server",
     "cookie_no_secure"),
    ("Cookie-Konfiguration unsicher", "cookie_no_secure"),
    ("Session-Cookie ohne Secure-Flag auf webmail", "cookie_no_secure"),

    # EOL — neu erweitert
    ("Exchange Server 2016 vor End-of-Life (Oktober 2025)", "software_eol"),
    ("Microsoft Exchange 2016 ohne Sicherheitsupdates", "software_eol"),
    ("Windows Server 2008 ist EOL — Support eingestellt", "software_eol"),

    # Bestehende sollen weiterhin funktionieren
    ("DMARC-Policy auf quarantine statt reject", "dmarc_p_quarantine"),
    ("SPF-Record fehlt fuer x.com", "spf_missing"),
    ("DKIM fehlt", "dkim_missing"),
    ("Subresource-Integrity (SRI) fehlt auf x.com", "sri_missing"),
    ("CSP enthaelt unsafe-inline", "csp_unsafe_inline"),
    ("HSTS-Header fehlt", "hsts_missing"),
])
def test_pattern_matches(title, expected):
    assert map_finding_type({"title": title}) == expected


def test_unknown_falls_back_to_none():
    """Long-Tail bleibt None → KI-Mapper greift in annotate_finding_types."""
    assert map_finding_type({
        "title": "Outlook Web App oeffentlich erreichbar ohne WAF"
    }) is None


def test_cve_in_title_takes_precedence():
    """CVE im Title → cve_finding (alte Regel bleibt)."""
    f = {"title": "CVE-2024-12345 in nginx"}
    assert map_finding_type(f) == "cve_finding"

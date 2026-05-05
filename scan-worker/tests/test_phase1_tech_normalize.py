"""Tests fuer phase1._split_tech_name_version + _extract_all_tech_signals
Datenqualitaet (Mai 2026): Versions-Strings die im Namen statt im
version-Feld stehen werden korrekt gesplittet, Duplikate dedupliziert.
"""

import pytest

from scanner.phase1 import _split_tech_name_version, _extract_all_tech_signals


@pytest.mark.parametrize("name,version,expected_name,expected_version", [
    # Bug-Faelle: Version im Namen
    ("WordPress 6.8.5", "", "WordPress", "6.8.5"),
    ("PHP/8.4.20", "", "PHP", "8.4.20"),
    ("Apache/2.4.49", "", "Apache", "2.4.49"),
    ("nginx 1.22.1", "", "nginx", "1.22.1"),
    ("Microsoft-IIS/10.0", "", "Microsoft-IIS", "10.0"),
    # Bereits korrekt: nichts aendern
    ("nginx", "1.22.1", "nginx", "1.22.1"),
    ("WordPress", "6.8.5", "WordPress", "6.8.5"),
    # Keine Version drin: Namen unveraendert
    ("WordPress", "", "WordPress", ""),
    ("Cloudflare", "", "Cloudflare", ""),
    # Single-Digit-"Versionen" werden NICHT extrahiert (zu unsicher)
    ("Next.js 14", "", "Next.js 14", ""),
    ("Bootstrap 5", "", "Bootstrap 5", ""),
])
def test_split_tech_name_version(name, version, expected_name, expected_version):
    assert _split_tech_name_version(name, version) == (expected_name, expected_version)


def test_extract_dedup_with_version_winning():
    """Wenn dasselbe Tech 2x auftaucht (1x mit Version, 1x ohne):
    Version-Variante gewinnt, kein doppelter Eintrag."""
    redirect_data = {
        "x.com": {
            "tech_info": {"generator": "WordPress 6.8.5"},
            "response_headers": {"server": "nginx/1.22.1"},
        },
        "y.com": {
            "tech_info": {"generator": "WordPress"},
            "response_headers": {"server": "nginx/1.29.5"},
        },
    }
    out = _extract_all_tech_signals(redirect_data)
    names = [t["name"].lower() for t in out]
    # Nur EIN WordPress, EIN nginx
    assert names.count("wordpress") == 1
    assert names.count("nginx") == 1
    # WordPress hat Version (extrahiert aus Bug-Daten)
    wp = next(t for t in out if t["name"].lower() == "wordpress")
    assert wp["version"] == "6.8.5"
    # nginx hat ERSTE gesehene Version (1.22.1)
    ng = next(t for t in out if t["name"].lower() == "nginx")
    assert ng["version"] == "1.22.1"


def test_extract_php_powered_by_split():
    """X-Powered-By: PHP/8.4.20 — wird gesplittet."""
    redirect_data = {
        "x.com": {
            "tech_info": {},
            "response_headers": {"x-powered-by": "PHP/8.4.20"},
        },
    }
    out = _extract_all_tech_signals(redirect_data)
    php = [t for t in out if t["name"].lower() == "php"]
    assert len(php) == 1
    assert php[0]["version"] == "8.4.20"


def test_extract_handles_empty_input():
    assert _extract_all_tech_signals({}) == []
    assert _extract_all_tech_signals(None) == []


def test_extract_no_double_wordpress():
    """User-Bug: bisher kamen 2 WordPress-Eintraege ('WordPress 6.8.5' +
    'WordPress' aus Cookie-Pattern). Jetzt: 1 sauberer Eintrag."""
    redirect_data = {
        "x.com": {
            "tech_info": {
                "generator": "WordPress 6.8.5",
                "cookies": "wordpress_logged_in=abc",
            },
            "response_headers": {},
        },
    }
    out = _extract_all_tech_signals(redirect_data)
    wp_entries = [t for t in out if "wordpress" in t["name"].lower()]
    assert len(wp_entries) == 1
    assert wp_entries[0]["name"] == "WordPress"
    assert wp_entries[0]["version"] == "6.8.5"

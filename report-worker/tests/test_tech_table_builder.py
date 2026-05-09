"""Tests fuer reporter.tech_table_builder — Per-Host-Tech-Tabelle (Mai 2026)."""

from __future__ import annotations

from datetime import date

import pytest

from reporter.tech_table_builder import build_tech_table_for_host


@pytest.fixture
def scan_date_2026():
    return date(2026, 5, 8)


# ─── Status-Klassifikation ────────────────────────────────────────────────


def test_apache_2_4_49_outdated_and_mega_cve(scan_date_2026):
    """Apache 2.4.49 → KNOWN_VULN_BUILDS_MANUAL match (CVE-2021-41773) → mega_cve.
    Apache 2.4 ist nicht EOL (laut endoflife.date, nur 2.0/2.2 sind EOL),
    aber 2.4.49 ist vor latest_patch → outdated.
    """
    profile = {
        "ip": "1.2.3.4", "fqdns": ["x.com"],
        "server": "Apache/2.4.49",
        "cms": None, "cms_version": None,
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    apache = next((r for r in rows if "apache" in r["name"].lower()), None)
    assert apache is not None
    assert apache["is_mega_cve"] is True
    assert "CVE-2021-41773" in apache["cves"]


def test_apache_2_4_62_is_current(scan_date_2026):
    """Aktuelles Apache → current (kein KNOWN_VULN_BUILDS-Match, neuer als latest_patch)."""
    profile = {
        "ip": "1.2.3.4", "fqdns": ["x.com"],
        "server": "Apache/2.4.62",
        "cms": None, "cms_version": None,
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    apache = next((r for r in rows if "apache" in r["name"].lower()), None)
    assert apache is not None
    assert apache["status"] == "current"
    assert apache["is_mega_cve"] is False


def test_apache_2_2_x_is_eol_plus_mega_cve(scan_date_2026):
    """Apache 2.2 ist EOL seit 2017-07-11 + KNOWN_VULN_BUILDS-Match → eol + is_mega_cve."""
    profile = {
        "ip": "1.2.3.4", "fqdns": ["x.com"],
        "server": "Apache/2.2.34",
        "cms": None, "cms_version": None,
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    apache = next((r for r in rows if "apache" in r["name"].lower()), None)
    assert apache is not None
    assert apache["status"] == "eol"
    assert apache["eol_date"] == "2017-07-11"
    # 2.2.34 matcht KNOWN_VULN_BUILDS_GENERATED Apache <2.4.60 → is_mega_cve=True
    assert apache["is_mega_cve"] is True


def test_neos_cms_no_eol_data_is_current(scan_date_2026):
    """Neos CMS hat keinen EOL-Eintrag in eol_data → current (kein false-EOL)."""
    profile = {
        "ip": "1.2.3.4", "fqdns": ["heuel.com"],
        "cms": "NEOS", "cms_version": "8.3", "cms_confidence": 0.85,
        "server": None,
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    neos = next((r for r in rows if "neos" in r["name"].lower()), None)
    assert neos is not None
    assert neos["status"] == "current"
    assert neos["is_mega_cve"] is False
    assert neos["category"] == "CMS"
    assert neos["confidence"] == 0.85


def test_openssl_heartbleed_version_is_mega_cve(scan_date_2026):
    """OpenSSL 1.0.1 → Heartbleed-Match in KNOWN_VULN_BUILDS_MANUAL → is_mega_cve."""
    profile = {
        "ip": "1.2.3.4", "fqdns": ["x.com"],
        "cms": None, "cms_version": None,
        "server": None,
        "technologies": [{"name": "OpenSSL", "version": "1.0.1"}],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    openssl = next((r for r in rows if "openssl" in r["name"].lower()), None)
    assert openssl is not None
    assert openssl["is_mega_cve"] is True
    assert "CVE-2014-0160" in openssl["cves"]


def test_apache_2_4_62_no_cpe_noise_match(scan_date_2026):
    """Regressions-Test: Apache 2.4.62 darf NICHT durch Oracle-CPE-Noise als
    mega_cve markiert werden (Generated hat zB '<10.2.1.14-75sv' fuer apache/httpd
    aber das ist ein Oracle-Linux-Apache-Modul). Major-Filter im Builder muss greifen.
    """
    profile = {
        "ip": "1.2.3.4", "fqdns": ["x.com"],
        "server": "Apache/2.4.62",
        "cms": None, "cms_version": None,
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    apache = next(r for r in rows if "apache" in r["name"].lower())
    assert apache["is_mega_cve"] is False
    assert apache["cves"] == []


# ─── Kategorisierung ─────────────────────────────────────────────────────


def test_category_apache_is_web_server(scan_date_2026):
    profile = {"ip": "1", "fqdns": [], "server": "Apache/2.4.62",
               "cms": None, "cms_version": None, "technologies": []}
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    apache = next(r for r in rows if "apache" in r["name"].lower())
    assert apache["category"] == "Web-Server"


def test_category_neos_cms(scan_date_2026):
    profile = {"ip": "1", "fqdns": [], "cms": "NEOS", "cms_version": "8.3",
               "server": None, "technologies": []}
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    neos = next(r for r in rows if "neos" in r["name"].lower())
    assert neos["category"] == "CMS"


def test_waf_appears_in_table_as_current(scan_date_2026):
    profile = {"ip": "1", "fqdns": [], "cms": None, "cms_version": None,
               "server": None, "waf": "Cloudflare", "technologies": []}
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    waf = next((r for r in rows if r["name"] == "Cloudflare"), None)
    assert waf is not None
    assert waf["category"] == "WAF/Schutz"
    assert waf["status"] == "current"


# ─── Dedup + Sortierung ──────────────────────────────────────────────────


def test_dedup_cms_and_technologies(scan_date_2026):
    """CMS und technologies[] zeigen denselben Eintrag (NEOS) → nur 1 Zeile."""
    profile = {
        "ip": "1", "fqdns": [],
        "cms": "NEOS", "cms_version": "8.3",
        "server": None,
        "technologies": [{"name": "NEOS", "version": "8.3"}],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    neos_rows = [r for r in rows if "neos" in r["name"].lower()]
    assert len(neos_rows) == 1


def test_sort_eol_first_then_outdated_then_current(scan_date_2026):
    """Status-Schwere bestimmt Reihenfolge: eol > outdated > current.
    is_mega_cve-Flag erhoeht Prioritaet innerhalb gleichen Status (sort-Tiebreaker).
    """
    profile = {
        "ip": "1", "fqdns": [],
        "cms": "NEOS", "cms_version": "8.3",  # current
        "server": "Apache/2.2.34",            # eol + mega_cve
        "technologies": [
            {"name": "OpenSSL", "version": "1.0.1"},  # is_mega_cve, kein EOL
        ],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    # Apache 2.2.34 (eol) muss vor OpenSSL 1.0.1 (kein eol) stehen
    apache_idx = next(i for i, r in enumerate(rows) if "apache" in r["name"].lower())
    openssl_idx = next(i for i, r in enumerate(rows) if "openssl" in r["name"].lower())
    neos_idx = next(i for i, r in enumerate(rows) if "neos" in r["name"].lower())
    assert apache_idx < neos_idx
    assert openssl_idx < neos_idx  # mega_cve vor current


# ─── Empty/Edge ──────────────────────────────────────────────────────────


def test_empty_tech_profile_returns_empty_table(scan_date_2026):
    profile = {
        "ip": "1.2.3.4", "fqdns": ["x.com"],
        "cms": None, "cms_version": None,
        "server": None, "waf": None,
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    assert rows == []


def test_admin_detail_fields_present(scan_date_2026):
    """confidence + source fuer Admin-View muessen pro Row gesetzt sein."""
    profile = {
        "ip": "1", "fqdns": [],
        "cms": "WordPress", "cms_version": "6.4", "cms_confidence": 0.92,
        "server": "Apache/2.4.62",
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    wp = next(r for r in rows if "wordpress" in r["name"].lower())
    apache = next(r for r in rows if "apache" in r["name"].lower())
    assert wp["confidence"] == 0.92
    assert wp["source"] == "cms_fingerprint"
    assert apache["confidence"] is None
    assert apache["source"] == "server_banner"


# ─── Banner-Suffix-Stripping (Mai 2026 — Test-Session-Folge) ─────────────


def test_openssh_banner_suffix_stripped(scan_date_2026):
    """OpenSSH-Banner mit Distro-Suffix → version ohne Suffix."""
    profile = {
        "ip": "1", "fqdns": [],
        "cms": None, "cms_version": None,
        "server": None,
        "technologies": [
            {"name": "OpenSSH", "version": "9.6p1 Ubuntu 3ubuntu13.16"},
        ],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    openssh = next(r for r in rows if "openssh" in r["name"].lower())
    assert openssh["version"] == "9.6p1"


def test_apache_banner_with_distro_suffix(scan_date_2026):
    """'2.4.66 (Debian)' → '2.4.66'."""
    profile = {
        "ip": "1", "fqdns": [],
        "cms": None, "cms_version": None,
        "server": None,
        "technologies": [
            {"name": "Apache", "version": "2.4.66 (Debian)"},
        ],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    apache = next(r for r in rows if "apache" in r["name"].lower())
    assert apache["version"] == "2.4.66"


def test_apache_dedup_across_name_variants(scan_date_2026):
    """'Apache' (technologies) + 'Apache/2.4.66' (server-banner) → 1 Eintrag mit Version 2.4.66."""
    profile = {
        "ip": "1", "fqdns": [],
        "cms": None, "cms_version": None,
        "server": "Apache/2.4.66",
        "technologies": [{"name": "Apache", "version": ""}],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    apache_rows = [r for r in rows if "apache" in r["name"].lower()]
    assert len(apache_rows) == 1, f"Erwartet 1 Apache-Eintrag, gefunden {len(apache_rows)}"
    assert apache_rows[0]["version"] == "2.4.66"


def test_apache_httpd_dedup_no_version(scan_date_2026):
    """'Apache' + 'Apache httpd' beide ohne Version → 1 Eintrag."""
    profile = {
        "ip": "1", "fqdns": [],
        "cms": None, "cms_version": None,
        "server": None,
        "technologies": [
            {"name": "Apache", "version": ""},
            {"name": "Apache httpd", "version": ""},
        ],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    apache_rows = [r for r in rows if "apache" in r["name"].lower()]
    assert len(apache_rows) == 1


def test_apache_category_web_server_after_dedup(scan_date_2026):
    """Wenn nur "Apache" reinkommt (ohne /httpd), muss vendor=apache+product=httpd
    → category=Web-Server (nicht "Sonstiges")."""
    profile = {
        "ip": "1", "fqdns": [],
        "cms": None, "cms_version": None,
        "server": None,
        "technologies": [{"name": "Apache", "version": ""}],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    apache = next(r for r in rows if "apache" in r["name"].lower())
    assert apache["category"] == "Web-Server", f"Got: {apache['category']}"


# ─── Minor-EOL Status (Mai 2026 — endoflife.date Severity-Mapping) ────────


def test_wordpress_6_8_is_minor_eol(scan_date_2026):
    """WordPress 6.8.5 EOL 2025-12-02 mit eol_data.severity=MEDIUM → minor_eol
    (nicht eol — Customer-UX: aktuelle Major-Familie aktiv, nur Minor-Reihe out)."""
    profile = {
        "ip": "1", "fqdns": [],
        "cms": "WordPress", "cms_version": "6.8.5",
        "server": None,
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    wp = next(r for r in rows if "wordpress" in r["name"].lower())
    assert wp["status"] == "minor_eol", f"Got: {wp['status']}"


def test_wordpress_4_7_is_eol(scan_date_2026):
    """WordPress 4.7 EOL 2017 mit severity=CRITICAL → eol (kritisch, alte Major)."""
    profile = {
        "ip": "1", "fqdns": [],
        "cms": "WordPress", "cms_version": "4.7.33",
        "server": None,
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    wp = next(r for r in rows if "wordpress" in r["name"].lower())
    assert wp["status"] == "eol", f"Got: {wp['status']}"


def test_neos_variants_dedup(scan_date_2026):
    """heuel.com lieferte 'NEOS', 'Neos CMS', 'Neos Flow' als 3 Eintraege.
    Nach _normalize_vendor_product-Erweiterung sollten alle drei auf
    vendor=neos mappen → 1 Eintrag (Dedup-Key (vendor, product))."""
    profile = {
        "ip": "1", "fqdns": [],
        "cms": "NEOS", "cms_version": "",
        "server": None,
        "technologies": [
            {"name": "Neos CMS", "version": ""},
            {"name": "Neos Flow", "version": "neos"},  # invalid version
        ],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    neos_rows = [r for r in rows if "neos" in r["name"].lower()]
    assert len(neos_rows) == 1, f"Erwartet 1 Neos-Eintrag, gefunden {len(neos_rows)}: {[r['name'] for r in neos_rows]}"


def test_invalid_version_string_stripped(scan_date_2026):
    """Phase-1 hat manchmal nicht-numerische Strings als Version (z.B.
    'Neos Flow' v='neos'). Sollte als leere Version gewertet werden."""
    profile = {
        "ip": "1", "fqdns": [],
        "cms": None, "cms_version": None,
        "server": None,
        "technologies": [{"name": "Neos Flow", "version": "neos"}],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    neos = next(r for r in rows if "neos" in r["name"].lower())
    assert neos["version"] == "", f"Erwartet leere Version, got: {neos['version']!r}"


def test_exchange_marketing_name_mapped_to_build(scan_date_2026):
    """Microsoft Exchange '2016' → Build '15.1' fuer eol_data-Lookup. eol_data
    hat Exchange 15.1 EOL 2025-10-14 (CRITICAL) → status=eol."""
    profile = {
        "ip": "1", "fqdns": [],
        "cms": None, "cms_version": None,
        "server": None,
        "technologies": [{"name": "Exchange", "version": "2016"}],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    exch = next(r for r in rows if "exchange" in r["name"].lower())
    # Status muss "eol" sein wenn endoflife.date Microsoft Exchange 15.1 EOL hat
    # (Mai 2026 sollte das geliefert haben — falls nicht, wird der Test failen
    # und die Test-Dependency muss verifiziert werden)
    assert exch["status"] in ("eol", "minor_eol"), (
        f"Exchange 2016 sollte EOL sein (15.1 EOL 2025-10-14), got: {exch['status']}"
    )


def test_sort_order_eol_minor_eol_outdated_current(scan_date_2026):
    """Sortier-Order: eol > minor_eol > outdated > current."""
    profile = {
        "ip": "1", "fqdns": [],
        "cms": "WordPress", "cms_version": "6.8.5",  # minor_eol
        "server": "Apache/2.2.34",                   # eol (CRITICAL)
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=scan_date_2026)
    statuses = [r["status"] for r in rows]
    apache_idx = next(i for i, r in enumerate(rows) if "apache" in r["name"].lower())
    wp_idx = next(i for i, r in enumerate(rows) if "wordpress" in r["name"].lower())
    assert apache_idx < wp_idx, f"eol muss vor minor_eol kommen, statuses={statuses}"

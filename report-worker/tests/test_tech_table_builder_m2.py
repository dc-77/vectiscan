"""M2 Track 2c — Tech-Table umstrukturieren.

Tests fuer die in M2 hinzugefuegten Filter + Spalten im
`reporter.tech_table_builder`:
- Kernel-Detection-Blacklist (P2-04)
- Min-Public-Version-Whitelist (P1-05)
- Neue Spalten (detection_source, confidence_label, patch_status,
  eol_date, top_cve)
"""
from __future__ import annotations

from datetime import date

from reporter.tech_table_builder import (
    KERNEL_DETECTION_BLACKLIST,
    MIN_PUBLIC_VERSIONS,
    build_tech_table_for_host,
)


# ─── Kernel-Blacklist ────────────────────────────────────────────────────


def test_kernel_blacklist_removes_httpapi():
    """HTTPAPI/2.0 ist Windows-Kernel — darf nicht in der Tech-Tabelle stehen."""
    profile = {
        "ip": "1.2.3.4",
        "technologies": [
            {"name": "Microsoft HTTPAPI httpd", "version": "2.0"},
            {"name": "Apache", "version": "2.4.49"},
        ],
    }
    rows = build_tech_table_for_host(profile)
    names = {(r.get("name") or "").lower() for r in rows}
    assert "microsoft httpapi httpd" not in names
    # Apache muss als legitime Software durchgehen
    assert any("apache" in n for n in names)


def test_kernel_blacklist_constant_present():
    """Die Blacklist-Konstante muss exportiert sein (PDF-Renderer-Hook)."""
    assert "httpapi" in KERNEL_DETECTION_BLACKLIST
    assert "http.sys" in KERNEL_DETECTION_BLACKLIST


def test_kernel_blacklist_handles_dash_variant():
    """microsoft-httpapi als Substring-Match."""
    profile = {
        "ip": "1.2.3.4",
        "technologies": [
            {"name": "Microsoft-HTTPAPI/2.0", "version": ""},
        ],
    }
    rows = build_tech_table_for_host(profile)
    names = {(r.get("name") or "").lower() for r in rows}
    assert not any("httpapi" in n for n in names)


# ─── Min-Public-Version-Whitelist ────────────────────────────────────────


def test_bootstrap_v1_marked_unknown():
    """Bootstrap 1 wurde nie released — Version muss als unbekannt markiert sein."""
    profile = {
        "ip": "1.2.3.4",
        "technologies": [{"name": "Bootstrap", "version": "1"}],
    }
    rows = build_tech_table_for_host(profile)
    bt = [r for r in rows if (r.get("name") or "").lower() == "bootstrap"]
    assert bt, "Bootstrap-Row sollte vorhanden sein (nur Version unbekannt markiert)"
    assert bt[0].get("patch_status") == "unbekannt"
    assert "unbekannt" in (bt[0].get("version") or "").lower()


def test_jquery_v0_marked_unknown():
    """jQuery 0.x ist sub-min-public — als unbekannt markieren."""
    profile = {
        "ip": "1.2.3.4",
        "technologies": [{"name": "jQuery", "version": "0.9"}],
    }
    rows = build_tech_table_for_host(profile)
    jq = [r for r in rows if (r.get("name") or "").lower() == "jquery"]
    assert jq
    assert jq[0].get("patch_status") == "unbekannt"


def test_min_public_versions_constant_exported():
    """Die Whitelist-Konstante muss exportiert sein."""
    assert MIN_PUBLIC_VERSIONS["bootstrap"] == 2
    assert "jquery" in MIN_PUBLIC_VERSIONS


# ─── Neue Spalten ────────────────────────────────────────────────────────


def test_column_split_present():
    """tech_row muss neue M2-Spalten haben (auch wenn Werte default sind)."""
    profile = {
        "ip": "1.2.3.4",
        "technologies": [{"name": "OpenSSH", "version": "7.4"}],
    }
    rows = build_tech_table_for_host(profile)
    if rows:
        r = rows[0]
        for key in ("detection_source", "confidence_label", "patch_status",
                    "eol_date", "top_cve"):
            assert key in r, f"missing column: {key}"


def test_patch_status_aktuell_for_current():
    """Apache 2.4.62 → status=current → patch_status='aktuell'."""
    profile = {
        "ip": "1.2.3.4",
        "server": "Apache/2.4.62",
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=date(2026, 5, 8))
    apache = next((r for r in rows if "apache" in (r.get("name") or "").lower()), None)
    if apache:
        assert apache["patch_status"] == "aktuell"
        # status (deprecated alias) zeigt internen Wert weiter
        assert apache["status"] == "current"


def test_top_cve_none_when_no_cves():
    """Keine CVEs → top_cve=None (statt fehlend)."""
    profile = {
        "ip": "1.2.3.4",
        "server": "Apache/2.4.62",
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=date(2026, 5, 8))
    for r in rows:
        if not r.get("cves"):
            assert r.get("top_cve") is None


def test_confidence_label_mapping():
    """CMS-Confidence 0.9 → 'hoch'."""
    profile = {
        "ip": "1.2.3.4",
        "cms": "WordPress",
        "cms_version": "6.4.2",
        "cms_confidence": 0.9,
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=date(2026, 5, 8))
    wp = next((r for r in rows if "wordpress" in (r.get("name") or "").lower()), None)
    if wp:
        assert wp.get("confidence_label") == "hoch"


# ─── Backwards-Compat ────────────────────────────────────────────────────


def test_status_alias_still_present():
    """Deprecated 'status' bleibt fuer Backwards-Compat (alter PDF-Renderer)."""
    profile = {
        "ip": "1.2.3.4",
        "server": "Apache/2.4.49",
        "technologies": [],
    }
    rows = build_tech_table_for_host(profile, scan_date=date(2026, 5, 8))
    if rows:
        for r in rows:
            assert "status" in r, "deprecated status-alias muss erhalten bleiben"

"""Tests fuer den deterministischen CVE-Referenz-Guard (VEC-377)."""

from __future__ import annotations

from reporter.cve_guard import (
    UNVERIFIED_MARKER,
    apply_cve_guard,
    build_allowlist,
)


# ---------------------------------------------------------------------------
# build_allowlist
# ---------------------------------------------------------------------------

def test_allowlist_from_enrichment_keys():
    enrichment = {
        "CVE-2024-6387": {"nvd": {"cve_id": "CVE-2024-6387"}},
        "CVE-2021-44228": {"epss": {"epss": 0.97}},
    }
    allow = build_allowlist(enrichment)
    assert "CVE-2024-6387" in allow
    assert "CVE-2021-44228" in allow


def test_allowlist_includes_curated_builds():
    # known_vuln_builds_generated enthaelt u.a. CVE-2024-38475 (Apache)
    allow = build_allowlist(None)
    assert "CVE-2024-38475" in allow
    # eol_detector manual: Heartbleed
    assert "CVE-2014-0160" in allow


def test_allowlist_ignores_non_cve_keys():
    allow = build_allowlist({"not-a-cve": {}, "CVE-2020-0001": {}})
    assert "CVE-2020-0001" in allow
    assert "not-a-cve" not in allow


def test_allowlist_handles_none_and_garbage():
    assert isinstance(build_allowlist(None), set)
    assert isinstance(build_allowlist([]), set)
    assert isinstance(build_allowlist("nonsense"), set)


# ---------------------------------------------------------------------------
# Halluzinierte CVE wird gestrichen
# ---------------------------------------------------------------------------

def test_hallucinated_cve_in_description_replaced():
    out = {
        "findings": [{
            "id": "VS-2026-001",
            "title": "Betheme 27.4.5 Remote Code Execution",
            "description": "Das Theme Betheme 27.4.5 ist anfaellig (CVE-2099-99999).",
        }],
    }
    stats = apply_cve_guard(out, enrichment={})
    desc = out["findings"][0]["description"]
    assert "CVE-2099-99999" not in desc
    assert UNVERIFIED_MARKER in desc
    # Vulnerability-Klasse bleibt erhalten
    assert "Betheme 27.4.5" in desc
    assert stats["removed_count"] == 1
    assert stats["distinct_removed"] == ["CVE-2099-99999"]


def test_verified_cve_kept_unchanged():
    out = {
        "findings": [{
            "id": "VS-2026-001",
            "title": "OpenSSH regreSSHion",
            "description": "Anfaellig fuer CVE-2024-6387 (RCE).",
        }],
    }
    enrichment = {"CVE-2024-6387": {"nvd": {"cve_id": "CVE-2024-6387"}}}
    stats = apply_cve_guard(out, enrichment=enrichment)
    assert "CVE-2024-6387" in out["findings"][0]["description"]
    assert stats["removed_count"] == 0


def test_mixed_verified_and_hallucinated():
    out = {
        "findings": [{
            "id": "VS-2026-001",
            "title": "T",
            "description": "Echt: CVE-2024-6387. Erfunden: CVE-2099-12345.",
        }],
    }
    enrichment = {"CVE-2024-6387": {"nvd": {"cve_id": "CVE-2024-6387"}}}
    stats = apply_cve_guard(out, enrichment=enrichment)
    desc = out["findings"][0]["description"]
    assert "CVE-2024-6387" in desc
    assert "CVE-2099-12345" not in desc
    assert UNVERIFIED_MARKER in desc
    assert stats["removed_count"] == 1


def test_parenthesized_cve_reads_cleanly():
    out = {
        "findings": [{
            "id": "X", "title": "RCE-Schwachstelle (CVE-2099-00001)",
        }],
    }
    apply_cve_guard(out, enrichment={})
    assert out["findings"][0]["title"] == f"RCE-Schwachstelle ({UNVERIFIED_MARKER})"


# ---------------------------------------------------------------------------
# title_vars + weitere Felder
# ---------------------------------------------------------------------------

def test_title_vars_cve_id_stripped_when_unverified():
    out = {
        "findings": [{
            "id": "X", "title": "T",
            "title_vars": {"host": "x.de", "cve_id": "CVE-2099-55555"},
        }],
    }
    apply_cve_guard(out, enrichment={})
    assert "cve_id" not in out["findings"][0]["title_vars"]
    assert out["findings"][0]["title_vars"]["host"] == "x.de"


def test_title_vars_cve_id_kept_when_verified():
    out = {
        "findings": [{
            "id": "X", "title": "T",
            "title_vars": {"cve_id": "CVE-2024-6387"},
        }],
    }
    apply_cve_guard(out, enrichment={"CVE-2024-6387": {"nvd": {}}})
    assert out["findings"][0]["title_vars"]["cve_id"] == "CVE-2024-6387"


def test_additional_findings_and_overall_description_scrubbed():
    out = {
        "findings": [],
        "additional_findings_summary": [
            {"id": "A", "title": "X", "recommendation": "Patch fuer CVE-2099-00002 einspielen."},
        ],
        "overall_description": "Kritisch: CVE-2099-00003 betrifft den Host.",
    }
    stats = apply_cve_guard(out, enrichment={})
    assert "CVE-2099-00002" not in out["additional_findings_summary"][0]["recommendation"]
    assert "CVE-2099-00003" not in out["overall_description"]
    assert stats["removed_count"] == 2


# ---------------------------------------------------------------------------
# Robustheit
# ---------------------------------------------------------------------------

def test_empty_and_missing_fields():
    stats = apply_cve_guard({"findings": []}, enrichment=None)
    assert stats["removed_count"] == 0
    stats2 = apply_cve_guard({}, enrichment=None)
    assert stats2["removed_count"] == 0


def test_case_insensitive_match():
    out = {"findings": [{"id": "X", "title": "lower cve-2099-00009 hier"}]}
    stats = apply_cve_guard(out, enrichment={})
    assert "cve-2099-00009" not in out["findings"][0]["title"].lower()
    assert stats["removed_count"] == 1


def test_curated_cve_in_text_not_stripped():
    # CVE-2014-0160 (Heartbleed) ist kuratiert → bleibt auch ohne enrichment
    out = {"findings": [{"id": "X", "title": "Heartbleed CVE-2014-0160"}]}
    stats = apply_cve_guard(out, enrichment={})
    assert "CVE-2014-0160" in out["findings"][0]["title"]
    assert stats["removed_count"] == 0


def test_stats_distinct_dedup():
    out = {
        "findings": [
            {"id": "A", "title": "CVE-2099-11111"},
            {"id": "B", "title": "auch CVE-2099-11111"},
        ],
    }
    stats = apply_cve_guard(out, enrichment={})
    assert stats["removed_count"] == 2
    assert stats["distinct_removed"] == ["CVE-2099-11111"]

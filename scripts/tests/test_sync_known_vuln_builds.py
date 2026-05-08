"""Tests fuer scripts/sync-known-vuln-builds.py (F-RPT-001).

Aufruf:
    python -m pytest scripts/tests/test_sync_known_vuln_builds.py -v

Mockt urllib + KEV-Fetch — keine echten Netzwerk-Calls.

Mai 2026 (Bug #6): /v1/query lieferte HTTP 400 fuer Server-Software ohne
Ecosystem. Script wurde auf KEV-driven /v1/vulns/{cve} umgestellt.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


# Lokaler Import — Skript hat Bindestrich, daher ueber importlib.
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SCRIPTS_DIR))

_SCRIPT_PATH = _SCRIPTS_DIR / "sync-known-vuln-builds.py"
_SPEC = importlib.util.spec_from_file_location(
    "sync_known_vuln_builds", _SCRIPT_PATH,
)
sync_known_vuln_builds = importlib.util.module_from_spec(_SPEC)  # type: ignore[arg-type]
sys.modules["sync_known_vuln_builds"] = sync_known_vuln_builds
_SPEC.loader.exec_module(sync_known_vuln_builds)  # type: ignore[union-attr]


# ─────────────────────────────────────────────────────────────────────────────
# 1. KEV-Fetch: liefert komplettes JSON-Document
# ─────────────────────────────────────────────────────────────────────────────

def test_fetch_kev_data_returns_full_doc():
    fake_kev = {
        "title": "CISA Catalog",
        "vulnerabilities": [
            {"cveID": "CVE-2023-25690", "vendorProject": "Apache",
             "product": "HTTP Server"},
            {"cveID": "CVE-2024-21762", "vendorProject": "Fortinet",
             "product": "FortiOS"},
        ],
    }
    with patch.object(sync_known_vuln_builds, "fetch_with_retry",
                      return_value=json.dumps(fake_kev)):
        data = sync_known_vuln_builds.fetch_kev_data()
    assert data["title"] == "CISA Catalog"
    assert len(data["vulnerabilities"]) == 2


def test_kev_cve_set_uppercase_filter():
    """kev_cve_set normalisiert IDs auf uppercase + filtert Garbage."""
    data = {"vulnerabilities": [
        {"cveID": "cve-2024-21762"},
        {"cveID": "  CVE-2024-1709  "},
        {"cveID": "GHSA-xxxx-yyyy-zzzz"},  # nicht-CVE
        {},
    ]}
    out = sync_known_vuln_builds.kev_cve_set(data)
    assert out == {"CVE-2024-21762", "CVE-2024-1709"}


def test_kev_cves_for_vendor_substring_match():
    """case-insensitiver substring-Match auf vendorProject + product."""
    data = {"vulnerabilities": [
        {"cveID": "CVE-2023-25690", "vendorProject": "Apache",
         "product": "HTTP Server"},
        {"cveID": "CVE-2024-21762", "vendorProject": "Fortinet",
         "product": "FortiOS"},
        {"cveID": "CVE-2024-1709",  "vendorProject": "ConnectWise",
         "product": "ScreenConnect"},
    ]}
    apache = sync_known_vuln_builds.kev_cves_for_vendor(data, "apache", "http server")
    assert [c[0] for c in apache] == ["CVE-2023-25690"]

    fortinet = sync_known_vuln_builds.kev_cves_for_vendor(data, "fortinet", "fortios")
    assert [c[0] for c in fortinet] == ["CVE-2024-21762"]

    # leeres product-match -> alle Vendor-Eintraege
    apache_all = sync_known_vuln_builds.kev_cves_for_vendor(data, "apache", "")
    assert [c[0] for c in apache_all] == ["CVE-2023-25690"]


# ─────────────────────────────────────────────────────────────────────────────
# 2. _range_specs_from_vuln: ECOSYSTEM-events vs database_specific.versions
# ─────────────────────────────────────────────────────────────────────────────

def test_range_specs_extracts_fixed_from_ecosystem_events():
    """Versions-like events.fixed -> "<fixed"-Spec (klassischer /v1/query-Pfad)."""
    vuln = {
        "id": "CVE-2023-25690",
        "affected": [{
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "2.4.0"},
                    {"fixed": "2.4.56"},
                ],
            }],
        }],
    }
    assert sync_known_vuln_builds._range_specs_from_vuln(vuln) == ["<2.4.56"]


def test_range_specs_extracts_last_affected_from_events():
    vuln = {
        "id": "CVE-X-2024-9999",
        "affected": [{
            "ranges": [{
                "events": [
                    {"introduced": "1.0"},
                    {"last_affected": "1.5.2"},
                ],
            }],
        }],
    }
    assert sync_known_vuln_builds._range_specs_from_vuln(vuln) == ["<=1.5.2"]


def test_range_specs_falls_back_to_database_specific_versions():
    """GIT-type events haben Commit-Hashes — Fallback auf database_specific.versions
    (typischer /v1/vulns/{id}-Pfad fuer Server-Software).
    """
    vuln = {
        "id": "CVE-2023-25690",
        "affected": [{
            "ranges": [{
                "type": "GIT",
                "repo": "https://github.com/apache/httpd",
                "events": [
                    {"introduced": "da5873e80d6eee7a0838793bf68f1d0254745fbb"},
                    {"last_affected": "8201e867f1d4cdf61840625c6c4be901e3f1b6ba"},
                ],
                "database_specific": {
                    "versions": [
                        {"introduced": "2.4.0"},
                        {"last_affected": "2.4.55"},
                    ],
                },
            }],
        }],
    }
    assert sync_known_vuln_builds._range_specs_from_vuln(vuln) == ["<=2.4.55"]


def test_range_specs_empty_when_no_versions_anywhere():
    """Weder events noch database_specific haben Versions -> leere Liste."""
    vuln = {
        "id": "CVE-X",
        "affected": [{
            "ranges": [{
                "type": "GIT",
                "events": [
                    {"introduced": "abc123"},
                    {"last_affected": "def456"},
                ],
            }],
        }],
    }
    assert sync_known_vuln_builds._range_specs_from_vuln(vuln) == []


# ─────────────────────────────────────────────────────────────────────────────
# 3. fetch_osv_vuln_by_cve: 404 -> None, parses JSON
# ─────────────────────────────────────────────────────────────────────────────

def test_fetch_osv_vuln_by_cve_returns_none_on_404():
    import urllib.error
    with patch.object(sync_known_vuln_builds.urllib.request, "urlopen",
                      side_effect=urllib.error.HTTPError(
                          url="x", code=404, msg="Not Found",
                          hdrs=None, fp=None)):
        assert sync_known_vuln_builds.fetch_osv_vuln_by_cve("CVE-9999-9999") is None


# ─────────────────────────────────────────────────────────────────────────────
# 4. Dry-Run: schreibt KEINE Datei + nutzt neuen build_entries(kev_data=)
# ─────────────────────────────────────────────────────────────────────────────

def test_dryrun_no_file_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fake_entries = {
        ("apache", "httpd", f"<2.4.{i}"): {
            "cves": [f"CVE-2024-{1000 + i}"], "severity": "CRITICAL",
            "name": f"fake-{i}", "_source": "osv+kev",
        }
        for i in range(20)
    }
    fake_kev = {"vulnerabilities": [{"cveID": "CVE-2024-1000"}]}
    out_file = tmp_path / "known_vuln_builds_generated.py"

    with patch.object(sync_known_vuln_builds, "build_entries",
                      return_value=fake_entries), \
         patch.object(sync_known_vuln_builds, "fetch_kev_data",
                      return_value=fake_kev):
        monkeypatch.setattr(
            "sys.argv",
            ["sync-known-vuln-builds.py", "--dry-run", "--out", str(out_file)],
        )
        rc = sync_known_vuln_builds.main()
    assert rc == 0
    assert not out_file.exists()


def test_min_entries_validation_fails_on_too_few(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    fake_entries = {
        ("apache", "httpd", "<2.4.99"): {
            "cves": ["CVE-2099-9999"], "severity": "CRITICAL",
            "name": "x", "_source": "osv+kev",
        },
    }
    fake_kev = {"vulnerabilities": [{"cveID": "CVE-2024-1000"}]}
    out_file = tmp_path / "known_vuln_builds_generated.py"
    with patch.object(sync_known_vuln_builds, "build_entries",
                      return_value=fake_entries), \
         patch.object(sync_known_vuln_builds, "fetch_kev_data",
                      return_value=fake_kev):
        monkeypatch.setattr(
            "sys.argv",
            ["sync-known-vuln-builds.py", "--out", str(out_file)],
        )
        rc = sync_known_vuln_builds.main()
    assert rc == 1
    assert not out_file.exists()


def test_main_aborts_on_empty_kev(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """KEV-Fetch leer -> kein Build, exit 1 (sonst wuerde Output mit 0 Eintraegen ueberschrieben)."""
    out_file = tmp_path / "known_vuln_builds_generated.py"
    with patch.object(sync_known_vuln_builds, "fetch_kev_data",
                      return_value={}):
        monkeypatch.setattr(
            "sys.argv",
            ["sync-known-vuln-builds.py", "--out", str(out_file)],
        )
        rc = sync_known_vuln_builds.main()
    assert rc == 1
    assert not out_file.exists()

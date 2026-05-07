"""Tests fuer scripts/sync-known-vuln-builds.py (F-RPT-001).

Aufruf:
    python -m pytest scripts/tests/test_sync_known_vuln_builds.py -v

Mockt urllib + KEV-Fetch — keine echten Netzwerk-Calls.
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
# 1. KEV-Fetch: parsed cveID-Liste in set() — robust gegen Garbage-Eintraege
# ─────────────────────────────────────────────────────────────────────────────

def test_fetch_kev_set_parses_cve_ids():
    """fetch_kev_set sollte aus KEV-JSON-Feed eine set[str] uppercase liefern."""
    fake_kev_payload = json.dumps({
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "vulnerabilities": [
            {"cveID": "CVE-2023-25690", "vendorProject": "Apache"},
            {"cveID": "cve-2024-21762", "vendorProject": "Fortinet"},  # lowercase
            {"cveID": "  CVE-2024-1709  ", "vendorProject": "ConnectWise"},
            {},  # leerer Eintrag — muss ignoriert werden
            {"cveID": ""},  # leere ID — ignoriert
        ],
    })
    with patch.object(sync_known_vuln_builds, "fetch_with_retry",
                      return_value=fake_kev_payload):
        kev = sync_known_vuln_builds.fetch_kev_set()
    assert "CVE-2023-25690" in kev
    assert "CVE-2024-21762" in kev
    assert "CVE-2024-1709" in kev
    assert "" not in kev
    assert len(kev) == 3


# ─────────────────────────────────────────────────────────────────────────────
# 2. OSV-Parser: Range-Spec aus events extrahieren (introduced + fixed)
# ─────────────────────────────────────────────────────────────────────────────

def test_range_specs_from_vuln_extracts_fixed():
    """Events mit `fixed` -> "<fixed"-Spec; events mit `last_affected` -> "<=last"."""
    vuln_with_fixed = {
        "id": "CVE-2023-25690",
        "affected": [{
            "package": {"name": "Apache HTTP Server"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "2.4.0"},
                    {"fixed": "2.4.56"},
                ],
            }],
        }],
    }
    out = sync_known_vuln_builds._range_specs_from_vuln(vuln_with_fixed)
    assert out == ["<2.4.56"]

    vuln_with_last_affected = {
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
    out2 = sync_known_vuln_builds._range_specs_from_vuln(vuln_with_last_affected)
    assert out2 == ["<=1.5.2"]


# ─────────────────────────────────────────────────────────────────────────────
# 3. Filter-Logik: KEV-Listing > CVSS-Threshold; sub-9.0-non-KEV faellt raus
# ─────────────────────────────────────────────────────────────────────────────

def test_passes_filter_kev_wins_over_cvss():
    """KEV-listed CVE passiert auch ohne hohen CVSS-Score."""
    vuln_kev_low_cvss = {
        "id": "CVE-2024-1709",
        "severity": [{"type": "CVSS_V3", "score": "5.5"}],
    }
    kev = {"CVE-2024-1709"}
    passes, cves, cvss = sync_known_vuln_builds._passes_filter(
        vuln_kev_low_cvss, kev_set=kev,
    )
    assert passes is True
    assert "CVE-2024-1709" in cves
    assert cvss == 5.5


def test_passes_filter_high_cvss_no_kev_passes():
    """CVSS >=9.0 alleine reicht (kein KEV noetig)."""
    vuln_critical = {
        "id": "CVE-2024-99999",
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
    }
    passes, cves, cvss = sync_known_vuln_builds._passes_filter(
        vuln_critical, kev_set=set(),
    )
    assert passes is True
    assert cvss == 9.8


def test_passes_filter_low_severity_rejected():
    """CVE ohne KEV + CVSS < 9.0 wird gefiltert."""
    vuln_low = {
        "id": "CVE-2024-12345",
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
    }
    passes, _, _ = sync_known_vuln_builds._passes_filter(
        vuln_low, kev_set=set(),
    )
    assert passes is False


# ─────────────────────────────────────────────────────────────────────────────
# 4. Dry-Run: schreibt KEINE Datei + ruft validate_min_entries
# ─────────────────────────────────────────────────────────────────────────────

def test_dryrun_no_file_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """--dry-run: keine Datei geschrieben, exit-code 0, build_entries gemockt."""
    fake_entries = {
        # 20 fake-Eintraege (>= MIN_TOTAL_ENTRIES=15)
        ("apache", "httpd", f"<2.4.{i}"): {
            "cves": [f"CVE-2024-{1000 + i}"], "severity": "CRITICAL",
            "name": f"fake-{i}", "_source": "osv",
        }
        for i in range(20)
    }
    out_file = tmp_path / "known_vuln_builds_generated.py"

    with patch.object(sync_known_vuln_builds, "build_entries",
                      return_value=fake_entries), \
         patch.object(sync_known_vuln_builds, "fetch_kev_set",
                      return_value=set()):
        monkeypatch.setattr(
            "sys.argv",
            ["sync-known-vuln-builds.py", "--dry-run", "--out", str(out_file)],
        )
        rc = sync_known_vuln_builds.main()

    assert rc == 0
    # File darf NICHT existieren — Sinn von --dry-run
    assert not out_file.exists()


def test_min_entries_validation_fails_on_too_few(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """Zu wenig Eintraege (< MIN_TOTAL_ENTRIES) => exit-code 1."""
    fake_entries = {
        ("apache", "httpd", "<2.4.99"): {
            "cves": ["CVE-2099-9999"], "severity": "CRITICAL",
            "name": "x", "_source": "osv",
        },
    }
    out_file = tmp_path / "known_vuln_builds_generated.py"
    with patch.object(sync_known_vuln_builds, "build_entries",
                      return_value=fake_entries), \
         patch.object(sync_known_vuln_builds, "fetch_kev_set",
                      return_value=set()):
        monkeypatch.setattr(
            "sys.argv",
            ["sync-known-vuln-builds.py", "--out", str(out_file)],
        )
        rc = sync_known_vuln_builds.main()
    assert rc == 1
    assert not out_file.exists()

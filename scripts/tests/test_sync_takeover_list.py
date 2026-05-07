"""Tests fuer scripts/sync-takeover-list.py (F-P0B-006).

Aufruf:
    python -m pytest scripts/tests/test_sync_takeover_list.py -v

Mockt urllib.request.urlopen analog zum test_sync_cloud_ranges.py-Stil.
EdOverflow liefert seit 2024 JSON (`fingerprints.json`), nicht mehr YAML —
die Tests benutzen entsprechend JSON-Bodies.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


# Lokaler Import — `scripts/_sync_lib.py` und das Sync-Skript liegen
# parallel. Da das Skript einen Bindestrich im Namen hat, laden wir es
# explizit ueber importlib (Module-Spec).
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SCRIPTS_DIR))

_SCRIPT_PATH = _SCRIPTS_DIR / "sync-takeover-list.py"
_SPEC = importlib.util.spec_from_file_location(
    "sync_takeover_list", _SCRIPT_PATH,
)
sync_takeover_list = importlib.util.module_from_spec(_SPEC)  # type: ignore[arg-type]
sys.modules["sync_takeover_list"] = sync_takeover_list
_SPEC.loader.exec_module(sync_takeover_list)  # type: ignore[union-attr]


# ─────────────────────────────────────────────────────────────────────────────
# Hilfs-Stubs
# ─────────────────────────────────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body
    def read(self) -> bytes:
        return self._body
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _make_urlopen_for(payload: str):
    """Liefert ein fake urlopen(req, timeout) das `payload` als Body returned."""
    def fake_urlopen(req, timeout):  # noqa: ARG001
        return _FakeResponse(payload.encode("utf-8"))
    return fake_urlopen


def _vuln_entry(service: str, cname: list[str] | None = None,
                fingerprint: str = "Service not found",
                vulnerable: bool = True,
                status: str = "Vulnerable",
                nxdomain: bool = False) -> dict:
    return {
        "service": service,
        "cname": cname or [],
        "fingerprint": fingerprint,
        "vulnerable": vulnerable,
        "status": status,
        "nxdomain": nxdomain,
        "http_status": None,
        "cicd_pass": True,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1. Parser extrahiert nur vulnerable Services
# ─────────────────────────────────────────────────────────────────────────────

def test_yaml_parser_extracts_vulnerable_services():
    """vulnerable=True Eintraege werden uebernommen, alles andere geskippt.

    (Name behaelt "yaml" aus dem ursprunglichen Spec — EdOverflow hat das
    Format inzwischen auf JSON migriert, die Filterlogik bleibt identisch.)
    """
    body = json.dumps([
        _vuln_entry("GitHub Pages", cname=["github.io"],
                    fingerprint="There isn't a GitHub Pages site here"),
        _vuln_entry("Heroku", cname=["herokudns.com", "herokuapp.com"],
                    fingerprint="No such app"),
        # Not vulnerable -> muss raus
        _vuln_entry("Akamai", cname=[], fingerprint="",
                    vulnerable=False, status="Not vulnerable"),
        # Edge case (status != Vulnerable, vulnerable=False) -> raus
        _vuln_entry("Some Edge", cname=["edgecase.io"],
                    vulnerable=False, status="Edge case"),
    ])
    out = sync_takeover_list.parse_fingerprints(body)

    assert "github-pages" in out
    assert out["github-pages"]["cname_patterns"] == ["github.io"]
    assert out["github-pages"]["fingerprint_strings"] == [
        "There isn't a GitHub Pages site here"
    ]
    assert out["github-pages"]["status"] == "Vulnerable"

    assert "heroku" in out
    # cname_patterns sind sortiert + lowercase
    assert out["heroku"]["cname_patterns"] == ["herokuapp.com", "herokudns.com"]

    # Akamai + Edge sind NICHT durchgekommen
    assert "akamai" not in out
    assert "some-edge" not in out
    assert len(out) == 2


# ─────────────────────────────────────────────────────────────────────────────
# 2. Status "Vulnerable" reicht auch ohne `vulnerable: true` (Schema-Defensive)
# ─────────────────────────────────────────────────────────────────────────────

def test_status_vulnerable_accepted_even_without_flag():
    """Wenn `vulnerable` fehlt aber `status: Vulnerable` gesetzt ist, soll
    der Eintrag trotzdem mitgenommen werden (defensiv gegen Schema-Drift)."""
    body = json.dumps([
        {
            "service": "Heroku",
            "cname": ["herokuapp.com"],
            "fingerprint": "No such app",
            "status": "Vulnerable",
            # `vulnerable`-Flag fehlt absichtlich
        },
    ])
    out = sync_takeover_list.parse_fingerprints(body)
    assert "heroku" in out


# ─────────────────────────────────────────────────────────────────────────────
# 3. Nicht-vulnerable Services werden uebersprungen
# ─────────────────────────────────────────────────────────────────────────────

def test_skip_services_marked_not_vulnerable():
    body = json.dumps([
        _vuln_entry("Akamai", cname=[], fingerprint="",
                    vulnerable=False, status="Not vulnerable"),
        _vuln_entry("AWS/Load Balancer (ELB)", cname=["elb.amazonaws.com"],
                    vulnerable=False, status="Not vulnerable"),
    ])
    out = sync_takeover_list.parse_fingerprints(body)
    assert out == {}


# ─────────────────────────────────────────────────────────────────────────────
# 4. NXDOMAIN-only Eintrag (kein cname, kein fingerprint, aber actionable)
# ─────────────────────────────────────────────────────────────────────────────

def test_nxdomain_entry_kept_even_without_cname():
    """Vulnerable + nxdomain=True ist actionable, auch ohne cname."""
    body = json.dumps([
        {
            "service": "Some NXDOMAIN Service",
            "cname": [],
            "fingerprint": "NXDOMAIN",  # Marker -> kein eigenstaendiger Fingerprint
            "vulnerable": True,
            "status": "Vulnerable",
            "nxdomain": True,
        },
    ])
    out = sync_takeover_list.parse_fingerprints(body)
    assert "some-nxdomain-service" in out
    assert out["some-nxdomain-service"]["nxdomain"] is True
    # NXDOMAIN ist kein "echter" Fingerprint-String -> rausgefiltert
    assert out["some-nxdomain-service"]["fingerprint_strings"] == []


# ─────────────────────────────────────────────────────────────────────────────
# 5. Vulnerable ohne actionable-Signal (kein cname/fp/nx) wird gefiltert
# ─────────────────────────────────────────────────────────────────────────────

def test_vulnerable_without_signal_is_skipped():
    body = json.dumps([
        {
            "service": "Smugsmug",  # echter EdOverflow-Eintrag dieses Stils
            "cname": [],
            "fingerprint": "",
            "vulnerable": True,
            "status": "Vulnerable",
            "nxdomain": False,
        },
    ])
    out = sync_takeover_list.parse_fingerprints(body)
    assert out == {}


# ─────────────────────────────────────────────────────────────────────────────
# 6. --dry-run schreibt KEINE Datei
# ─────────────────────────────────────────────────────────────────────────────

def test_dryrun_no_file_written(tmp_path: Path,
                                 monkeypatch: pytest.MonkeyPatch):
    """Bei --dry-run wird der Output-Pfad nicht beschrieben.
    Wir mocken build_indicators() so dass die min-entries-Sanity passt
    (>= MIN_TOTAL_ENTRIES=30)."""
    fake_entries = {
        f"service-{i}": {
            "cname_patterns": [f"svc{i}.example.com"],
            "fingerprint_strings": [f"FP {i}"],
            "nxdomain": False,
            "service": f"Service {i}",
            "status": "Vulnerable",
        }
        for i in range(40)  # >= 30
    }
    out_file = tmp_path / "takeover_data_generated.py"

    with patch.object(sync_takeover_list, "build_indicators",
                      return_value=fake_entries):
        monkeypatch.setattr(
            "sys.argv",
            ["sync-takeover-list.py", "--dry-run", "--out", str(out_file)],
        )
        rc = sync_takeover_list.main()

    assert rc == 0
    # File darf NICHT existieren — das ist der Sinn von --dry-run
    assert not out_file.exists()


# ─────────────────────────────────────────────────────────────────────────────
# 7. Min-Entries-Validation: < MIN_TOTAL_ENTRIES => Exit-Code 1
# ─────────────────────────────────────────────────────────────────────────────

def test_min_entries_validation_below_threshold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    """Wenn weniger als MIN_TOTAL_ENTRIES extrahiert werden, bricht main()
    mit rc=1 ab und schreibt KEIN File."""
    fake_entries = {
        # Nur 5 — viel zu wenig (Floor ist 30)
        f"service-{i}": {
            "cname_patterns": [f"svc{i}.example.com"],
            "fingerprint_strings": [f"FP {i}"],
            "nxdomain": False,
            "service": f"Service {i}",
            "status": "Vulnerable",
        }
        for i in range(5)
    }
    out_file = tmp_path / "takeover_data_generated.py"

    with patch.object(sync_takeover_list, "build_indicators",
                      return_value=fake_entries):
        monkeypatch.setattr(
            "sys.argv",
            ["sync-takeover-list.py", "--out", str(out_file)],
        )
        rc = sync_takeover_list.main()

    assert rc == 1
    assert not out_file.exists()
    captured = capsys.readouterr()
    combined = (captured.err + captured.out).lower()
    assert "edoverflow-takeover-list" in combined or "ERROR" in captured.err


# ─────────────────────────────────────────────────────────────────────────────
# 8. End-to-End mit gemocktem urlopen — schreibt Datei wenn nicht --dry-run
# ─────────────────────────────────────────────────────────────────────────────

def test_full_run_writes_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Mockt urllib.request.urlopen und prueft ob das Output-File geschrieben
    wird (TAKEOVER_INDICATORS_GENERATED-Variable + min 30 Eintraege)."""
    entries = [
        _vuln_entry(f"Service {i}",
                    cname=[f"svc{i}.example.com"],
                    fingerprint=f"FP {i} not found")
        for i in range(35)
    ]
    body = json.dumps(entries)
    out_file = tmp_path / "takeover_data_generated.py"

    with patch("urllib.request.urlopen", _make_urlopen_for(body)):
        monkeypatch.setattr(
            "sys.argv",
            ["sync-takeover-list.py", "--out", str(out_file)],
        )
        rc = sync_takeover_list.main()

    assert rc == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "TAKEOVER_INDICATORS_GENERATED" in content
    assert "service-0" in content
    assert "svc0.example.com" in content


# ─────────────────────────────────────────────────────────────────────────────
# 9. Slugify: AWS/S3 -> aws-s3, "GitHub Pages" -> github-pages
# ─────────────────────────────────────────────────────────────────────────────

def test_slugify_handles_slashes_and_spaces():
    body = json.dumps([
        _vuln_entry("AWS/S3", cname=["s3.amazonaws.com"],
                    fingerprint="The specified bucket does not exist"),
        _vuln_entry("GitHub Pages", cname=["github.io"],
                    fingerprint="There isn't a GitHub Pages site here"),
    ])
    out = sync_takeover_list.parse_fingerprints(body)
    assert "aws-s3" in out
    assert "github-pages" in out

"""Tests fuer scripts/sync-cloud-ranges.py (F-PRE-003).

Aufruf:
    python -m pytest scripts/tests/test_sync_cloud_ranges.py -v

Mockt urllib analog zu test_sync_lib.py-Stil.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest


# Lokaler Import — `scripts/_sync_lib.py` und das Sync-Skript liegen
# parallel. Da das Skript einen Bindestrich im Namen hat, laden wir es
# explizit ueber importlib (Module-Spec).
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SCRIPTS_DIR))

_SCRIPT_PATH = _SCRIPTS_DIR / "sync-cloud-ranges.py"
_SPEC = importlib.util.spec_from_file_location(
    "sync_cloud_ranges", _SCRIPT_PATH,
)
sync_cloud_ranges = importlib.util.module_from_spec(_SPEC)  # type: ignore[arg-type]
sys.modules["sync_cloud_ranges"] = sync_cloud_ranges
_SPEC.loader.exec_module(sync_cloud_ranges)  # type: ignore[union-attr]


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


# ─────────────────────────────────────────────────────────────────────────────
# 1. AWS-Parser: extrahiert IPv4-Prefixes aus prefixes[]
# ─────────────────────────────────────────────────────────────────────────────

def test_aws_parser_extracts_ipv4_prefixes():
    body = json.dumps({
        "syncToken": "1234",
        "createDate": "2026-05-01-00-00-00",
        "prefixes": [
            {"ip_prefix": "3.0.0.0/15", "region": "us-east-1", "service": "EC2"},
            {"ip_prefix": "13.32.0.0/15", "region": "GLOBAL", "service": "CLOUDFRONT"},
            # Duplikat — muss dedupliziert werden
            {"ip_prefix": "3.0.0.0/15", "region": "us-east-1", "service": "AMAZON"},
            # Garbage — muss verworfen werden
            {"ip_prefix": "not-a-prefix"},
            {},
        ],
        "ipv6_prefixes": [
            {"ipv6_prefix": "2400:6500::/32"},  # wird ignoriert (kein ip_prefix)
        ],
    })
    out = sync_cloud_ranges.parse_aws(body)
    # Beide validen IPv4-Prefixes, dedupliziert + sortiert
    assert out == ["3.0.0.0/15", "13.32.0.0/15"]


# ─────────────────────────────────────────────────────────────────────────────
# 2. Cloudflare-Parser: Plain-Text, eine Zeile pro Prefix
# ─────────────────────────────────────────────────────────────────────────────

def test_cloudflare_parser_text_lines():
    body = (
        "173.245.48.0/20\n"
        "103.21.244.0/22\n"
        "\n"  # leere Zeile -> ignoriert
        "  104.16.0.0/13  \n"  # whitespace getrimmt
        "garbage\n"  # kein gueltiges CIDR -> ignoriert
    )
    out = sync_cloud_ranges.parse_cloudflare(body)
    # Sortiert nach (network_address, prefixlen)
    assert "173.245.48.0/20" in out
    assert "103.21.244.0/22" in out
    assert "104.16.0.0/13" in out
    assert "garbage" not in out
    # 3 valide Eintraege
    assert len(out) == 3


# ─────────────────────────────────────────────────────────────────────────────
# 3. Fastly-Parser: addresses[] aus JSON
# ─────────────────────────────────────────────────────────────────────────────

def test_fastly_parser_addresses_array():
    body = json.dumps({
        "addresses": [
            "23.235.32.0/20",
            "43.249.72.0/22",
            "broken",
            "23.235.32.0/20",  # duplicate
        ],
        "ipv6_addresses": ["2a04:4e40::/32"],
    })
    out = sync_cloud_ranges.parse_fastly(body)
    assert out == ["23.235.32.0/20", "43.249.72.0/22"]


# ─────────────────────────────────────────────────────────────────────────────
# 4. RIPEstat-ASN-Parser: extrahiert Prefixes mit Mindest-Praefixlaenge
# ─────────────────────────────────────────────────────────────────────────────

def test_ripe_asn_parser_extracts_prefixes():
    """Prefix < /16 wird gefiltert (MIN_PREFIX_LEN_ASN), >= /16 behalten.
    IPv6 wird verworfen (nicht IPv4)."""
    body = json.dumps({
        "data": {
            "prefixes": [
                # Behalten — /16
                {"prefix": "188.114.96.0/20", "timelines": []},
                # Behalten — /18
                {"prefix": "162.158.0.0/18"},
                # Verworfen — /8 zu gross
                {"prefix": "10.0.0.0/8"},
                # Verworfen — IPv6 (kein IPv4-Match)
                {"prefix": "2001:db8::/32"},
                # Verworfen — Garbage
                {"prefix": "not-a-cidr"},
                # Verworfen — leerer Eintrag
                {},
            ],
        },
        "status": "ok",
    })
    out = sync_cloud_ranges.parse_ripe_asn(body)
    assert "188.114.96.0/20" in out
    assert "162.158.0.0/18" in out
    assert "10.0.0.0/8" not in out
    assert all(":" not in p for p in out)  # kein IPv6
    assert len(out) == 2


# ─────────────────────────────────────────────────────────────────────────────
# 5. --dry-run schreibt KEINE Datei
# ─────────────────────────────────────────────────────────────────────────────

def test_dryrun_no_file_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Bei --dry-run wird der Output-Pfad nicht beschrieben.
    Wir mocken build_ranges() so dass die min-entries-Sanity-Check passt."""
    fake_entries = {
        # 60 Eintraege (>= MIN_TOTAL_ENTRIES=50)
        "aws": [f"10.{i}.0.0/16" for i in range(60)],
    }
    out_file = tmp_path / "cloud_ranges_generated.py"

    with patch.object(sync_cloud_ranges, "build_ranges",
                      return_value=fake_entries):
        monkeypatch.setattr(
            "sys.argv",
            ["sync-cloud-ranges.py", "--dry-run", "--out", str(out_file)],
        )
        rc = sync_cloud_ranges.main()

    assert rc == 0
    # File darf NICHT existieren — das ist der Sinn von --dry-run
    assert not out_file.exists()


# ─────────────────────────────────────────────────────────────────────────────
# 6. Min-Entries-Validation: weniger als 50 Total-Eintraege => Exit-Code 1
# ─────────────────────────────────────────────────────────────────────────────

def test_min_entries_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                 capsys: pytest.CaptureFixture[str]):
    """Wenn Total-Prefix-Count < MIN_TOTAL_ENTRIES, bricht main() mit rc=1 ab
    und schreibt KEIN File."""
    fake_entries = {
        "aws": ["3.0.0.0/15"],  # nur 1 Prefix - viel zu wenig
        "gcp": ["8.34.208.0/20", "8.35.192.0/20"],
    }
    out_file = tmp_path / "cloud_ranges_generated.py"

    with patch.object(sync_cloud_ranges, "build_ranges",
                      return_value=fake_entries):
        monkeypatch.setattr(
            "sys.argv",
            ["sync-cloud-ranges.py", "--out", str(out_file)],
        )
        rc = sync_cloud_ranges.main()

    assert rc == 1
    assert not out_file.exists()
    captured = capsys.readouterr()
    assert "cloud-provider-ranges" in captured.err.lower() \
        or "cloud-provider-ranges" in captured.out.lower() \
        or "ERROR" in captured.err

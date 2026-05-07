"""Tests fuer scripts/_sync_lib.py.

Aufruf:
    python -m pytest scripts/tests/test_sync_lib.py -v
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

# Lokaler Import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _sync_lib import (  # noqa: E402
    SyncValidationError,
    atomic_write_python_module,
    commit_and_push_if_changed,  # noqa: F401 — referenced in _sync_commit; smoke test indirekt
    fetch_with_retry,
    has_git_changes,
    validate_min_entries,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. fetch_with_retry — 429 → Retry → 200
# ─────────────────────────────────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body
    def read(self) -> bytes:
        return self._body
    def __enter__(self): return self
    def __exit__(self, *a): return False


def test_fetch_with_retry_handles_429():
    """Erster Call wirft 429, zweiter liefert 200 → Returncode `ok`."""
    call_count = {"n": 0}
    sleeps: list[float] = []

    def fake_urlopen(req, timeout):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise urllib.error.HTTPError(
                "https://example.com", 429, "Too Many", {}, io.BytesIO(b""),
            )
        return _FakeResponse(b'{"ok":true}')

    def fake_sleep(s):
        sleeps.append(s)

    with patch("_sync_lib.urllib.request.urlopen", side_effect=fake_urlopen), \
         patch("_sync_lib.time.sleep", side_effect=fake_sleep):
        body = fetch_with_retry(
            "https://example.com", retries=3, timeout=5, backoff_base=2.0,
        )

    assert body == '{"ok":true}'
    assert call_count["n"] == 2
    # Backoff nach 1. Versuch: 2.0 ** 0 = 1.0
    assert sleeps == [1.0]


def test_fetch_with_retry_4xx_no_retry():
    """404 ist nicht-transient → kein Retry, sofort raise."""
    call_count = {"n": 0}

    def fake_urlopen(req, timeout):
        call_count["n"] += 1
        raise urllib.error.HTTPError(
            "https://example.com", 404, "Not Found", {}, io.BytesIO(b""),
        )

    with patch("_sync_lib.urllib.request.urlopen", side_effect=fake_urlopen):
        with pytest.raises(urllib.error.HTTPError):
            fetch_with_retry("https://example.com", retries=3)

    assert call_count["n"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# 2. atomic_write_python_module — Format + No-Partial-File
# ─────────────────────────────────────────────────────────────────────────────

def test_atomic_write_format_matches_expected(tmp_path: Path):
    """Erzeugter Output ist exakt deterministisch (sortiert, gleiche Indentierung)."""
    target = tmp_path / "generated.py"
    header = '"""Test header.\n\nGen-Stand: testing\n"""\n'
    data = {
        ("apache", "httpd", "2.4"): {
            "_source": "endoflife.date",
            "date": "2025-01-01",
            "severity": "HIGH",
        },
        ("nginx", "", "1.20"): {
            "_source": "endoflife.date",
            "date": "2024-04-01",
            "severity": "MEDIUM",
        },
    }

    atomic_write_python_module(
        target,
        header=header,
        data_name="EOL_DATA_GENERATED",
        data_dict=data,
        dict_type_hint="dict[tuple[str, str, str], dict]",
    )

    expected = (
        '"""Test header.\n'
        '\n'
        'Gen-Stand: testing\n'
        '"""\n'
        '\n'
        'from __future__ import annotations\n'
        '\n'
        '# (vendor, product, version_prefix) -> info dict\n'
        'EOL_DATA_GENERATED: dict[tuple[str, str, str], dict] = {\n'
        '    ("apache", "httpd", "2.4"): '
        '{"_source": "endoflife.date", "date": "2025-01-01", "severity": "HIGH"},\n'
        '    ("nginx", "", "1.20"): '
        '{"_source": "endoflife.date", "date": "2024-04-01", "severity": "MEDIUM"},\n'
        '}\n'
    )
    actual = target.read_text(encoding="utf-8")
    assert actual == expected


def test_atomic_write_no_partial_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Wenn os.replace fehlschlaegt, bleibt KEIN partielles File zurueck."""
    target = tmp_path / "generated.py"

    def boom(*a, **kw):
        raise OSError("simulated crash mid-replace")

    monkeypatch.setattr("_sync_lib.os.replace", boom)

    with pytest.raises(OSError, match="simulated crash"):
        atomic_write_python_module(
            target,
            header='"""x"""\n',
            data_name="X",
            data_dict={"a": 1},
            dict_type_hint="dict[str, int]",
        )

    # Hauptpruefung: Ziel-Datei darf nicht existieren
    assert not target.exists()
    # Tempfiles im Verzeichnis muessen aufgeraeumt sein
    leftover = list(tmp_path.glob(".*.tmp"))
    assert leftover == [], f"leftover temp files: {leftover}"


# ─────────────────────────────────────────────────────────────────────────────
# 3. has_git_changes — initialisiertes temp-Repo
# ─────────────────────────────────────────────────────────────────────────────

def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=str(cwd), check=True,
                   capture_output=True, text=True, shell=False)


def test_has_git_changes_detects_diff(tmp_path: Path):
    """Initialisiert ein leeres Git-Repo, modifiziert eine Datei,
    prueft has_git_changes True/False."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init", "-q"], repo)
    _git(["config", "user.email", "test@test"], repo)
    _git(["config", "user.name", "Test"], repo)
    _git(["config", "commit.gpgsign", "false"], repo)

    f = repo / "data.py"
    f.write_text("ORIGINAL\n", encoding="utf-8")
    _git(["add", "data.py"], repo)
    _git(["commit", "-q", "-m", "initial"], repo)

    # Direkt nach Commit: keine Aenderungen
    assert has_git_changes(f, repo_root=repo) is False

    # Nach Modifikation: True
    f.write_text("CHANGED\n", encoding="utf-8")
    assert has_git_changes(f, repo_root=repo) is True

    # Revert -> False wieder
    f.write_text("ORIGINAL\n", encoding="utf-8")
    assert has_git_changes(f, repo_root=repo) is False


# ─────────────────────────────────────────────────────────────────────────────
# 4. validate_min_entries
# ─────────────────────────────────────────────────────────────────────────────

def test_validate_min_entries_raises_below_threshold():
    with pytest.raises(SyncValidationError, match="endoflife.date"):
        validate_min_entries(
            {"a": 1, "b": 2}, min_count=10, source_name="endoflife.date",
        )


def test_validate_min_entries_passes_at_threshold():
    # Genau die Schwelle: ok
    validate_min_entries(
        {f"k{i}": i for i in range(10)}, min_count=10, source_name="x",
    )
    # Liste mit ausreichend Eintraegen: ok
    validate_min_entries([1, 2, 3], min_count=3, source_name="x")

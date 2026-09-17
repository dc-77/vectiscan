"""S0a: Startup-Check fuer die im Code referenzierten Wordlists.

Die Tests laufen ausserhalb des Scanner-Images (CI-Job test-scan-worker nutzt
python:3.12-slim), dort existiert keine der Wordlists. Deshalb wird
``os.path.isfile`` gemockt statt auf echte Dateien zu pruefen.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from scanner import preflight
from scanner.phase0 import GOBUSTER_DNS_WORDLIST_PATH
from scanner.phase2 import FFUF_WORDLISTS, WORDLIST_MAP


def test_required_covers_all_phase_constants() -> None:
    """Kein zweiter Pfad-Katalog: die Liste kommt aus den Phase-Konstanten."""
    paths = set(preflight.REQUIRED_WORDLISTS.values())
    assert set(WORDLIST_MAP.values()) <= paths
    assert set(FFUF_WORDLISTS.values()) <= paths
    assert GOBUSTER_DNS_WORDLIST_PATH in paths


def test_sensitive_wordlist_is_raft_small() -> None:
    """F-PH2-001: gobuster und ffuf erwarten beide raft-small-files.txt."""
    assert WORDLIST_MAP["sensitive"].endswith("raft-small-files.txt")
    assert FFUF_WORDLISTS["sensitive"].endswith("raft-small-files.txt")


def test_check_passes_when_all_present() -> None:
    with patch("scanner.preflight.os.path.isfile", return_value=True):
        preflight.check_wordlists()  # darf nicht werfen


def test_missing_wordlists_reports_only_the_missing_one() -> None:
    gone = FFUF_WORDLISTS["sensitive"]

    with patch("scanner.preflight.os.path.isfile", side_effect=lambda p: p != gone):
        missing = preflight.missing_wordlists()

    assert list(missing.values()) == [gone]


def test_check_aborts_on_missing_wordlist() -> None:
    """Harter Abbruch statt stillem Skip -- fehlende Wordlist = kaputtes Image."""
    gone = FFUF_WORDLISTS["sensitive"]

    with patch("scanner.preflight.os.path.isfile", side_effect=lambda p: p != gone):
        with pytest.raises(SystemExit) as excinfo:
            preflight.check_wordlists()

    assert excinfo.value.code == 1


def test_worker_main_aborts_before_touching_redis() -> None:
    """main() prueft die Wordlists, bevor irgendeine Verbindung aufgebaut wird."""
    from scanner import worker

    with patch("scanner.preflight.os.path.isfile", return_value=False), \
            patch("scanner.worker.redis.from_url") as mock_redis, \
            patch("scanner.worker.prewarm_buckets") as mock_prewarm:
        with pytest.raises(SystemExit) as excinfo:
            worker.main()

    assert excinfo.value.code == 1
    mock_redis.assert_not_called()
    mock_prewarm.assert_not_called()

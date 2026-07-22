"""Tests for F-P0B-001 — DKIM-Probe parallel + erweiterte Selektor-Liste.

Audit-Eintrag: docs/scan-flow/Scan-Optimierung.md Sektion 3.3.1.
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

from scanner import phase0


def test_dkim_selectors_runs_in_parallel(tmp_path: Path) -> None:
    """~44 Selektoren mit je 0.05s Delay duerfen nicht ~2.2s sequenziell brauchen.

    Hinweis: `_dig_query` ist eine Closure in `collect_dns_records` — wir
    koennen sie nicht direkt patchen. Stattdessen patchen wir
    `subprocess.run`, was die Closure am Ende aufruft.
    """
    sleep_time = 0.05
    call_count = {"n": 0}

    (tmp_path / "phase0").mkdir()
    scan_dir = str(tmp_path)

    def slow_subprocess(args, **kwargs):
        call_count["n"] += 1
        time.sleep(sleep_time)

        class _Result:
            stdout = ""
            stderr = ""
            returncode = 0

        joined = " ".join(args) if isinstance(args, list) else str(args)
        if "default._domainkey." in joined:
            _Result.stdout = "v=DKIM1; k=rsa; p=AAAA"
        elif "selector1._domainkey." in joined:
            _Result.stdout = "v=DKIM1; k=rsa; p=BBBB"
        return _Result()

    with patch("subprocess.run", side_effect=slow_subprocess), \
         patch.object(phase0, "run_tool", return_value=("", 0, 0.0)), \
         patch.object(phase0, "record_tool_run"), \
         patch("scanner.passive.mail_security_parsers.check_dmarc_policy",
               return_value={"dmarc_present": False, "raw": None,
                             "p": None, "sp": None, "pct": 100,
                             "rua": [], "ruf": [],
                             "aspf": "r", "adkim": "r", "fo": None,
                             "issues": []}):
        start = time.monotonic()
        records = phase0.collect_dns_records(
            domain="example.com", scan_dir=scan_dir, order_id="t1",
        )
        duration = time.monotonic() - start

    # 44+ Selektoren x 0.05s sequenziell = ~2.2s. Parallel max_workers=10 ~0.25s.
    # Selbst mit Overhead/CI-Latenz sollten wir < 1.5s bleiben.
    assert duration < 1.5, (
        f"DKIM-Probe dauerte {duration:.2f}s — vermutlich nicht parallel "
        f"(call_count={call_count['n']})"
    )
    # Beide bekannte Selektoren MUESSEN gefunden sein.
    assert "default" in records["dkim_selectors"]
    assert "selector1" in records["dkim_selectors"]
    assert records["dkim"] is True


def test_dkim_selector_list_contains_new_providers() -> None:
    """Verifiziert, dass die Selektor-Liste die ~19 neuen Eintraege enthaelt."""
    # Wir muessen den dynamisch erzeugten Set rekonstruieren — naehesten Weg:
    # In einem vereinfachten Lauf rufen wir collect_dns_records mit komplett
    # leerem _dig + minimal-mocks und lesen records["dkim_selectors"] —
    # liefert nichts. Stattdessen pruefen wir die Liste direkt im Source.
    src = (Path(__file__).resolve().parent.parent
           / "scanner" / "phase0.py").read_text(encoding="utf-8")
    # Provider-Erweiterungen die F-P0B-001 fordert.
    must_contain = [
        '"amazonses"', '"mxvault"',          # SES
        '"pm"', '"postmark"',                # Postmark
        '"mg"', '"mailgun"',                  # Mailgun
        '"mailjet"', '"mj"',                  # Mailjet
        '"brevo"', '"sib"', '"mailin"',       # Brevo
        '"zoho"', '"zmail"',                  # Zoho
        '"ionos1"', '"strato1"',              # DE-Provider
        '"t-online"', '"gmx"',
        '"google"', '"googledomains"',
    ]
    for token in must_contain:
        assert token in src, f"DKIM-Selektor fehlt: {token}"


def test_dkim_selectors_deduplicated_and_sorted() -> None:
    """records['dkim_selectors'] soll deterministisch sortiert sein."""
    def fake_dig(args, **kwargs):
        class _R:
            stdout = "v=DKIM1; k=rsa; p=XXX"
            stderr = ""
            returncode = 0

        joined = " ".join(args) if isinstance(args, list) else str(args)
        # Triple-match scenario: 3 Selektoren liefern alle DKIM
        if any(s in joined for s in ("selector1.", "selector2.", "google.")):
            return _R()

        class _Empty:
            stdout = ""
            stderr = ""
            returncode = 0

        return _Empty()

    with patch("subprocess.run", side_effect=fake_dig), \
         patch.object(phase0, "run_tool", return_value=("", 0, 0.0)), \
         patch("scanner.passive.mail_security_parsers.check_dmarc_policy",
               return_value={"dmarc_present": False, "raw": None,
                             "p": None, "sp": None, "pct": 100,
                             "rua": [], "ruf": [],
                             "aspf": "r", "adkim": "r", "fo": None,
                             "issues": []}):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            (Path(td) / "phase0").mkdir()
            records = phase0.collect_dns_records(
                domain="example.com", scan_dir=td, order_id="t2",
            )

    sels = records["dkim_selectors"]
    assert sels == sorted(sels), "DKIM-Selektor-Liste muss sortiert sein"
    assert len(sels) == len(set(sels)), "DKIM-Selektor-Liste muss dedupliziert sein"
    assert "google" in sels and "selector1" in sels and "selector2" in sels

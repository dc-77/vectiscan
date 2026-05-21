"""Tests fuer M1 ValidationGate-Checks.

Spec: docs/report-erstellung/01_Fehleranalyse_und_Korrekturplan.md Phase A
Plan: ~/.claude/plans/ich-m-chte-gerne-das-iterative-nova.md M1

Pro Fixture wird mindestens ein Error (oder ggf. Warning) erwartet.
clean_report.json muss ohne Errors passieren.
"""
from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from reporter.validation.checks import (
    consistency,
    cvss as cvss_check,
    eol,
    ids,
    plan,
    tech_table,
    titles,
)
from reporter.validation.gate import ValidationGate, ValidationLevel

FIX = pathlib.Path(__file__).parent / "fixtures"


def _load(name: str) -> dict[str, Any]:
    return json.loads((FIX / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Clean baseline
# ---------------------------------------------------------------------------

def test_clean_report_passes() -> None:
    """clean_report.json darf keine Errors triggern."""
    gate = ValidationGate(level=ValidationLevel.WARN)
    result = gate.run(
        _load("clean_report.json"),
        report_data={},
        context={
            "package": "perimeter",
            "order_id": "test",
            "domain": "example.com",
            "tech_profiles": [],
        },
    )
    assert result.passed, "Clean report sollte ohne Errors passieren. Errors: " + ", ".join(
        f"{i.check}/{i.message}" for i in result.errors
    )


# ---------------------------------------------------------------------------
# Per-Check Parametrized: jedes Bad-Fixture loest mind. einen Error aus
# ---------------------------------------------------------------------------

_BAD_FIXTURES_ERROR = [
    ("bad_title_with_placeholder.json", titles),
    ("bad_title_duplicate.json", titles),
    ("bad_id_gap.json", ids),
    ("bad_cvss_zero_with_impact.json", cvss_check),
    ("bad_cvss_missing_prefix.json", cvss_check),
    ("bad_plan_unreferenced_port.json", plan),
    ("bad_plan_dead_ref.json", plan),
]

_BAD_FIXTURES_WARNING = [
    ("bad_title_naked_number.json", titles),
    ("bad_id_duplicate.json", ids),
    ("bad_eol_mariadb_mysql.json", eol),
    ("bad_plan_orphan.json", plan),
    # heuel.com-Vorfall Mai 2026: consistency-Issues sind generell Warnings
    # (zu hohes FP-Risiko, Admin-Review noetig — siehe consistency.py-Docstring).
    ("bad_consistency_spf_dkim.json", consistency),
]


@pytest.mark.parametrize("fixture,check_mod", _BAD_FIXTURES_ERROR)
def test_bad_fixture_triggers_error(fixture: str, check_mod: Any) -> None:
    """Jedes Bad-Fixture muss mindestens einen Error produzieren."""
    issues = check_mod.check(
        _load(fixture),
        {},
        {"package": "perimeter", "order_id": "t", "domain": "example.com",
         "tech_profiles": []},
    ) or []
    errors = [i for i in issues if i.severity == "error"]
    assert errors, (
        f"{fixture} sollte mind. einen Error produzieren. "
        f"Gefunden: {[(i.severity, i.message) for i in issues]}"
    )


@pytest.mark.parametrize("fixture,check_mod", _BAD_FIXTURES_WARNING)
def test_bad_fixture_triggers_warning(fixture: str, check_mod: Any) -> None:
    """Bad-Fixtures, die "nur" Warnings produzieren sollten."""
    issues = check_mod.check(
        _load(fixture),
        {},
        {"package": "perimeter", "order_id": "t", "domain": "example.com",
         "tech_profiles": []},
    ) or []
    warnings = [i for i in issues if i.severity == "warning"]
    errors = [i for i in issues if i.severity == "error"]
    # Mindestens ein Issue (Warning oder Error) — der Defect muss erkannt werden
    assert (warnings or errors), (
        f"{fixture} sollte mind. ein Issue produzieren. "
        f"Gefunden: {issues}"
    )


# ---------------------------------------------------------------------------
# CVSS score-vs-vector-mismatch braucht die cvss-Library — defensiver Test
# ---------------------------------------------------------------------------

def test_cvss_score_vector_mismatch_when_library_available() -> None:
    """Mismatches sind Warnings (Mai 2026, securess.de-Vorfall) — nicht
    blockierend. Admin-Override-UI loest das via Korrektur des Findings.

    Wenn cvss-Library nicht installiert ist, wird zusaetzlich eine
    Warning ueber die fehlende Lib emittiert.
    """
    issues = cvss_check.check(
        _load("bad_cvss_score_vector_mismatch.json"),
        {},
        {"package": "perimeter"},
    )
    try:
        import cvss  # noqa: F401
        library_available = True
    except ImportError:
        library_available = False

    if library_available:
        # Mismatch ist warning (nicht error), und keine errors aus cvss-check
        warnings = [i for i in issues if i.severity == "warning"]
        assert warnings, f"Library verfuegbar — Mismatch sollte Warning sein. {issues}"
        assert any(
            "weicht von Vektor-berechnetem" in w.message for w in warnings
        ), f"Erwartet: Score-Mismatch-Warning. {issues}"
        assert not [i for i in issues if i.severity == "error"], (
            f"Score-Mismatch darf keinen Error mehr emittieren. {issues}"
        )
    else:
        # Library fehlt → Warning (kein Crash)
        assert any(
            i.severity == "warning" and "cvss" in i.message.lower()
            for i in issues
        ), f"Erwartet: Warning ueber fehlende cvss-Library. Gefunden: {issues}"


# ---------------------------------------------------------------------------
# Tech-Table braucht context.tech_profiles — speziell aufgebauter Test
# ---------------------------------------------------------------------------

def test_tech_table_kernel_detection_triggers_error() -> None:
    """HTTPAPI/2.0 in tech_profile darf nicht durchgehen."""
    ctx = {
        "package": "perimeter",
        "tech_profiles": [{
            "ip": "1.2.3.4",
            "technologies": [{"name": "HTTPAPI", "version": "2.0"}],
        }],
    }
    issues = tech_table.check(_load("bad_tech_kernel.json"), {}, ctx)
    errors = [i for i in issues if i.severity == "error"]
    assert errors, f"HTTPAPI Kernel-Detection sollte Error sein. {issues}"
    assert any("httpapi" in (i.detail.get("blacklisted_token") or "")
               for i in errors)


def test_tech_table_bootstrap_v1_triggers_error() -> None:
    """Bootstrap 0.x ist unter MIN_PUBLIC_VERSIONS = 2 → Error."""
    ctx = {
        "package": "perimeter",
        "tech_profiles": [{
            "ip": "1.2.3.4",
            "technologies": [{"name": "Bootstrap", "version": "0.9"}],
        }],
    }
    issues = tech_table.check(_load("bad_tech_bootstrap_v1.json"), {}, ctx)
    errors = [i for i in issues if i.severity == "error"]
    assert errors, f"Bootstrap 0.x sollte Error sein. {issues}"


def test_tech_table_empty_returns_warning() -> None:
    """Kein tech_profile in context → Warning, kein Crash."""
    ctx = {"package": "perimeter", "tech_profiles": []}
    issues = tech_table.check(_load("clean_report.json"), {}, ctx)
    warnings = [i for i in issues if i.severity == "warning"]
    assert warnings, "Leere Tech-Tabelle sollte Warning produzieren"
    assert not [i for i in issues if i.severity == "error"]


# ---------------------------------------------------------------------------
# Consistency: P0-02 (version mismatch) braucht tech_profile
# ---------------------------------------------------------------------------

def test_consistency_version_mismatch_with_tech_profile() -> None:
    """Finding nennt WordPress 6.9.4, Tech-Tabelle hat 6.4.2 → Warning.

    Mai 2026: consistency-Issues sind generell Warnings (siehe Docstring
    in consistency.py).
    """
    ctx = {
        "package": "perimeter",
        "tech_profiles": [{
            "ip": "1.2.3.4",
            "cms": "WordPress",
            "cms_version": "6.4.2",
        }],
    }
    issues = consistency.check(
        _load("bad_consistency_version_mismatch.json"), {}, ctx,
    )
    warnings = [i for i in issues if i.severity == "warning"]
    assert warnings, f"Versions-Mismatch sollte Warning sein. {issues}"
    assert any("wordpress" in (i.detail.get("software") or "").lower()
               for i in warnings)
    assert not [i for i in issues if i.severity == "error"], (
        f"consistency darf keine errors emittieren. {issues}"
    )


# ---------------------------------------------------------------------------
# Consistency: heuel.com False-Positive-Schutz (Mai 2026)
# ---------------------------------------------------------------------------

def test_consistency_skips_service_check_when_token_only_in_recommendation() -> None:
    """FTP-Title + SFTP nur in Recommendation -> KEIN Issue.

    Real-Vorfall heuel.com VS-2026-001: Title 'FTP klartextfaehig',
    Recommendation 'FTP durch SFTP ersetzen'. Recommendation darf den
    Service-Check nicht triggern.
    """
    issues = consistency.check(
        _load("bad_consistency_recommendation_token.json"),
        {},
        {"package": "perimeter", "tech_profiles": []},
    ) or []
    service_issues = [
        i for i in issues
        if "Service-Verwechslung" in i.message
    ]
    assert not service_issues, (
        f"Recommendation-Token darf Service-Check nicht triggern. {issues}"
    )


def test_consistency_skips_service_check_on_crossref() -> None:
    """SPF-Title + DMARC-Token im Body mit 'siehe VS-...' -> KEIN Issue.

    Real-Vorfall heuel.com VS-2026-006: Title 'SPF Softfail', Impact
    'in Kombination mit DMARC-Policy (siehe VS-2026-005)'. Querverweise
    auf andere Findings sind keine Service-Verwechslung.
    """
    issues = consistency.check(
        _load("bad_consistency_crossref_skip.json"),
        {},
        {"package": "perimeter", "tech_profiles": []},
    ) or []
    service_issues = [
        i for i in issues
        if "Service-Verwechslung" in i.message
    ]
    assert not service_issues, (
        f"Cross-Reference darf Service-Check nicht triggern. {issues}"
    )


# ---------------------------------------------------------------------------
# Gate-Integration: lade alle Checks via Gate
# ---------------------------------------------------------------------------

def test_gate_orchestrates_all_checks() -> None:
    """Gate muss alle 7 Module finden, keiner darf skipped sein."""
    gate = ValidationGate(level=ValidationLevel.WARN)
    result = gate.run(
        _load("clean_report.json"),
        report_data={},
        context={"package": "perimeter", "order_id": "t", "domain": "ex.com",
                 "tech_profiles": []},
    )
    expected = {"titles", "ids", "cvss", "consistency", "tech_table", "eol", "plan"}
    actual = set(result.checks_run)
    missing = expected - actual
    assert not missing, f"Gate hat Checks nicht gefunden: {missing} (skipped: {result.checks_skipped})"

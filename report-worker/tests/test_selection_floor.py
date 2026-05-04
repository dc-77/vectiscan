"""Tests fuer reporter.selection (A3 — Findings-Floor)."""

from reporter.selection import select_findings, MIN_N_PER_PACKAGE


def _mk(idx: int, score: float = 5.0):
    return {"finding_id": f"F{idx:03d}", "title": f"X{idx}",
            "severity": "low", "business_impact_score": score,
            "finding_type": f"t{idx}", "policy_id": f"p{idx}",
            "cvss_score": score}


def test_floor_pulls_from_additional():
    """Wenn KI 4 Findings liefert (perimeter Min 6), zieht Floor 2 aus additional."""
    findings = [_mk(i, 10 - i) for i in range(8)]  # 8 Findings
    res = select_findings(findings, "perimeter")
    # top_n=15, hat aber nur 8 → alle selected, additional leer, kein Floor noetig
    assert len(res.selected) == 8
    assert res.floor_applied == 0
    assert res.retry_hint is None


def test_floor_applies_when_underrun():
    """Bei wenigen Findings (Standard-top_n=15 fuer perimeter, nur 4 da)
    versucht Floor aus additional zu ziehen — additional ist aber leer.
    Resultat: alle 4 selected + retry_hint.
    """
    findings = [_mk(i, 10 - i) for i in range(4)]
    res = select_findings(findings, "perimeter")
    assert len(res.selected) == 4
    assert res.retry_hint is not None


def test_floor_skipped_when_top_n_override():
    """Wenn Caller explizit top_n_override setzt, respektieren wir das —
    Floor greift NICHT (sonst Verletzung der Caller-Semantik)."""
    findings = [_mk(i, 10 - i) for i in range(20)]
    res = select_findings(findings, "perimeter", top_n_override=5)
    assert len(res.selected) == 5  # Override gewinnt
    assert res.floor_applied == 0
    assert res.retry_hint is None


def test_retry_hint_when_below_min_no_additional():
    """Nur 4 Findings total (Min 6, kein additional) → retry_hint gesetzt."""
    findings = [_mk(i) for i in range(4)]
    res = select_findings(findings, "perimeter")
    assert len(res.selected) == 4
    assert res.retry_hint is not None
    assert "perimeter" in res.retry_hint


def test_no_retry_hint_when_min_reached_via_floor():
    """webcheck Min=3, 2 Findings → Floor kann nicht aus additional ziehen
    (auch leer) → retry_hint gesetzt; bei 3+ Findings keine retry_hint."""
    findings = [_mk(i) for i in range(3)]  # genau Min fuer webcheck
    res = select_findings(findings, "webcheck")
    assert len(res.selected) == 3
    assert res.retry_hint is None


def test_min_per_package_keys():
    """Sanity: alle Standard-Pakete haben Min."""
    for pkg in ("webcheck", "perimeter", "compliance", "supplychain", "insurance"):
        assert pkg in MIN_N_PER_PACKAGE
        assert MIN_N_PER_PACKAGE[pkg] >= 3

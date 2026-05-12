"""Unit-Tests fuer report-worker/reporter/id_renumber.py (M1 / Doc 01 Phase F)."""

from reporter.id_renumber import remap_recommendation_refs, renumber_findings


def test_gap_free_renumbering():
    """IDs sind nach Renumerierung lueckenlos und in Render-Sortierung."""
    findings = [
        {"id": "VS-2026-008", "severity": "HIGH", "cvss_score": 7.5, "policy_id": "SP-DB-001"},
        {"id": "VS-2026-002", "severity": "MEDIUM", "cvss_score": 5.0, "policy_id": "SP-HDR-001"},
        {"id": "VS-2026-005", "severity": "CRITICAL", "cvss_score": 9.8, "policy_id": "SP-RDP-001"},
    ]
    remap = renumber_findings(findings, year=2026)

    # Reihenfolge der findings-Liste bleibt erhalten (kein in-place-resort),
    # aber die neuen IDs werden in Render-Sortierung vergeben:
    #   CRITICAL -> VS-2026-001
    #   HIGH     -> VS-2026-002
    #   MEDIUM   -> VS-2026-003
    # findings[0] war HIGH       -> VS-2026-002
    # findings[1] war MEDIUM     -> VS-2026-003
    # findings[2] war CRITICAL   -> VS-2026-001
    assert findings[0]["id"] == "VS-2026-002"
    assert findings[1]["id"] == "VS-2026-003"
    assert findings[2]["id"] == "VS-2026-001"

    # external_id muss mit id matchen
    assert findings[0]["external_id"] == findings[0]["id"]
    assert findings[1]["external_id"] == findings[1]["id"]
    assert findings[2]["external_id"] == findings[2]["id"]

    # policy_id bleibt unveraendert (interner Audit-Trail-Anker)
    assert findings[0]["policy_id"] == "SP-DB-001"
    assert findings[1]["policy_id"] == "SP-HDR-001"
    assert findings[2]["policy_id"] == "SP-RDP-001"

    # original_claude_id persistiert
    assert findings[0]["original_claude_id"] == "VS-2026-008"
    assert findings[1]["original_claude_id"] == "VS-2026-002"
    assert findings[2]["original_claude_id"] == "VS-2026-005"

    # remap-dict zeigt Mapping auf neue IDs
    assert remap["VS-2026-008"] == "VS-2026-002"
    assert remap["VS-2026-005"] == "VS-2026-001"
    # VS-2026-002 -> VS-2026-003 (alte ID war 002, neue ist 003)
    assert remap["VS-2026-002"] == "VS-2026-003"


def test_gap_free_sequence():
    """5 Findings mit Luecken in den Claude-IDs werden zu 001..005."""
    findings = [
        {"id": "VS-2026-001", "severity": "CRITICAL", "cvss_score": 10.0, "policy_id": "P1"},
        {"id": "VS-2026-005", "severity": "HIGH", "cvss_score": 8.0, "policy_id": "P2"},
        {"id": "VS-2026-008", "severity": "MEDIUM", "cvss_score": 6.0, "policy_id": "P3"},
        {"id": "VS-2026-011", "severity": "LOW", "cvss_score": 3.0, "policy_id": "P4"},
        {"id": "VS-2026-013", "severity": "INFO", "cvss_score": 0.0, "policy_id": "P5"},
    ]
    renumber_findings(findings, year=2026)

    # Reihenfolge der externer IDs nach Severity:
    # findings[0] CRITICAL -> 001
    # findings[1] HIGH     -> 002
    # findings[2] MEDIUM   -> 003
    # findings[3] LOW      -> 004
    # findings[4] INFO     -> 005
    assert findings[0]["id"] == "VS-2026-001"
    assert findings[1]["id"] == "VS-2026-002"
    assert findings[2]["id"] == "VS-2026-003"
    assert findings[3]["id"] == "VS-2026-004"
    assert findings[4]["id"] == "VS-2026-005"


def test_cvss_tiebreaker_within_severity():
    """Bei gleicher Severity sortiert cvss_score DESC."""
    findings = [
        {"id": "A", "severity": "HIGH", "cvss_score": 7.0, "policy_id": "PA"},
        {"id": "B", "severity": "HIGH", "cvss_score": 8.5, "policy_id": "PB"},
        {"id": "C", "severity": "HIGH", "cvss_score": 7.8, "policy_id": "PC"},
    ]
    renumber_findings(findings, year=2026)
    # B (8.5) > C (7.8) > A (7.0)
    # findings[0] war A (7.0)  -> letzter Platz -> VS-2026-003
    # findings[1] war B (8.5)  -> erster Platz -> VS-2026-001
    # findings[2] war C (7.8)  -> zweiter Platz -> VS-2026-002
    assert findings[0]["id"] == "VS-2026-003"
    assert findings[1]["id"] == "VS-2026-001"
    assert findings[2]["id"] == "VS-2026-002"


def test_remap_recommendation_refs():
    """finding_refs werden synchron auf neue IDs gemappt."""
    recs = [
        {"text": "Fix DB", "finding_refs": ["VS-2026-008", "VS-2026-005"]},
        {"text": "Patch", "finding_refs": ["VS-2026-002"]},
        {"text": "Orphan", "finding_refs": []},
    ]
    remap = {"VS-2026-008": "VS-2026-002", "VS-2026-005": "VS-2026-001"}
    n = remap_recommendation_refs(recs, remap)
    assert n == 2
    assert recs[0]["finding_refs"] == ["VS-2026-002", "VS-2026-001"]
    # VS-2026-002 ist nicht im remap-dict -> bleibt unveraendert
    assert recs[1]["finding_refs"] == ["VS-2026-002"]
    assert recs[2]["finding_refs"] == []


def test_empty_inputs():
    """Leere Inputs liefern leere/null Outputs."""
    assert renumber_findings([], year=2026) == {}
    assert remap_recommendation_refs([], {}) == 0
    assert remap_recommendation_refs([{"finding_refs": ["X"]}], {}) == 0


def test_idempotent_double_run():
    """Mehrfacher Aufruf liefert dieselbe Belegung — wichtig fuer Replay-Tests."""
    findings = [
        {"id": "VS-2026-005", "severity": "HIGH", "cvss_score": 7.5, "policy_id": "SP-DB-001"},
    ]
    renumber_findings(findings, year=2026)
    first_id = findings[0]["id"]
    assert first_id == "VS-2026-001"
    # original_claude_id zeigt nach erstem Run auf alte Claude-ID
    assert findings[0]["original_claude_id"] == "VS-2026-005"

    renumber_findings(findings, year=2026)
    # IDs bleiben stabil (es gibt nur 1 Finding -> immer 001)
    assert findings[0]["id"] == first_id
    # Nach zweitem Run zeigt original_claude_id auf das Ergebnis des ersten Runs
    assert findings[0]["original_claude_id"] == first_id


def test_invalid_cvss_does_not_crash():
    """Defekte cvss_score-Werte (None, str, etc.) werden tolerant gehandhabt."""
    findings = [
        {"id": "A", "severity": "HIGH", "cvss_score": None, "policy_id": "PA"},
        {"id": "B", "severity": "HIGH", "cvss_score": "not-a-number", "policy_id": "PB"},
        {"id": "C", "severity": "HIGH", "cvss_score": "8.5", "policy_id": "PC"},
    ]
    renumber_findings(findings, year=2026)
    # C (8.5) gewinnt; A/B (0.0) entscheiden ueber policy_id-Tiebreaker (PA < PB)
    assert findings[2]["id"] == "VS-2026-001"
    assert findings[0]["id"] == "VS-2026-002"  # PA
    assert findings[1]["id"] == "VS-2026-003"  # PB


def test_year_in_id():
    """Year-Parameter wird korrekt in IDs eingesetzt."""
    findings = [
        {"id": "X", "severity": "HIGH", "cvss_score": 7.0, "policy_id": "P1"},
    ]
    renumber_findings(findings, year=2027)
    assert findings[0]["id"] == "VS-2027-001"
    assert findings[0]["external_id"] == "VS-2027-001"

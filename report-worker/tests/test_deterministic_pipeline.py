"""Tests fuer reporter/deterministic_pipeline.py — Post-Claude Determinismus."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporter.deterministic_pipeline import apply_deterministic_pipeline
from reporter.severity_policy import POLICY_VERSION

FIXTURES = Path(__file__).parent / "fixtures"


def _claude_response_findings():
    return [
        {
            "id": "VS-2026-001",
            "title": "Exponierter MySQL/MariaDB-Port",
            "severity": "HIGH",
            "cvss_score": "8.6",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
            "cwe": "CWE-284",
            "affected": "88.99.35.112:3306 (beispiel.de)",
            "description": "Der MariaDB-Port 3306 ist oeffentlich erreichbar.",
            "evidence": "nmap output...",
            "impact": "Brute-Force-Risiko",
            "recommendation": "Firewall",
        },
        {
            "id": "VS-2026-002",
            "title": "Fehlende Security-Header",
            "severity": "LOW",
            "cvss_score": "3.1",
            "cwe": "CWE-693",
            "affected": "https://beispiel.de",
            "description": (
                "Mehrere empfohlene Security-Header fehlen: "
                "X-Frame-Options, Content-Security-Policy, Referrer-Policy"
            ),
            "evidence": "headers...",
            "impact": "Clickjacking",
            "recommendation": "X-Frame-Options: DENY",
        },
    ]


class TestApplyPipeline:
    def test_sets_policy_version(self):
        claude_output = {"findings": _claude_response_findings()}
        apply_deterministic_pipeline(
            claude_output, package="perimeter", domain="beispiel.de",
        )
        assert claude_output["policy_version"] == POLICY_VERSION

    def test_policy_id_distinct_is_sorted(self):
        claude_output = {"findings": _claude_response_findings()}
        apply_deterministic_pipeline(
            claude_output, package="perimeter", domain="beispiel.de",
        )
        ids = claude_output["policy_id_distinct"]
        assert ids == sorted(ids)
        # Mindestens fuer das HSTS/XFO-Finding muessen wir was haben (oder SP-FALLBACK fuer DB-Port)
        assert len(ids) >= 1

    def test_findings_have_severity_provenance(self):
        claude_output = {"findings": _claude_response_findings()}
        apply_deterministic_pipeline(
            claude_output, package="perimeter", domain="beispiel.de",
        )
        for f in claude_output["findings"]:
            assert "policy_id" in f
            assert "severity_provenance" in f
            assert f["severity_provenance"]["policy_version"] == POLICY_VERSION

    def test_severity_is_uppercase_after_pipeline(self):
        """PDF-Mapper erwartet UPPER-Severity — Pipeline darf das nicht brechen."""
        claude_output = {"findings": _claude_response_findings()}
        apply_deterministic_pipeline(
            claude_output, package="perimeter", domain="beispiel.de",
        )
        for f in claude_output["findings"]:
            assert f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_empty_findings_list_handled(self):
        claude_output = {"findings": []}
        result = apply_deterministic_pipeline(
            claude_output, package="perimeter", domain="example.com",
        )
        assert result["findings"] == []
        assert result["policy_version"] == POLICY_VERSION
        assert result["policy_id_distinct"] == []

    def test_idempotent(self):
        from copy import deepcopy
        co1 = {"findings": _claude_response_findings()}
        co2 = {"findings": _claude_response_findings()}
        apply_deterministic_pipeline(co1, package="perimeter", domain="example.com")
        apply_deterministic_pipeline(co2, package="perimeter", domain="example.com")

        # Severity, policy_id, sortierung sind deterministisch identisch
        assert [f["id"] for f in co1["findings"]] == [f["id"] for f in co2["findings"]]
        assert co1["policy_id_distinct"] == co2["policy_id_distinct"]

    def test_selection_stats_present(self):
        claude_output = {"findings": _claude_response_findings()}
        apply_deterministic_pipeline(
            claude_output, package="perimeter", domain="example.com",
        )
        stats = claude_output["selection_stats"]
        assert stats["original_count"] == 2
        assert stats["selected_count"] <= stats["original_count"]
        assert stats["top_n"] == 15  # perimeter default


class TestRealClaudeFixture:
    def test_pipeline_works_on_real_fixture(self):
        fixture = json.loads((FIXTURES / "claude_response.json").read_text())
        apply_deterministic_pipeline(
            fixture, package="perimeter", domain="beispiel.de",
        )
        assert fixture["policy_version"] == POLICY_VERSION
        # Saemtliche selektierten Findings haben policy_id
        for f in fixture["findings"]:
            assert "policy_id" in f


class TestFindingTypePersisted:
    """Mai 2026 (securess.de-Drift): finding_type muss im Writeback-Schritt
    erhalten bleiben — frueher wurde es vom mapper gesetzt, dann aber im
    `_writeback_to_claude` verworfen, sodass die API fuer ALLE Findings
    `finding_type=null` lieferte."""

    def test_finding_type_in_output(self):
        claude_output = {"findings": _claude_response_findings()}
        apply_deterministic_pipeline(
            claude_output, package="perimeter", domain="beispiel.de",
        )
        for f in claude_output["findings"]:
            # entweder vom Regex-Mapper gesetzt oder von der KI (use_ai_fallback
            # ist default True; in Test-Umgebung ohne API-Key bleibt der
            # Eintrag entweder regex-typed oder ohne finding_type — letzteres
            # ist OK fuer SP-FALLBACK). Wir testen: wenn ein finding_type
            # gesetzt wurde, dann landet er auch im Output.
            if f.get("policy_id") and f.get("policy_id") != "SP-FALLBACK":
                assert f.get("finding_type"), (
                    f"finding_type fehlt obwohl policy_id={f.get('policy_id')}: {f}"
                )

    def test_finding_type_source_marker(self):
        """_finding_type_source landet als Audit-Marker im Output."""
        claude_output = {"findings": _claude_response_findings()}
        apply_deterministic_pipeline(
            claude_output, package="perimeter", domain="beispiel.de",
        )
        for f in claude_output["findings"]:
            if f.get("finding_type"):
                assert f.get("_finding_type_source") in (
                    "regex", "ai_fallback", "preset",
                ), f"Marker fehlt fuer {f}"

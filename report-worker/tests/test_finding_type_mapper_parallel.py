"""F-RPT-004: Parallelisierung des AI-Fallback-Loops im finding_type_mapper.

Verifiziert, dass mehrere Findings in `needs_ai` ueber einen
ThreadPoolExecutor parallel an `map_finding_type_via_ai` uebergeben werden
und dass ein Future-Timeout/Fehler andere Findings nicht abreisst.
"""

import time
from unittest.mock import patch

import pytest

from reporter.finding_type_mapper import annotate_finding_types


def test_ai_fallback_runs_in_parallel():
    """F-RPT-004: bei 5 Findings in needs_ai sollte total time
    deutlich kleiner als 5x single-time sein."""
    findings = [
        {"id": f"f{i}", "title": f"unklarer befund {i}", "description": "",
         "cwe": "", "evidence": ""}
        for i in range(5)
    ]

    def slow_mapper(finding):
        time.sleep(0.5)  # 0.5s per call
        return "csp_missing"

    with patch("reporter.ai_finding_type_fallback.map_finding_type_via_ai",
               side_effect=slow_mapper):
        start = time.monotonic()
        annotate_finding_types(findings, use_ai_fallback=True)
        elapsed = time.monotonic() - start

    # 5 calls x 0.5s sequential = 2.5s. Parallel mit 5 workers = ~0.5s.
    # Generous threshold: <1.5s = parallel.
    assert elapsed < 1.5, f"Loop nicht parallel? Dauerte {elapsed:.2f}s"
    for f in findings:
        assert f.get("finding_type") == "csp_missing"
        assert f.get("_finding_type_source") == "ai_fallback"


@pytest.mark.slow
def test_ai_fallback_individual_timeout_does_not_break_others():
    """F-RPT-004: ein Future-Timeout darf andere Futures nicht abbrechen.

    Hinweis: 15s sleep + 10s `fut.result(timeout=10)` -> Test dauert ~10s.
    Daher als `slow` markiert; per Default mitlaufend, aber via
    `-m 'not slow'` ueberspringbar.
    """
    findings = [
        {"id": "f0", "title": "good", "description": "", "cwe": "", "evidence": ""},
        {"id": "f1", "title": "slow", "description": "", "cwe": "", "evidence": ""},
        {"id": "f2", "title": "good", "description": "", "cwe": "", "evidence": ""},
    ]

    def varied_mapper(finding):
        if finding.get("title") == "slow":
            time.sleep(15)  # > 10s timeout
            return "csp_missing"
        return "hsts_missing"

    with patch("reporter.ai_finding_type_fallback.map_finding_type_via_ai",
               side_effect=varied_mapper):
        annotate_finding_types(findings, use_ai_fallback=True)

    # f0 + f2 sollten gemappt sein, f1 timeout -> kein finding_type
    assert findings[0].get("finding_type") == "hsts_missing"
    assert findings[2].get("finding_type") == "hsts_missing"
    assert not findings[1].get("finding_type")

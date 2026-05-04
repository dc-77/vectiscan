"""Tests fuer qa_check.title_template (Check #9, A1 Polish)."""

from reporter.qa_check import _check_title_template


def test_no_issue_when_template_present():
    findings = [
        {"id": "F1", "policy_id": "SP-DNS-010", "title": "DMARC..."},
    ]
    issues = _check_title_template(findings)
    assert issues == []


def test_issue_when_template_missing_flag():
    findings = [
        {"id": "F1", "policy_id": "SP-XXX-999", "title": "X",
         "_title_template_missing": True},
    ]
    issues = _check_title_template(findings)
    assert len(issues) == 1
    assert issues[0]["check"] == "title_template"
    assert issues[0]["finding_id"] == "F1"
    assert "SP-XXX-999" in issues[0]["issue"]


def test_no_issue_without_policy_id():
    """Findings ohne policy_id sollen nicht den Check triggern."""
    findings = [{"id": "F1", "title": "X"}]
    issues = _check_title_template(findings)
    assert issues == []

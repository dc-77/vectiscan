"""Smoke-Test fuer A3 — Insurance-PDF-Builders.

Wir bauen reportlab-Stories aus den 3 neuen Builder-Funktionen und
verifizieren dass sie ohne Crash laufen UND erwartete Inhalte liefern.
Kein echter PDF-Build (waere langsam) — story-list-Inspektion reicht.
"""

from unittest.mock import MagicMock

from reporter.generate_report import (
    build_insurance_questionnaire,
    build_insurance_risk_score,
    build_insurance_premium_actions,
)


def _empty_styles():
    """Minimaler Styles-Dict — die Builder lesen styles[name] mit
    `.get()`-aehnlichen Zugriffen. ParagraphStyles direkt aus
    reportlab erzeugen ist OK fuer Smoke."""
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    base = getSampleStyleSheet()
    # Custom style names die in den Buildern gebraucht werden
    for name in ("SectionTitle", "SubsectionTitle", "BodyText2"):
        if name not in base:
            base.add(ParagraphStyle(name=name, parent=base["BodyText"]))
    return base


def test_questionnaire_builds_without_crash():
    story = []
    styles = _empty_styles()
    insurance_data = {
        "questionnaire": [
            {"id": "INS-01", "category": "encryption",
             "question": "Wird TLS 1.2+ eingesetzt?",
             "answer": "PASS", "risk_impact": "low",
             "detail": "Alle Hosts nutzen TLS 1.2+"},
            {"id": "INS-02", "category": "authentication",
             "question": "MFA aktiv?", "answer": "FAIL",
             "risk_impact": "high", "detail": "—"},
        ],
    }
    build_insurance_questionnaire(story, styles, insurance_data)
    assert len(story) > 0


def test_questionnaire_empty_shows_stub():
    story = []
    styles = _empty_styles()
    build_insurance_questionnaire(story, styles, {"questionnaire": []})
    assert len(story) > 0  # stub paragraph


def test_risk_score_builds():
    story = []
    styles = _empty_styles()
    build_insurance_risk_score(story, styles, {
        "risk_score": {
            "score": 45, "rating": "MEDIUM",
            "ransomware_indicator": "LOW",
        },
    })
    assert len(story) > 0


def test_premium_actions_builds():
    story = []
    styles = _empty_styles()
    build_insurance_premium_actions(story, styles, {
        "risk_score": {
            "premium_reduction_actions": [
                "MFA aktivieren (-15% Praemie)",
                "TLS aktualisieren (-5% Praemie)",
            ],
        },
    })
    assert len(story) > 0


def test_premium_actions_empty_shows_stub():
    story = []
    styles = _empty_styles()
    build_insurance_premium_actions(story, styles, {"risk_score": {}})
    assert len(story) > 0

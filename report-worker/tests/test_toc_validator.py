"""Tests fuer A4 — TOC-Validator."""

from reporter.generate_report import _validate_toc


def test_drops_insurance_when_data_missing():
    rd = {"toc": [
        ("1", "Zusammenfassung", False),
        ("5", "Versicherungs-Fragebogen", False),
        ("6", "Risikobewertung", False),
        ("7", "Massnahmen zur Praemienreduktion", False),
    ]}
    _validate_toc(rd, insurance_data=None, nis2=None)
    titles = [t[1] for t in rd["toc"]]
    assert "Zusammenfassung" in titles
    assert "Versicherungs-Fragebogen" not in titles
    assert "Risikobewertung" not in titles
    assert "Massnahmen zur Praemienreduktion" not in titles


def test_keeps_insurance_when_data_present():
    rd = {"toc": [
        ("1", "Z", False),
        ("5", "Versicherungs-Fragebogen", False),
        ("6", "Risikobewertung", False),
    ]}
    _validate_toc(
        rd,
        insurance_data={"questionnaire": [{"id": "INS-01"}],
                         "risk_score": {"score": 50}},
        nis2=None,
    )
    titles = [t[1] for t in rd["toc"]]
    assert "Versicherungs-Fragebogen" in titles
    assert "Risikobewertung" in titles


def test_drops_audit_trail_when_missing():
    rd = {"toc": [("1", "Z", False), ("A", "Audit-Trail", False)]}
    _validate_toc(rd, None, None)
    assert all("Audit-Trail" not in t[1] for t in rd["toc"])


def test_keeps_audit_trail_when_present():
    rd = {"toc": [("1", "Z", False), ("A", "Audit-Trail", False)]}
    _validate_toc(rd, None, nis2={"audit_trail": {"scan_start": "x"}})
    assert any("Audit-Trail" in t[1] for t in rd["toc"])


def test_drops_supply_chain_when_missing():
    rd = {"toc": [("1", "Z", False), ("A", "Lieferketten-Zusammenfassung", False)]}
    _validate_toc(rd, None, None)
    assert all("Lieferketten" not in t[1] for t in rd["toc"])


def test_no_toc_no_op():
    rd = {}
    _validate_toc(rd, None, None)
    assert rd == {}

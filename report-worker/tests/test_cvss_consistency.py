"""Tests fuer reporter/cvss_consistency.py (M2 Track 2a)."""
import pytest
from reporter.cvss_consistency import (
    normalize_vector, is_zero_impact_vector, score_from_vector,
    apply_consistency, is_hygiene_finding, hygiene_level_for,
)


def test_normalize_adds_prefix():
    assert normalize_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") \
        == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_normalize_keeps_prefix():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert normalize_vector(v) == v


def test_normalize_upgrades_cvss30_to_31():
    v_in = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    v_out = normalize_vector(v_in)
    assert v_out.startswith("CVSS:3.1/")


def test_normalize_handles_empty():
    assert normalize_vector(None) is None
    assert normalize_vector("") is None
    assert normalize_vector("—") is None


def test_zero_impact_vector():
    assert is_zero_impact_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert not is_zero_impact_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")


def test_score_from_vector_critical():
    s = score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert s == 9.8


def test_score_from_vector_invalid_returns_none():
    assert score_from_vector("not-a-vector") is None


def test_apply_consistency_hygiene_finding():
    f = {
        "id": "VS-1",
        "finding_type": "cookie_missing_secure",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",  # mathematisch ~4.3
        "cvss_score": 0.0,
        "severity": "INFO",
    }
    apply_consistency(f)
    assert f["scale"] == "hygiene"
    assert f["cvss_vector"] is None
    assert f["cvss_score"] is None
    assert f["hygiene_level"] == "high"
    assert f["score_provenance"] == "hygiene_skala"


def test_apply_consistency_zero_impact_falls_through_to_hygiene():
    # P1-01 Fallcase: Vektor sagt 0-Impact, Tool gibt Score 0.0 -- wir wollen
    # diese Findings NICHT mit CVSS 0.0 weiterführen.
    f = {
        "id": "VS-2",
        "finding_type": "unknown_minor",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "cvss_score": 0.0,
        "severity": "INFO",
    }
    apply_consistency(f)
    assert f["scale"] == "hygiene"
    assert f["hygiene_level"] == "low"


def test_apply_consistency_real_cvss_finding():
    f = {
        "id": "VS-3",
        "finding_type": "rdp_exposed",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.0,  # Tool-Wert leicht daneben
        "severity": "CRITICAL",
    }
    apply_consistency(f)
    assert f["scale"] == "cvss"
    assert f["cvss_vector"].startswith("CVSS:3.1/")
    assert f["cvss_score"] == 9.8
    assert f["score_provenance"] == "vector"


def test_apply_consistency_p1_02_score_vector_divergence():
    f = {
        "id": "VS-014",
        "finding_type": "cleartext_login",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cvss_score": 3.7,  # falsch -- Vektor ergibt 5.3
        "severity": "LOW",
    }
    apply_consistency(f)
    assert f["cvss_score"] == 5.3  # Score wurde aus Vektor neu berechnet


def test_hygiene_level_lookup():
    assert hygiene_level_for("cookie_missing_secure") == "high"
    assert hygiene_level_for("header_xcto_missing") == "low"
    assert hygiene_level_for("unknown_finding") is None

"""S1: Schema-Eigenschaften von facts.json (pydantic, IDs, Pflichtfelder)."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from reporter.facts import schema as S
from reporter.facts.serialize import dumps, ip_token, iso_utc, excerpt, sort_key


def _minimal_facts() -> S.Facts:
    scan = S.ScanFact(id="scan:x", source="meta", mode="active", observed_at="2026-08-31T14:41:05Z",
                      confidence=1.0, order_id="x", package="perimeter", domain="example.test")
    return S.Facts(generator=S.Generator(name="t", version="0"), scan=scan)


def test_roundtrip_und_versionsfeld():
    f = _minimal_facts()
    data = f.to_dict()
    assert data["schema_version"] == S.FACTS_SCHEMA_VERSION
    again = S.Facts.from_dict(data)
    assert again.to_dict() == data


def test_unbekannte_felder_werden_abgelehnt():
    f = _minimal_facts()
    data = f.to_dict()
    data["scan"]["severity"] = "HIGH"
    with pytest.raises(ValidationError):
        S.Facts.from_dict(data)


def test_confidence_bereich():
    with pytest.raises(ValidationError):
        S.HostFact(id="host:1", source="nmap", mode="active", confidence=1.5, ip="1.2.3.4", family=4)


def test_jedes_faktum_hat_pflichtfelder():
    for name in S.Facts.ENTITY_FIELDS:
        model = S.Facts.model_fields[name].annotation.__args__[0]
        assert issubclass(model, S.Fact), name
        for field in ("id", "source", "mode", "observed_at", "confidence", "evidence"):
            assert field in model.model_fields, f"{name}.{field}"


def test_ipv6_id_token():
    assert ip_token("2a01:4f8:d0a:3124::2") == "[2a01:4f8:d0a:3124::2]"
    assert ip_token("188.40.3.130") == "188.40.3.130"


@pytest.mark.parametrize("value,expected", [
    ("2026-08-31T14:37:46.048213794Z", "2026-08-31T14:37:46Z"),
    ("2026-08-31T14:10:43.827615+00:00", "2026-08-31T14:10:43Z"),
    ("2026-08-31T14:10:43.899Z", "2026-08-31T14:10:43Z"),
    ("1788185800", "2026-08-31T14:16:40Z"),
    (1788185800, "2026-08-31T14:16:40Z"),
    ("2026-08-31T16:10:43+02:00", "2026-08-31T14:10:43Z"),
    (None, None),
    ("kein datum", None),
])
def test_iso_utc(value, expected):
    assert iso_utc(value) == expected


def test_excerpt_normalisiert_ansi_und_laenge():
    text = "\x1b[1m TLS 1 \x1b[m  offered\r\n   (deprecated)"
    assert excerpt(text) == "TLS 1 offered (deprecated)"
    assert len(excerpt("x" * 1000)) == 300


def test_sort_key_none_sicher():
    rows = [("b", None), (None, 3), ("a", 2)]
    assert sorted(rows, key=lambda r: sort_key(*r)) == [(None, 3), ("a", 2), ("b", None)]


def test_dumps_deterministisch():
    f = _minimal_facts()
    a = dumps(f.to_dict())
    b = dumps(S.Facts.from_dict(f.to_dict()).to_dict())
    assert a == b
    assert a.endswith("\n") and "\r" not in a

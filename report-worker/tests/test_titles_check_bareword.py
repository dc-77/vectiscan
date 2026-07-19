"""Regression: der titles-Validation-Check darf legitime Ports/Versionen/IPs im
Title NICHT als "Bareword-Number" flaggen (Juli 2026).

Hintergrund: Die hier getesteten realen Titel blockierten Perimeter-Scans am
Validation-Gate (dortmund-beach.com, securess.de). Ursachen im Check:
- Version-Regex `\\d+\\.\\d+` erfasste 3-teilige Versionen (3.4.1) nur halb -> ".1"
  blieb als vermeintliche Bareword-Number uebrig.
- Nicht-Standard-Ports (Webmin 10000) fehlten in der Known-Ports-Liste.
Fix: mehrteilige Version/IP-Regex + "Port"-Kontext-Erkennung.
"""
from reporter.validation.checks.titles import check


def _bareword_ids(titles):
    findings = {"findings": [{"id": f"f{i}", "title": t} for i, t in enumerate(titles)]}
    issues = check(findings, {}, {})
    return {i.finding_id for i in issues if "Bareword" in i.message}


def test_port_context_not_flagged():
    # Webmin-Port 10000 hat "Port"-Kontext -> legitim; IP darf ebenfalls nicht flaggen.
    assert _bareword_ids([
        "Webmin-Verwaltungsoberfläche (Port 10000) öffentlich erreichbar auf 88.99.35.112",
    ]) == set()


def test_multipart_version_not_flagged():
    # 3-teilige Versionen vollstaendig als Version erkennen (nicht das letzte Segment flaggen).
    assert _bareword_ids([
        "Veraltete jQuery-Migrate-Bibliothek 3.4.1 auf example.com",
        "testssl 2.4.49 veraltet",
    ]) == set()


def test_ipv4_not_flagged():
    assert _bareword_ids(["Dienst auf 88.99.35.112 erreichbar"]) == set()


def test_real_bareword_still_flagged():
    # Gegenprobe: eine echte kontextlose Zahl MUSS weiterhin geflaggt werden.
    assert _bareword_ids(["Auffälliger Wert 42 im Banner"]) == {"f0"}

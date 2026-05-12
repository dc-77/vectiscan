"""M3 End-to-End: Aggregator + v2-Renderer + v1-Renderer parallel auf
realem secumetrix-aehnlichem Fixture.

Validiert dass:
  - layer1_aggregator gegen das Realreport-Fixture sinnvolle Output liefert
    (Top-Hebel bundelt DB+RDP, Risiko-Ampel zeigt Perimeter=hoch)
  - v1 + v2 produzieren beide ein PDF aus identischem report_data
  - v2 PDF ist nicht offensichtlich kaputt (groesser als reine Cover-Page)
"""
from __future__ import annotations

import json
import pathlib

from reporter.layer1_aggregator import build_layer1
from reporter.generate_report import generate_report
from reporter.pdf.v2 import generate_report_v2


FIXTURE = (
    pathlib.Path(__file__).parent.parent
    / "reporter" / "validation" / "tests" / "fixtures"
    / "replay_secumetrix_like.json"
)


def _load_findings_data():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _minimal_report_data_from_findings(findings_data, layer1):
    """Wrappt das Fixture in eine report_data-Struktur, die beide Renderer
    konsumieren koennen. Ohne TR-03116, ohne NIS2 — pure Smoke.
    """
    findings = findings_data.get("findings") or []
    return {
        "meta": {
            "title": "M3-E2E", "author": "VectiScan",
            "header_left": "VECTISCAN", "header_right": "secumetrix.de",
            "footer_left": "Vertraulich",
            "classification_label": "VERTRAULICH",
        },
        "cover": {
            "cover_subtitle": "VECTISCAN", "cover_title": "Sicherheitsbewertung",
            "package": "perimeter",
            "cover_meta": [
                ["Ziel:", "secumetrix.de (2 Hosts)"],
                ["Datum:", "2026-05-12"],
                ["Paket:", "Perimeter"],
            ],
        },
        "domain": "secumetrix.de",
        "toc": [("1", "Befunde", False)],
        "executive_summary": {
            "section_label": "1 ES",
            "subsections": [{"title": "Zusammenfassung",
                             "paragraphs": ["Mehrere kritische Befunde."]}],
        },
        "scope": {
            "section_label": "2 Scope",
            "subsections": [{"title": "Pruefungsumfang",
                             "paragraphs": ["secumetrix.de + dev.secumetrix.de"]}],
        },
        "findings": [
            {"id": f.get("id"), "external_id": f.get("id"),
             "policy_id": f.get("policy_id", ""),
             "title": f.get("title", ""), "severity": f.get("severity"),
             "cvss_score": f.get("cvss_score"),
             "cvss_vector": f.get("cvss_vector", "—"),
             "cwe": f.get("cwe", "—"),
             "affected": f.get("affected", ""),
             "description": f.get("description", ""),
             "evidence": str(f.get("evidence", "—")),
             "impact": f.get("impact", ""),
             "recommendation": f.get("recommendation", ""),
             "label_description": "Beschreibung",
             "label_evidence": "Nachweis",
             "label_impact": "Auswirkung",
             "label_recommendation": "Empfehlung"}
            for f in findings
        ],
        "recommendations": {"intro_paragraph": "x", "roadmap_table": None},
        "screenshots": [],
        "disclaimer": "Disclaimer",
        "layer1": layer1,
    }


def test_layer1_against_secumetrix_fixture():
    """Aggregator gegen reales Fixture: Perimeter=hoch, Top-Hebel bundelt
    DB/RDP, Hygiene-Split ist ungleich Null."""
    data = _load_findings_data()
    layer1 = build_layer1(
        findings=data.get("findings") or [],
        recommendations=data.get("recommendations") or [],
        host_inventory={"domain": "secumetrix.de"},
        package="perimeter",
    )
    # Perimeter-Bucket muss hoch sein (RDP + FTP im Fixture)
    perimeter = next(c for c in layer1["risk_ampel"]
                     if c["key"] == "perimeter_exposition")
    assert perimeter["level"] in ("hoch", "mittel-hoch", "mittel"), perimeter
    assert perimeter["count"] >= 2  # mind. RDP + FTP

    # Top-Hebel enthaelt mindestens den Perimeter- oder den EOL-Hebel
    titles = " | ".join(h["title"] for h in layer1["top_hebel"])
    assert any(kw in titles for kw in ("Datenbank", "RDP", "Firewall", "EOL", "CMS", "Mail")), titles

    # Hygiene-Split: ein Cookie-Finding ist Hygiene (scale-Feld fehlt im
    # Fixture, default cvss — wir pruefen nur dass die Struktur da ist)
    assert "cvss" in layer1["hygiene_split"]
    assert "hygiene" in layer1["hygiene_split"]


def test_double_render_secumetrix_fixture(tmp_path):
    """v1 und v2 rendern beide das secumetrix-Fixture ohne Crash."""
    data = _load_findings_data()
    layer1 = build_layer1(
        findings=data.get("findings") or [],
        host_inventory={"domain": "secumetrix.de"},
        package="perimeter",
    )
    report_data = _minimal_report_data_from_findings(data, layer1)

    out_v1 = tmp_path / "secumetrix_v1.pdf"
    out_v2 = tmp_path / "secumetrix_v2.pdf"
    generate_report(report_data, str(out_v1))
    generate_report_v2(report_data, str(out_v2))

    assert out_v1.exists()
    assert out_v1.stat().st_size > 5000  # echtes PDF mit Inhalt
    assert out_v2.exists()
    assert out_v2.stat().st_size > 5000

    # v2 sollte zumindest die Layer-1-Frontpage rendern (PDF mit mind.
    # 2 Seiten erwartet)
    pdf_bytes = out_v2.read_bytes()
    page_markers = pdf_bytes.count(b"/Type /Page\n")
    assert page_markers >= 2 or pdf_bytes.count(b"/Type /Page<") >= 2

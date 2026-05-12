"""Schicht 3 -- Befund-Details (Doc 02 Seite 11+).

Pro Befund: Header (FindingHeaderV2) + 7-Sektionen-Body:

  WAS               - description
  NACHWEIS          - evidence (mono-style)
  THREAT INTEL      - CVE-IDs, EPSS, KEV (P2-02 / Phase H)
  GESCHAEFTSAUSWIRKUNG - impact
  EMPFEHLUNG        - recommendation (Maerker mit Prioritaet)
  VERIFIKATION      - aus verification_templates.py
  INTERNE REFERENZ  - policy_id + policy_version
"""
from __future__ import annotations

from typing import Any

from reportlab.platypus import (
    Paragraph, Spacer, PageBreak, Table, TableStyle, KeepTogether,
)
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor

from reporter.pdf.branding import COLORS
from reporter.pdf.v2.flowables import FindingHeaderV2
from reporter.verification_templates import get_verification_block


# ====================================================================
# DRINGLICHKEITS-ABBILDUNG (Doc 02 Seite 10/11)
# ====================================================================
_SEV_TO_PRIORITY: dict[str, str] = {
    "CRITICAL": "Unverzueglich",
    "HIGH":     "Unverzueglich",
    "MEDIUM":   "In Kuerze",
    "LOW":      "Mittelfristig",
    "INFO":     "Strategisch",
}

_SEV_TO_RISIKO: dict[str, str] = {
    "CRITICAL": "KRITISCH",
    "HIGH":     "HOCH",
    "MEDIUM":   "MITTEL",
    "LOW":      "NIEDRIG",
    "INFO":     "INFO",
}


# ====================================================================
# THREAT-INTEL EXTRAKTION
# ====================================================================
def _normalize_cve_entries(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """Liefert eine Liste {cve_id, epss_score, kev}, sortiert EPSS DESC.

    Quellen pro Finding:
      1. finding["cves"]            : list[str] ODER list[dict]
      2. finding["cve_id"]          : einzelner string -> Single-Entry
      3. finding["threat_intel"]    : {epss_score, in_kev, ...}  (Single-CVE-Shape)
      4. finding["enrichment"]      : {cisa_kev, epss: {epss: 0.7}} (struct)
      5. finding["correlation_data"]: nested

    Maximal Top-3 nach EPSS-Score, KEV-Findings bekommen Vorrang bei
    gleichem Score.
    """
    out: list[dict[str, Any]] = []

    # 1. finding["cves"] (Hauptquelle nach tech_table_builder)
    cves_field = finding.get("cves")
    if isinstance(cves_field, list):
        for c in cves_field:
            if isinstance(c, dict) and c.get("cve_id"):
                out.append({
                    "cve_id": str(c["cve_id"]),
                    "epss_score": _coerce_float(c.get("epss_score")),
                    "kev": bool(c.get("kev") or c.get("in_kev")),
                })
            elif isinstance(c, str) and c:
                out.append({
                    "cve_id": c,
                    "epss_score": None,
                    "kev": False,
                })

    # 2. Single cve_id Felder
    single_cve = finding.get("cve_id") or finding.get("cve")
    if single_cve and not any(e["cve_id"] == single_cve for e in out):
        ti = _extract_threat_intel(finding)
        out.append({
            "cve_id": str(single_cve),
            "epss_score": ti["epss_score"],
            "kev": ti["kev"],
        })

    # 3. Strukturierte threat_intel ohne Bezug zur CVE-ID — wenn die CVE-Liste
    # leer ist, aber threat_intel KEV signalisiert, zeigen wir das mindestens
    # als 'CVE-Treffer (Top 3)'-Zeile.
    if not out:
        ti = _extract_threat_intel(finding)
        if ti["epss_score"] is not None or ti["kev"]:
            out.append({
                "cve_id": "(unspezifiziert)",
                "epss_score": ti["epss_score"],
                "kev": ti["kev"],
            })

    # 4. correlation_data ist heute selten als finding-Attribut sichtbar, aber
    # falls vorhanden, mergen wir EPSS/KEV in den ersten Eintrag.
    corr = finding.get("correlation_data")
    if isinstance(corr, dict) and out:
        if out[0]["epss_score"] is None:
            out[0]["epss_score"] = _coerce_float(corr.get("epss_score"))
        if not out[0]["kev"]:
            out[0]["kev"] = bool(corr.get("kev") or corr.get("in_kev"))

    # Sortieren: KEV zuerst (bei Tie), dann EPSS DESC, dann CVE-ID ASC.
    out.sort(key=lambda e: (
        0 if e.get("kev") else 1,
        -float(e.get("epss_score") or 0.0),
        str(e.get("cve_id") or ""),
    ))
    return out[:3]


def _extract_threat_intel(finding: dict[str, Any]) -> dict[str, Any]:
    """Extrahiert {epss_score, kev} aus den verschiedenen Threat-Intel-Shapes."""
    ti = finding.get("threat_intel") or finding.get("enrichment") or {}
    if not isinstance(ti, dict):
        return {"epss_score": None, "kev": False}

    # KEV
    kev = bool(
        ti.get("in_kev")
        or ti.get("kev_in")
        or ti.get("kev") is True
        or (isinstance(ti.get("cisa_kev"), dict) and ti.get("cisa_kev"))
    )

    # EPSS — simple or structured
    epss: float | None = None
    epss_simple = ti.get("epss_score")
    if isinstance(epss_simple, (int, float)):
        epss = float(epss_simple)
    elif isinstance(ti.get("epss"), dict):
        try:
            epss = float(ti["epss"].get("epss") or 0.0) or None
        except (ValueError, TypeError):
            epss = None
    elif isinstance(ti.get("epss"), (int, float)):
        epss = float(ti["epss"])

    return {"epss_score": epss, "kev": kev}


def _coerce_float(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (ValueError, TypeError):
        return None


# ====================================================================
# RENDER-HELPER
# ====================================================================
def _body_style(styles):
    return styles.get("BodyText2") or styles["BodyText"]


def _label_style(styles):
    return styles.get("FindingLabel") or styles.get("SubsectionTitle") \
        or styles["BodyText"]


def _evidence_style(styles):
    return styles.get("Evidence") or styles["BodyText"]


def _section_label(story, styles, label: str) -> None:
    story.append(Paragraph(f"<b>{label}</b>", _label_style(styles)))


def _section_body(story, styles, text: str) -> None:
    text = (text or "—").strip()
    if not text:
        text = "—"
    story.append(Paragraph(text, _body_style(styles)))


def _section_evidence(story, styles, text: str) -> None:
    text = (text or "—").strip()
    if not text:
        text = "—"
    # Reportlab: <br/> fuer Zeilenumbruch im Paragraph
    text = text.replace("\n", "<br/>")
    story.append(Paragraph(text, _evidence_style(styles)))


# ====================================================================
# 7-SEKTIONEN-BODY
# ====================================================================
def _render_threat_intel(story, styles, finding: dict[str, Any]) -> None:
    """THREAT INTELLIGENCE-Sektion (Doc 01 P2-02 / Phase H).

    Erscheint nur, wenn mindestens eine CVE oder EPSS/KEV-Daten vorhanden.
    Sonst wird die Sektion weggelassen — Doc 02 wuerde sonst pro Header-Finding
    eine leere Box zeigen.
    """
    entries = _normalize_cve_entries(finding)
    if not entries:
        return

    _section_label(story, styles, "THREAT INTELLIGENCE")

    kev_any = any(e.get("kev") for e in entries)
    if kev_any:
        kev_badge = (
            "<font color='#DC2626'><b>CISA KEV - aktiv ausgenutzt</b></font>"
        )
    else:
        kev_badge = "CISA KEV: nein"

    lines: list[str] = []
    if len(entries) > 1:
        lines.append("CVE-Treffer (Top 3 nach EPSS-Score):")
    else:
        lines.append("CVE-Treffer:")
    for e in entries:
        epss = e.get("epss_score")
        bits = [str(e.get("cve_id") or "")]
        if isinstance(epss, (int, float)):
            bits.append(f"EPSS {epss:.2f}")
            if epss >= 0.5:
                bits.append("(Top-Risikobereich)")
        if e.get("kev"):
            bits.append("<b>KEV</b>")
        lines.append("&nbsp;&nbsp;&#8226; " + " &middot; ".join(bits))
    lines.append("")
    lines.append(kev_badge)

    _section_body(story, styles, "<br/>".join(lines))
    story.append(Spacer(1, 2 * mm))


def _render_compliance_inline(
    story, styles, finding: dict[str, Any],
    mappings: dict[str, Any] | None,
) -> None:
    """Optional: kompakte Compliance-Zeile pro Finding (Vorbereitung Anhang D).

    Wenn `report_data["compliance_mappings"][finding_id]` vorhanden ist, zeigen
    wir hier eine 4-Spalten-Inline-Tabelle. Sonst weggelassen — der vollstaendige
    Anhang D rendert die Tabelle erneut.
    """
    if not mappings:
        return
    fid = finding.get("id") or finding.get("external_id") or ""
    m = mappings.get(fid)
    if not isinstance(m, dict):
        return

    nis2 = m.get("nis2") or "—"
    iso = m.get("iso27001") or "—"
    bsi = m.get("bsi") or "—"
    dsgvo = m.get("dsgvo") or "—"

    _section_label(story, styles, "COMPLIANCE")

    header_style = styles.get("TableHeader") or styles["BodyText"]
    cell_style = styles.get("TableCell") or styles["BodyText"]
    rows = [
        [
            Paragraph("<b>NIS2 / §30 BSIG</b>", header_style),
            Paragraph("<b>BSI-Grundschutz</b>", header_style),
            Paragraph("<b>ISO 27001</b>", header_style),
            Paragraph("<b>DSGVO</b>", header_style),
        ],
        [
            Paragraph(str(nis2), cell_style),
            Paragraph(str(bsi), cell_style),
            Paragraph(str(iso), cell_style),
            Paragraph(str(dsgvo), cell_style),
        ],
    ]
    t = Table(rows, colWidths=[42 * mm, 42 * mm, 42 * mm, 44 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLORS["primary"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLORS["white"]),
        ("GRID", (0, 0), (-1, -1), 0.4, COLORS["light_accent"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t)
    story.append(Spacer(1, 2 * mm))


def _build_single_finding(
    story, styles, finding: dict[str, Any],
    policy_version: str,
    scan_context: dict[str, Any] | None,
    compliance_mappings: dict[str, Any] | None,
) -> None:
    """Rendert einen kompletten Befund mit Header + 7 Sektionen."""
    fid = finding.get("external_id") or finding.get("id") or "VS-?"
    title = finding.get("title") or "(ohne Titel)"
    severity = (finding.get("severity") or "INFO").upper()
    priority = _SEV_TO_PRIORITY.get(severity, "Mittelfristig")
    risiko = _SEV_TO_RISIKO.get(severity, "INFO")
    policy_id = finding.get("policy_id") or ""

    # Header + Spacer als KeepTogether, damit zumindest Header+WAS auf einer
    # Seite bleiben (Doc 02 Seite 11+: Befund-Block).
    header_group = []
    header_group.append(FindingHeaderV2(
        finding_id=str(fid),
        title=str(title),
        priority=priority,
        risk=risiko,
        policy_id=str(policy_id) if policy_id else None,
    ))
    header_group.append(Spacer(1, 4 * mm))

    # CVSS + CWE Inline-Meta wenn vorhanden
    cvss_vector = finding.get("cvss_vector")
    cvss_score = finding.get("cvss_score")
    cwe = finding.get("cwe")
    affected = finding.get("affected")
    meta_bits: list[str] = []
    if affected and affected not in ("—", "", "N/A"):
        meta_bits.append(f"<b>Betroffene Systeme:</b> {affected}")
    if cvss_vector and cvss_vector not in ("—", "", "N/A"):
        meta_bits.append(
            f"<b>CVSS:</b> {cvss_score} ({cvss_vector})"
            if cvss_score not in (None, "—", "")
            else f"<b>CVSS-Vektor:</b> {cvss_vector}"
        )
    if cwe and cwe not in ("—", "", "N/A"):
        meta_bits.append(f"<b>CWE:</b> {cwe}")
    if meta_bits:
        body_style = _body_style(styles)
        header_group.append(Paragraph(
            "&nbsp;&nbsp;|&nbsp;&nbsp;".join(meta_bits),
            body_style,
        ))
        header_group.append(Spacer(1, 2 * mm))

    # WAS — direkt mit dem Header in einer KeepTogether-Gruppe
    description = finding.get("description") or "—"
    header_group.append(Paragraph(
        f"<b>WAS WURDE GEFUNDEN</b>", _label_style(styles),
    ))
    header_group.append(Paragraph(str(description), _body_style(styles)))
    story.append(KeepTogether(header_group))
    story.append(Spacer(1, 2 * mm))

    # NACHWEIS
    _section_label(story, styles, "NACHWEIS")
    evidence_raw = finding.get("evidence") or "—"
    _section_evidence(story, styles, str(evidence_raw))
    story.append(Spacer(1, 2 * mm))

    # THREAT INTELLIGENCE (optional)
    _render_threat_intel(story, styles, finding)

    # GESCHAEFTSAUSWIRKUNG
    _section_label(story, styles, "GESCHAEFTSAUSWIRKUNG")
    _section_body(story, styles, finding.get("impact") or "—")
    story.append(Spacer(1, 2 * mm))

    # EMPFEHLUNG
    _section_label(story, styles, "EMPFEHLUNG")
    rec = finding.get("recommendation") or "—"
    # Prio-Praefix (Doc 02 Seite 11+: "Sofort:" / "In Kuerze:" als Maerker)
    prefix_map = {
        "Unverzueglich": "Sofort: ",
        "In Kuerze":     "In Kuerze: ",
        "Mittelfristig": "Mittelfristig: ",
        "Strategisch":   "Strategisch: ",
    }
    rec_text = f"<b>{prefix_map.get(priority, '')}</b>{rec}"
    _section_body(story, styles, rec_text)
    story.append(Spacer(1, 2 * mm))

    # COMPLIANCE (inline, Anhang D bietet die volle Tabelle)
    _render_compliance_inline(story, styles, finding, compliance_mappings)

    # VERIFIKATION
    verification_text, is_fallback = get_verification_block(finding, scan_context)
    _section_label(story, styles, "VERIFIKATION")
    if is_fallback:
        _section_body(story, styles,
                      "<i>Generischer Hinweis (kein spezifischer Befehl hinterlegt):</i>")
        _section_body(story, styles, verification_text)
    else:
        _section_evidence(story, styles, verification_text)
    story.append(Spacer(1, 2 * mm))

    # INTERNE REFERENZ
    _section_label(story, styles, "INTERNE REFERENZ")
    if policy_id:
        ref_text = (
            f"Severity-Policy: <b>{policy_id}</b> &middot; "
            f"Version {policy_version}"
        )
    else:
        ref_text = (
            f"Severity-Policy: <i>kein policy_id zugeordnet</i> &middot; "
            f"Version {policy_version}"
        )
    _section_body(story, styles, ref_text)
    story.append(Spacer(1, 6 * mm))


# ====================================================================
# ENTRY-POINT
# ====================================================================
def build_layer3_findings(story, styles, data: dict[str, Any]) -> None:
    """Schicht 3: Befund-Details (Doc 02 Seite 11+).

    Erwartet `data["findings"]` als bereits gemappte Finding-Liste.
    `data["methodology_stats"]["policy_version"]` wird als interne Referenz
    angezeigt.
    """
    findings = (data or {}).get("findings") or []
    if not findings:
        return

    section_style = styles.get("SectionTitle") or styles["BodyText"]
    story.append(Paragraph("<b>BEFUND-DETAILS</b>", section_style))
    story.append(Spacer(1, 3 * mm))

    body_style = _body_style(styles)
    story.append(Paragraph(
        "Pro Befund: Was wurde gefunden, wie wurde es nachgewiesen, welche "
        "Threat-Intel ist relevant, was bedeutet es geschaeftlich, was ist zu "
        "tun, wie verifiziert der Admin den Fix, und wo ist die interne "
        "Referenz im Audit-Trail.",
        body_style,
    ))
    story.append(Spacer(1, 4 * mm))

    policy_version = (
        (data.get("methodology_stats") or {}).get("policy_version")
        or "unbekannt"
    )

    # Scan-Context fuer Verifikations-Template-Var-Substitution
    scope = data.get("scope_meta") or {}
    scan_context = {
        "domain": scope.get("domain") or data.get("domain") or "",
    }

    compliance_mappings = data.get("compliance_mappings")

    for finding in findings:
        if finding.get("is_positive_finding"):
            continue
        _build_single_finding(
            story, styles, finding,
            policy_version=str(policy_version),
            scan_context=scan_context,
            compliance_mappings=compliance_mappings if isinstance(
                compliance_mappings, dict) else None,
        )

    story.append(PageBreak())

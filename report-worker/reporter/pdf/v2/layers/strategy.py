"""Schicht 2 -- Strategie-Ebene (Doc 02 Seite 3-9).

Diese Schicht ist fuer den IT-Verantwortlichen geschrieben. Sie liefert:

  Seite 3   - Geschaeftskontext (Doc 02 Seite 3)
  Seite 4-5 - Umfang + Methodik (Doc 02 Seite 4-5)
  Seite 6   - Tech-Stack pro Host (Doc 02 Seite 6)
  Seite 7   - Service-Karte + Posture-Indikatoren (Doc 02 Seite 6-7)
  Seite 8-9 - Befund-Landschaft (Doc 02 Seite 8-9)

Die fachlichen Daten kommen aus dem v2-Augment-Step in report_mapper.
Diese Datei ist reines Rendering.
"""
from __future__ import annotations

from typing import Any

from reportlab.platypus import Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib.units import mm

from reporter.pdf.branding import COLORS
from reporter.pdf.v2.flowables import (
    PostureIndicator, ServiceCard, KategorieBlock,
)


# ====================================================================
# RENDERING-HELPER
# ====================================================================
def _section(story, styles, title: str) -> None:
    section_style = styles.get("SectionTitle") or styles["BodyText"]
    story.append(Paragraph(f"<b>{title}</b>", section_style))


def _subsection(story, styles, title: str) -> None:
    subsec_style = styles.get("SubsectionTitle") or styles["BodyText"]
    story.append(Paragraph(f"<b>{title}</b>", subsec_style))


def _body(story, styles, text: str, key: str = "BodyText2") -> None:
    body_style = styles.get(key) or styles["BodyText"]
    story.append(Paragraph(text, body_style))


# ====================================================================
# SEITE 3 - GESCHAEFTSKONTEXT (Track 4b)
# ====================================================================
def _build_business_context(story, styles, data: dict[str, Any]) -> None:
    bc = data.get("business_context")
    if not bc:
        return  # keine Kontext-Seite ohne Daten

    _section(story, styles, "GESCHAEFTSKONTEXT")
    story.append(Spacer(1, 3 * mm))

    cluster_label = bc.get("cluster_label") or "Branchenkontext"
    _body(
        story, styles,
        f"<b>Branchenkontext:</b> {cluster_label}",
    )
    story.append(Spacer(1, 2 * mm))

    narrative = bc.get("narrative") or ""
    if narrative:
        _body(story, styles, narrative)

    # Datenarten + konkret beobachtete Apps
    data_kinds = bc.get("data_kinds") or []
    if data_kinds:
        story.append(Spacer(1, 3 * mm))
        _body(
            story, styles,
            "<b>Betroffene Datenarten (Annahme aus Branche und beobachteten "
            "Anwendungen):</b>",
        )
        for kind in data_kinds:
            _body(story, styles, f"&#8226; {kind}")

    observed_apps = bc.get("observed_apps") or []
    if observed_apps:
        story.append(Spacer(1, 2 * mm))
        _body(
            story, styles,
            "<b>Konkret im Scan beobachtet:</b> "
            + "; ".join(observed_apps),
        )

    compliance_focus = bc.get("compliance_focus") or ()
    if compliance_focus:
        story.append(Spacer(1, 3 * mm))
        _body(
            story, styles,
            "<b>Compliance-Fokus:</b> " + ", ".join(compliance_focus),
        )

    story.append(PageBreak())


# ====================================================================
# SEITE 4-5 - UMFANG + METHODIK (Track 4c)
# ====================================================================
def _build_scope_methodology(story, styles, data: dict[str, Any]) -> None:
    scope = data.get("scope_meta") or {}
    method = data.get("methodology_stats") or {}
    host_inventory = data.get("_host_inventory") or {}

    _section(story, styles, "UMFANG &amp; METHODIK")
    story.append(Spacer(1, 3 * mm))

    # 2.1 Pruefungsumfang
    _subsection(story, styles, "Pruefungsumfang")
    story.append(Spacer(1, 2 * mm))
    domain = scope.get("domain", "?")
    hosts_count = scope.get("hosts_count", "?")
    subdomains_count = scope.get("subdomains_count", "?")
    scan_date = scope.get("scan_date", "?")
    _body(
        story, styles,
        f"Pruefziel: <b>{domain}</b>. Im Rahmen der Reconnaissance wurden "
        f"<b>{subdomains_count} Subdomains</b> identifiziert, davon "
        f"<b>{hosts_count} aktive Hosts</b> in die aktive Pruefung "
        f"einbezogen.",
    )
    _body(
        story, styles,
        f"<b>Scan-Datum:</b> {scan_date}. Reconnaissance, "
        f"Technologie-Erkennung, Tiefenscan und Korrelation liefen in "
        f"derselben Pipeline-Ausfuehrung."
    )

    out_of_scope = scope.get("out_of_scope") or ()
    if out_of_scope:
        story.append(Spacer(1, 2 * mm))
        _body(
            story, styles,
            "<b>Nicht Bestandteil dieser Pruefung waren:</b> "
            + ", ".join(out_of_scope) + ".",
        )

    # 2.2 Methodik
    story.append(Spacer(1, 4 * mm))
    _subsection(story, styles, "Methodik")
    story.append(Spacer(1, 2 * mm))
    _body(
        story, styles,
        "Die Pruefung lief als automatisierter Scan nach dem PTES-Standard "
        "(Penetration Testing Execution Standard). Sie umfasst vier Phasen:",
    )
    for phase in method.get("phases") or []:
        _body(
            story, styles,
            f"<b>{phase.get('name', '')}:</b> {phase.get('description', '')}",
        )

    # 2.2.1 KI + Severity-Policy
    story.append(Spacer(1, 3 * mm))
    _body(
        story, styles,
        "<b>Was 'KI' in diesem Scan konkret tut:</b>",
    )
    for model in method.get("ai_models") or []:
        _body(
            story, styles,
            f"&#8226; <b>{model.get('name', '')}</b> ({model.get('model_id', '')}): "
            f"{model.get('role', '')}",
        )

    # 2.2.2 Filter-Statistik
    filtered = method.get("filtered_count", 0)
    selected = method.get("selected_count", 0)
    rate = method.get("filter_rate_pct", 0.0)
    if (filtered + selected) > 0:
        story.append(Spacer(1, 2 * mm))
        _body(
            story, styles,
            f"<b>Korrelation und False-Positive-Filterung:</b> Aus insgesamt "
            f"<b>{filtered + selected}</b> Tool-Roh-Befunden wurden "
            f"<b>{selected}</b> validierte Befunde uebernommen "
            f"(Filterrate: {rate}%). Die ausgefilterten Roh-Befunde sind in "
            f"Anhang E aufgeschluesselt.",
        )

    # 2.3 Was leistet dieser Scan nicht?
    story.append(Spacer(1, 4 * mm))
    _subsection(story, styles, "Was leistet dieser Scan nicht?")
    note = method.get("out_of_scope_note") or ""
    if note:
        _body(story, styles, note)

    story.append(PageBreak())


# ====================================================================
# SEITE 6 - TECH-STACK PRO HOST (Track 4d)
# ====================================================================
def _patch_status_label(status: str) -> str:
    return {
        "eol":       "EOL",
        "minor_eol": "Minor-EOL",
        "outdated":  "veraltet",
        "current":   "aktuell",
        "aktuell":   "aktuell",
        "unbekannt": "unbekannt",
    }.get((status or "").lower(), status or "?")


def _patch_status_color_hex(status: str) -> str:
    return {
        "eol":       "#DC2626",
        "minor_eol": "#F97316",
        "outdated":  "#CA8A04",
        "current":   "#16A34A",
        "aktuell":   "#16A34A",
        "unbekannt": "#64748B",
    }.get((status or "").lower(), "#64748B")


def _build_tech_stack(story, styles, data: dict[str, Any]) -> None:
    tables = data.get("tech_table_v2") or []
    if not tables:
        return
    _section(story, styles, "ARCHITEKTUR-SICHT")
    story.append(Spacer(1, 3 * mm))
    _subsection(story, styles, "Tech-Stack pro Host")
    story.append(Spacer(1, 2 * mm))

    body_style = styles.get("BodyText2") or styles["BodyText"]
    header_style = styles.get("TableHeader") or styles["BodyText"]
    cell_style = styles.get("TableCell") or styles["BodyText"]

    for tbl in tables:
        host_label = tbl.get("host_label", "?")
        story.append(Paragraph(f"<b>{host_label}</b>", body_style))
        story.append(Spacer(1, 1 * mm))
        header = [
            Paragraph("<b>Komponente</b>", header_style),
            Paragraph("<b>Version</b>", header_style),
            Paragraph("<b>Erkennung</b>", header_style),
            Paragraph("<b>Patch-Status</b>", header_style),
            Paragraph("<b>Bekannte CVEs</b>", header_style),
        ]
        rows = [header]
        for r in tbl.get("rows") or []:
            name = r.get("name", "?")
            version = r.get("version", "—") or "—"
            det_source = r.get("detection_source") or r.get("source") or ""
            conf = r.get("confidence_label") or ""
            detection_text = (
                f"{det_source} ({conf})" if det_source and conf else det_source or "—"
            )
            patch_status = r.get("patch_status") or r.get("status") or "?"
            patch_label = _patch_status_label(patch_status)
            patch_color = _patch_status_color_hex(patch_status)
            patch_para = Paragraph(
                f"<font color='{patch_color}'><b>{patch_label}</b></font>",
                cell_style,
            )
            top_cve = r.get("top_cve")
            if top_cve and top_cve.get("cve_id"):
                cve_id = top_cve.get("cve_id")
                epss = top_cve.get("epss_score")
                kev = top_cve.get("kev")
                cve_text = cve_id
                extras = []
                if epss is not None:
                    extras.append(f"EPSS {epss:.2f}")
                if kev:
                    extras.append("<b>KEV</b>")
                if extras:
                    cve_text += " (" + ", ".join(extras) + ")"
            else:
                cve_text = "—"
            rows.append([
                Paragraph(str(name), cell_style),
                Paragraph(str(version), cell_style),
                Paragraph(detection_text, cell_style),
                patch_para,
                Paragraph(cve_text, cell_style),
            ])
        table = Table(rows, colWidths=[
            45 * mm, 25 * mm, 30 * mm, 25 * mm, 45 * mm,
        ], hAlign="LEFT")
        table.setStyle(TableStyle([
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
        story.append(table)
        story.append(Spacer(1, 4 * mm))


# ====================================================================
# SEITE 7 - SERVICE-KARTE + POSTURE-INDIKATOREN (Track 4d)
# ====================================================================
def _build_service_cards(story, styles, data: dict[str, Any]) -> None:
    cards = data.get("service_cards") or []
    if not cards:
        return
    _subsection(story, styles, "Exponierte Dienste - Service-Karte")
    story.append(Spacer(1, 2 * mm))
    for card in cards:
        story.append(ServiceCard(
            host_label=card.get("host_label", "?"),
            ports=card.get("ports") or [],
        ))
        story.append(Spacer(1, 4 * mm))
    # Legende
    _body(
        story, styles,
        "<font color='#DC2626'><b>rot</b></font> = direkt riskanter Port "
        "(DB/RDP/SMB/...), "
        "<font color='#F97316'><b>orange</b></font> = Klartext-Protokoll, "
        "<font color='#22C55E'><b>gruen</b></font> = unauffaellig.",
    )


def _build_posture_indicators(story, styles, data: dict[str, Any]) -> None:
    indicators = data.get("posture_indicators") or []
    if not indicators:
        return
    story.append(Spacer(1, 4 * mm))
    _subsection(story, styles, "Posture-Indikatoren")
    story.append(Spacer(1, 2 * mm))
    for ind in indicators:
        story.append(PostureIndicator(
            label=ind.get("label", "?"),
            items=ind.get("items") or [],
        ))
        story.append(Spacer(1, 1 * mm))


# ====================================================================
# SEITE 8-9 - BEFUND-LANDSCHAFT (Track 4d)
# ====================================================================
def _build_befund_landschaft(story, styles, data: dict[str, Any]) -> None:
    landschaft = data.get("befund_landschaft") or {}
    cats = landschaft.get("categories") or []
    positives = landschaft.get("positive_findings") or []
    if not cats and not positives:
        return

    story.append(PageBreak())
    _section(story, styles, "BEFUND-LANDSCHAFT")
    story.append(Spacer(1, 2 * mm))
    _body(
        story, styles,
        "Die folgende Kategorisierung gruppiert die Befunde nach "
        "Massnahmenkategorie - <i>nicht</i> nach CVSS-Score. So sieht der "
        "IT-Verantwortliche auf einen Blick, welche Aktion mehrere Befunde "
        "gleichzeitig adressiert.",
    )
    story.append(Spacer(1, 3 * mm))

    for cat in cats:
        story.append(KategorieBlock(
            category_label=cat.get("label", "?"),
            count=cat.get("count", 0),
            schwerpunkt=cat.get("schwerpunkt", "?"),
            finding_titles=[
                (f.get("id", "?"), f.get("title", "(ohne Titel)"))
                for f in cat.get("findings") or []
            ],
        ))
        story.append(Spacer(1, 3 * mm))

    if positives:
        story.append(Spacer(1, 4 * mm))
        _subsection(story, styles, f"POSITIVE BEFUNDE ({len(positives)})")
        for pf in positives:
            _body(story, styles, f"&#8226; {pf.get('title', '')}")


# ====================================================================
# ENTRY-POINT
# ====================================================================
def build_layer2_strategy(story, styles, data):
    """Doc 02 Seite 3-9: Geschaeftskontext + Methodik + Architektur + Befund-Landschaft."""
    data = data or {}
    _build_business_context(story, styles, data)
    _build_scope_methodology(story, styles, data)
    _build_tech_stack(story, styles, data)
    _build_service_cards(story, styles, data)
    _build_posture_indicators(story, styles, data)
    _build_befund_landschaft(story, styles, data)
    story.append(PageBreak())

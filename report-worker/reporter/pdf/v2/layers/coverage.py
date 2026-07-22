"""C3 — Kapitel "Was wurde geprueft — und was nicht".

Rendert die Host-Status-Tabelle (drei Zustaende: Befund / unauffaellig /
nicht pruefbar) und die Tool-x-Host-Matrix. Datenquelle ist ausschliesslich
``data["scan_coverage"]`` (aggregiert in ``reporter/coverage.py``). Ist das
Feld ``None`` oder leer, wird das Kapitel komplett uebersprungen — kein halbes
Kapitel, das PDF baut trotzdem.

Reines Rendering, Farben ausschliesslich aus branding.COLORS.
"""
from __future__ import annotations

from typing import Any

from reportlab.platypus import Paragraph, Spacer, PageBreak
from reportlab.lib.units import mm

from reporter.pdf.branding import COLORS
from reporter.pdf.v2.flowables import data_table, chunked_matrix_tables


# ====================================================================
# RENDERING-HELPER (lokal, analog strategy.py:37-49)
# ====================================================================
def _section(story, styles, title: str) -> None:
    section_style = styles.get("SectionTitle") or styles["BodyText"]
    story.append(Paragraph(f"<b>{title}</b>", section_style))


def _subsection(story, styles, title: str) -> None:
    subsec_style = styles.get("SubsectionTitle") or styles["BodyText"]
    story.append(Paragraph(f"<b>{title}</b>", subsec_style))


def _body(story, styles, text: str) -> None:
    body_style = styles.get("BodyText2") or styles["BodyText"]
    story.append(Paragraph(text, body_style))


def _hex(color: Any) -> str:
    """ReportLab-Color -> ``#RRGGBB`` (Hex-Strings aus COLORS ableiten, nicht
    literal tippen)."""
    try:
        return "#{:02X}{:02X}{:02X}".format(
            int(round(color.red * 255)),
            int(round(color.green * 255)),
            int(round(color.blue * 255)),
        )
    except Exception:  # pragma: no cover - Absicherung
        return "#000000"


# Zustands-Farben (aus COLORS, nicht hart kodiert).
_STATE_COLOR = {
    "befund": COLORS["critical"],
    "unauffaellig": COLORS["low"],
    "nicht_pruefbar": COLORS["muted"],
}

# Matrix-Zell-Darstellung: (Symbol, Farbe). ok/fail/skip/n_a.
_CELL_GLYPH = {
    "ok": ("✓", COLORS["low"]),        # ✓ gruen
    "fail": ("✗", COLORS["critical"]),  # ✗ rot
    "skip": ("○", COLORS["muted"]),     # ○ grau (uebersprungen)
    "n/a": ("–", COLORS["light_accent"]),  # – nicht ausgefuehrt
}


def _colored(text: str, color: Any, bold: bool = False) -> str:
    inner = f"<b>{text}</b>" if bold else text
    return f'<font color="{_hex(color)}">{inner}</font>'


# ====================================================================
# ENTRY-POINT
# ====================================================================
def build_coverage_chapter(story, styles, data: dict[str, Any]) -> None:
    """Rendert das Abdeckungskapitel. No-op bei fehlendem scan_coverage."""
    data = data or {}
    coverage = data.get("scan_coverage")
    if not coverage:
        # Degradation: kein Kapitel, kein halber Abschnitt (Muster
        # strategy.py:227-228). Das PDF baut trotzdem.
        return

    hosts = coverage.get("hosts") or []
    matrix = coverage.get("matrix") or {}
    totals = coverage.get("totals") or {}
    if not hosts:
        return

    _section(story, styles, "WAS WURDE GEPRÜFT — UND WAS NICHT")
    story.append(Spacer(1, 3 * mm))

    # -- Einleitung mit den echten Zahlen (kein Boilerplate ohne Bezug) ----
    _build_intro(story, styles, totals)

    # -- Host-Status-Tabelle ------------------------------------------------
    story.append(Spacer(1, 3 * mm))
    _subsection(story, styles, "Host-Abdeckung")
    story.append(Spacer(1, 2 * mm))
    _build_host_table(story, styles, hosts)

    # -- Tool-x-Host-Matrix -------------------------------------------------
    _build_matrix(story, styles, matrix)

    story.append(PageBreak())


def _build_intro(story, styles, totals: dict[str, Any]) -> None:
    total = totals.get("hosts_total", 0)
    befund = totals.get("hosts_with_findings", 0)
    clean = totals.get("hosts_clean", 0)
    not_testable = totals.get("hosts_not_testable", 0)
    runs = totals.get("tool_runs_total", 0)
    runs_failed = totals.get("tool_runs_failed", 0)

    _body(
        story, styles,
        "Dieser Abschnitt macht transparent, welche Hosts tatsaechlich geprueft "
        "wurden und welche nicht — und warum. Ein Host gilt als "
        "<b>Befund</b>, wenn mindestens eine Schwachstelle gefunden wurde; als "
        "<b>unauffaellig</b>, wenn er erfolgreich geprueft wurde, ohne dass "
        "etwas zu beanstanden war; als <b>nicht pruefbar</b>, wenn kein "
        "erfolgreicher Pruefschritt zustande kam (mit Angabe des Grundes).",
    )
    story.append(Spacer(1, 2 * mm))
    _body(
        story, styles,
        f"Von <b>{total}</b> identifizierten Hosts wiesen "
        f"{_colored(str(befund), _STATE_COLOR['befund'], bold=True)} einen "
        f"Befund auf, "
        f"{_colored(str(clean), _STATE_COLOR['unauffaellig'], bold=True)} "
        f"blieben unauffaellig und "
        f"{_colored(str(not_testable), _STATE_COLOR['nicht_pruefbar'], bold=True)} "
        f"waren nicht pruefbar. Insgesamt wurden <b>{runs}</b> Tool-Laeufe "
        f"protokolliert, davon <b>{runs_failed}</b> fehlgeschlagen.",
    )


def _build_host_table(story, styles, hosts: list[dict[str, Any]]) -> None:
    cell_style = styles.get("TableCell") or styles["BodyText"]

    rows: list[list[Any]] = []
    for h in hosts:
        state = h.get("state", "nicht_pruefbar")
        color = _STATE_COLOR.get(state, COLORS["muted"])
        status_label = h.get("state_label", state)
        status_cell = Paragraph(
            _colored(status_label, color, bold=True), cell_style,
        )

        fids = h.get("finding_ids") or []
        finding_count = h.get("finding_count", len(fids))
        befunde_cell = str(finding_count) if finding_count else "—"

        if state == "befund" and fids:
            hint = ", ".join(fids[:5])
            if len(fids) > 5:
                hint += f" (+{len(fids) - 5})"
        elif state == "nicht_pruefbar":
            hint = h.get("reason") or "Grund nicht protokolliert"
        else:
            hint = "—"

        rows.append([
            h.get("host_label", h.get("ip", "?")),
            status_cell,
            befunde_cell,
            hint,
        ])

    data_table(
        story, styles,
        ["Host", "Status", "Befunde", "Begruendung / Hinweis"],
        rows,
        [60 * mm, 28 * mm, 22 * mm, 60 * mm],
    )


def _build_matrix(story, styles, matrix: dict[str, Any]) -> None:
    tools = matrix.get("tools") or []
    cols = matrix.get("hosts") or []
    cells = matrix.get("cells") or {}
    tool_phase = matrix.get("tool_phase") or {}
    col_labels = matrix.get("host_labels") or {}

    if not tools or not cols:
        return

    cell_style = styles.get("TableCell") or styles["BodyText"]

    story.append(Spacer(1, 4 * mm))
    _subsection(story, styles, "Tool-Abdeckung pro Host")
    story.append(Spacer(1, 1 * mm))
    _body(
        story, styles,
        "Die Matrix zeigt fuer jeden protokollierten Pruefschritt, ob er auf "
        "dem jeweiligen Host erfolgreich lief, fehlschlug oder gar nicht "
        "ausgefuehrt wurde. Nur tatsaechlich protokollierte Tools sind "
        "aufgefuehrt.",
    )
    story.append(Spacer(1, 2 * mm))

    # Zeilen-Labels: Phase-Praefix + Tool.
    row_labels: dict[str, str] = {}
    for t in tools:
        ph = tool_phase.get(t)
        prefix = f"P{ph} " if ph is not None else ""
        row_labels[t] = f"{prefix}{t}"

    def _cell_renderer(tool: str, col: str) -> Paragraph:
        state = (cells.get(tool) or {}).get(col, "n/a")
        glyph, color = _CELL_GLYPH.get(state, _CELL_GLYPH["n/a"])
        return Paragraph(
            f'<font color="{_hex(color)}"><b>{glyph}</b></font>', cell_style,
        )

    chunks = chunked_matrix_tables(
        label_header="Tool",
        row_keys=list(tools),
        row_labels=row_labels,
        col_keys=list(cols),
        col_labels=col_labels,
        cell_renderer=_cell_renderer,
        max_cols=6,
    )
    total_cols = len(cols)
    for chunk in chunks:
        if total_cols > 6:
            _body(story, styles,
                  f"<i>{chunk['range_label']}</i>")
            story.append(Spacer(1, 1 * mm))
        data_table(
            story, styles,
            chunk["header"], chunk["rows"], chunk["col_widths"],
        )
        story.append(Spacer(1, 2 * mm))

    # Legende.
    ok_g, ok_c = _CELL_GLYPH["ok"]
    fail_g, fail_c = _CELL_GLYPH["fail"]
    skip_g, skip_c = _CELL_GLYPH["skip"]
    na_g, na_c = _CELL_GLYPH["n/a"]
    _body(
        story, styles,
        "<b>Legende:</b> "
        f"{_colored(ok_g, ok_c, bold=True)} erfolgreich · "
        f"{_colored(fail_g, fail_c, bold=True)} fehlgeschlagen · "
        f"{_colored(skip_g, skip_c, bold=True)} uebersprungen · "
        f"{_colored(na_g, na_c, bold=True)} nicht ausgefuehrt. "
        "Die Spalte „scanweit“ fasst Pruefschritte ohne Host-Bezug "
        "zusammen (z. B. Subdomain-Enumeration).",
    )


__all__ = ["build_coverage_chapter"]

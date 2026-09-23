"""Subscription Status-Report PDF Generator (PR-Posture, 2026-05-03).

Erzeugt einen periodischen/on-demand/eskalations-PDF-Report fuer eine
Subscription mit aggregierten Posture-Daten aus consolidated_findings,
posture_history und subscription_posture.

Nicht zu verwechseln mit `generate_report.py` — der ist pro Scan/Order.
Hier ist die Einheit die SUBSCRIPTION ueber alle Scans.

Aufruf via Job-Queue:
    process_status_report_job({
        "subscriptionId": "...",
        "triggerReason": "scheduled" | "on_demand" | "critical_escalation",
        "requestedBy": "<user_uuid>" | None,
        "periodStart": "<iso8601>" | None,  # default: started_at
        "periodEnd":   "<iso8601>" | None,  # default: now
    })

Aufruf von Hand (Ops-Job ops-status-report):
    python -m reporter.status_report_generator --subscription <id> [--pdf <pfad>]

Output: PDF in MinIO unter `subscription-reports/<sub_id>/<report_id>.pdf`,
plus Eintrag in subscription_status_reports.

Issue #29 (S6a): der Job ist seit seiner Einfuehrung nie durchgelaufen.
`COLORS` aus branding.py sind Color-Objekte, `HexColor()` darum warf einen
TypeError in der ersten Stildefinition. Dahinter lagen zwei weitere Fehler:
MinIO ohne Port (die Verbindung ging auf 80) und Datenwerte, die ungeschuetzt
in ReportLab-Markup landeten (ein `<` oder `&` im Titel bricht den Parser).
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from xml.sax.saxutils import escape

import psycopg2
import psycopg2.extras
import structlog

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    Paragraph, Spacer, Table, TableStyle, PageBreak,
    SimpleDocTemplate,
)

from reporter.pdf.branding import (
    COLORS, COMPANY_NAME,
    FONT_BODY, FONT_HEADING, FONT_SIZE_BODY, FONT_SIZE_HEADING1,
    FONT_SIZE_HEADING2,
)

log = structlog.get_logger()

# Anzeigetexte. Die Datenwerte (Severity, Intervall, Ausloeser) bleiben in der
# DB englische Codes; im PDF steht Deutsch.
TRIGGER_LABELS = {
    "scheduled": "planmäßig",
    "on_demand": "auf Anforderung",
    "critical_escalation": "Eskalation wegen eines kritischen Befunds",
}
INTERVAL_LABELS = {"weekly": "wöchentlich", "monthly": "monatlich", "quarterly": "vierteljährlich"}
SEVERITY_LABELS = {"CRITICAL": "kritisch", "HIGH": "hoch", "MEDIUM": "mittel", "LOW": "niedrig", "INFO": "Hinweis"}
TREND_LABELS = {"improving": "verbessernd", "stable": "stabil", "degrading": "verschlechternd"}
CLASSIFICATION_TEXT = "Klassifizierung: vertraulich, nur für autorisierte Empfänger"

# Dieselbe Bedingung wie api/src/lib/scheduler.ts tickStatusReports().
DUE_INTERVALS = {"weekly": 7, "monthly": 30, "quarterly": 90}


def _e(value: Any) -> str:
    """Datenwert fuer ReportLab-Markup schuetzen."""
    return escape("" if value is None else str(value))


def _severity(value: Any) -> str:
    return SEVERITY_LABELS.get(str(value or "").upper(), _e(value))


# ============================================================================
# Datenbeschaffung
# ============================================================================

def _load_subscription_data(conn, subscription_id: str) -> Optional[dict]:
    """Hole Subscription-Stammdaten + Posture + Findings + History."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """SELECT s.id, s.package, s.scan_interval, s.started_at, s.expires_at,
                      c.email AS customer_email, c.company_name
                 FROM subscriptions s
                 JOIN customers c ON c.id = s.customer_id
                WHERE s.id = %s""",
            (subscription_id,),
        )
        sub = cur.fetchone()
        if not sub:
            return None

        cur.execute(
            "SELECT * FROM subscription_posture WHERE subscription_id = %s",
            (subscription_id,),
        )
        posture = cur.fetchone()

        cur.execute(
            """SELECT id, host_ip, vhost, finding_type, port_or_path, status, severity,
                      cvss_score, title, description, first_seen_at, last_seen_at,
                      resolved_at, risk_accepted_at, risk_accepted_reason
                 FROM consolidated_findings
                WHERE subscription_id = %s
                ORDER BY
                  CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                                WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
                  first_seen_at DESC""",
            (subscription_id,),
        )
        findings = cur.fetchall()

        cur.execute(
            """SELECT snapshot_at, posture_score, severity_counts,
                      new_findings, resolved_findings, regressed_findings
                 FROM posture_history
                WHERE subscription_id = %s
                ORDER BY snapshot_at""",
            (subscription_id,),
        )
        history = cur.fetchall()

        cur.execute(
            """SELECT canonical FROM scan_targets
                WHERE subscription_id = %s AND status = 'approved'
                ORDER BY canonical""",
            (subscription_id,),
        )
        targets = [r["canonical"] for r in cur.fetchall()]

    return {
        "subscription": dict(sub),
        "posture": dict(posture) if posture else None,
        "findings": [dict(f) for f in findings],
        "history": [dict(h) for h in history],
        "targets": targets,
    }


def _scheduled_report_due(conn, subscription_id: str) -> bool:
    """Ist ein planmaessiger Bericht (noch) faellig?

    Der Scheduler stellt jede Minute einen Job ein, solange
    `last_status_report_at` leer oder aelter als das Intervall ist. Laeuft der
    Worker gerade einen langen Auftragsbericht, stauen sich diese Jobs; ohne
    diese Pruefung erzeugte jeder davon einen eigenen Bericht.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT scan_interval, last_status_report_at FROM subscriptions WHERE id = %s",
            (subscription_id,),
        )
        row = cur.fetchone()
    if not row:
        return False
    interval, last = row[0], row[1]
    if last is None:
        return True
    days = DUE_INTERVALS.get(interval)
    if days is None:
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - last).total_seconds() > days * 86400


# ============================================================================
# Trend-Chart als matplotlib-Image
# ============================================================================

def _generate_trend_chart_png(history: list[dict]) -> Optional[bytes]:
    """Posture-Score-Verlauf als PNG-Bytes. Returns None bei < 2 Punkten."""
    if len(history) < 2:
        return None
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates

        ts = [h["snapshot_at"] for h in history]
        scores = [float(h["posture_score"]) for h in history]

        fig, ax = plt.subplots(figsize=(7, 2.5), dpi=120)
        ax.plot(ts, scores, marker="o", linewidth=2, color="#0EA5E9")
        ax.set_ylim(0, 100)
        ax.set_ylabel("Posture-Score")
        ax.set_title("Sicherheits-Status im Zeitverlauf")
        ax.grid(True, alpha=0.3)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%d.%m"))
        fig.autofmt_xdate()
        fig.tight_layout()

        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        plt.close(fig)
        return buf.getvalue()
    except Exception as e:
        log.warning("trend_chart_failed", error=str(e))
        return None


# ============================================================================
# PDF-Builder
# ============================================================================

def _build_pdf_bytes(data: dict, period_start: datetime, period_end: datetime,
                     trigger_reason: str) -> bytes:
    """Generiere PDF in-memory, return bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=20 * mm, bottomMargin=20 * mm,
        title="VectiScan Statusbericht",
    )

    # COLORS sind bereits Color-Objekte (branding.py), kein HexColor() darum.
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontName=FONT_HEADING,
                        fontSize=FONT_SIZE_HEADING1, textColor=COLORS["primary"])
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontName=FONT_HEADING,
                        fontSize=FONT_SIZE_HEADING2, textColor=COLORS["primary"])
    body = ParagraphStyle("body", parent=styles["BodyText"], fontName=FONT_BODY,
                          fontSize=FONT_SIZE_BODY, textColor=COLORS["text"],
                          alignment=TA_LEFT, leading=14)
    score_style = ParagraphStyle("score", parent=body, fontSize=48,
                                 alignment=TA_CENTER, leading=52,
                                 textColor=COLORS["primary"])

    story: list = []
    sub = data["subscription"]
    posture = data["posture"] or {}
    findings = data["findings"]
    history = data["history"]

    # ---- Deckblatt ----
    interval = INTERVAL_LABELS.get(sub.get("scan_interval"), _e(sub.get("scan_interval")))
    story.append(Paragraph(f"<b>{_e(COMPANY_NAME)}</b> Statusbericht", h1))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        f"Abonnement: {_e(str(sub.get('package') or '').capitalize())} ({interval})", body))
    story.append(Paragraph(f"Kunde: {_e(sub.get('company_name') or sub.get('customer_email'))}", body))
    story.append(Paragraph(
        f"Berichtszeitraum: {period_start:%d.%m.%Y} bis {period_end:%d.%m.%Y}", body))
    story.append(Paragraph(
        f"Anlass: {TRIGGER_LABELS.get(trigger_reason, _e(trigger_reason))}", body))
    story.append(Paragraph(f"Erstellt am: {datetime.now(timezone.utc):%d.%m.%Y %H:%M} UTC", body))
    story.append(Spacer(1, 10 * mm))

    score = posture.get("posture_score")
    if score is not None:
        story.append(Paragraph("Aktueller Posture-Score:", body))
        story.append(Paragraph(f"<b>{int(round(float(score)))} / 100</b>", score_style))
        trend = posture.get("trend_direction") or "unknown"
        trend_label = TREND_LABELS.get(trend, "unbekannt")
        story.append(Paragraph(f"Trend: <b>{trend_label}</b>", body))
    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph(f"<i>{CLASSIFICATION_TEXT}</i>", body))
    story.append(PageBreak())

    # ---- Zusammenfassung ----
    story.append(Paragraph("Zusammenfassung", h1))
    story.append(Spacer(1, 4 * mm))
    sc = posture.get("severity_counts") or {}
    if isinstance(sc, str):
        try:
            sc = json.loads(sc)
        except Exception:
            sc = {}
    open_counts = (sc.get("open") or {})
    summary_rows = [
        ["Kategorie", "Anzahl"],
        ["Offene Befunde (gesamt)", str(sc.get("total_open", 0))],
        ["  davon kritisch", str(open_counts.get("CRITICAL", 0))],
        ["  davon hoch", str(open_counts.get("HIGH", 0))],
        ["  davon mittel", str(open_counts.get("MEDIUM", 0))],
        ["  davon niedrig", str(open_counts.get("LOW", 0))],
        ["Behoben (kumuliert)", str(sc.get("resolved_total", 0))],
        ["Wieder aufgetreten (kumuliert)", str(sc.get("regressed_total", 0))],
        ["Risiko akzeptiert", str(sc.get("accepted_total", 0))],
    ]
    t = Table(summary_rows, colWidths=[80 * mm, 30 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLORS["primary"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
        ("FONTNAME", (0, 0), (-1, -1), FONT_BODY),
        ("FONTSIZE", (0, 0), (-1, -1), FONT_SIZE_BODY),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
        ("ALIGN", (1, 1), (1, -1), "RIGHT"),
    ]))
    story.append(t)
    story.append(Spacer(1, 8 * mm))

    # Delta zum vorherigen Snapshot
    if len(history) >= 2:
        last = history[-1]
        story.append(Paragraph(
            f"Im letzten Scan: <b>{_e(last.get('new_findings'))} neu</b>, "
            f"<b>{_e(last.get('resolved_findings'))} behoben</b>, "
            f"<b>{_e(last.get('regressed_findings'))} wieder aufgetreten</b>.", body,
        ))

    # ---- Trend-Chart ----
    chart_png = _generate_trend_chart_png(history)
    if chart_png:
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph("Verlauf des Posture-Scores", h2))
        from reportlab.platypus import Image as RLImage
        img_buf = io.BytesIO(chart_png)
        story.append(RLImage(img_buf, width=170 * mm, height=60 * mm))

    story.append(PageBreak())

    # ---- Offene Befunde ----
    # Tabellenzellen sind reine Zeichenketten, kein Markup: dort braucht es
    # keine Maskierung, ReportLab setzt sie woertlich.
    open_findings = [f for f in findings if f["status"] in ("open", "regressed")]
    story.append(Paragraph(f"Offene Befunde ({len(open_findings)})", h1))
    if open_findings:
        rows = [["Stufe", "Host", "Befund", "Erstes Auftreten"]]
        for f in open_findings[:50]:  # cap
            rows.append([
                SEVERITY_LABELS.get(str(f.get("severity") or "").upper(), str(f.get("severity") or "")),
                str(f["host_ip"])[:25],
                (f["title"] or "")[:60],
                (f["first_seen_at"]).strftime("%d.%m.%Y") if f["first_seen_at"] else "-",
            ])
        ft = Table(rows, colWidths=[18 * mm, 35 * mm, 87 * mm, 30 * mm])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLORS["primary"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
            ("FONTNAME", (0, 0), (-1, -1), FONT_BODY),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, HexColor("#cccccc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(ft)
        if len(open_findings) > 50:
            story.append(Spacer(1, 3 * mm))
            story.append(Paragraph(f"... und {len(open_findings) - 50} weitere", body))
    else:
        story.append(Paragraph("Keine offenen Befunde im aktuellen Scan.", body))
    story.append(PageBreak())

    # ---- Behoben im Berichtszeitraum ----
    resolved_period = [
        f for f in findings
        if f["status"] == "resolved"
        and f.get("resolved_at")
        and period_start <= f["resolved_at"] <= period_end
    ]
    story.append(Paragraph(f"Behoben im Berichtszeitraum ({len(resolved_period)})", h2))
    if resolved_period:
        for f in resolved_period[:30]:
            story.append(Paragraph(
                f"<b>{_severity(f['severity'])}</b> · {_e(f['host_ip'])} · {_e(f['title'])}", body))
    else:
        story.append(Paragraph("Keine Befunde im Berichtszeitraum behoben.", body))
    story.append(Spacer(1, 6 * mm))

    # ---- Wieder aufgetreten ----
    regressed = [f for f in findings if f["status"] == "regressed"]
    if regressed:
        story.append(Paragraph(f"Wieder aufgetretene Befunde ({len(regressed)})", h2))
        for f in regressed[:30]:
            story.append(Paragraph(
                f"<b>{_severity(f['severity'])}</b> · {_e(f['host_ip'])} · {_e(f['title'])}", body))
        story.append(Spacer(1, 6 * mm))

    # ---- Akzeptierte Risiken ----
    accepted = [f for f in findings if f["status"] == "risk_accepted"]
    if accepted:
        story.append(PageBreak())
        story.append(Paragraph(f"Akzeptierte Risiken ({len(accepted)})", h2))
        for f in accepted[:30]:
            story.append(Paragraph(
                f"<b>{_severity(f['severity'])}</b> · {_e(f['host_ip'])} · {_e(f['title'])}", body))
            if f.get("risk_accepted_reason"):
                story.append(Paragraph(
                    f"<i>Begründung: {_e(f['risk_accepted_reason'])}</i>", body))
            story.append(Spacer(1, 2 * mm))

    # ---- Anhang: Pruefumfang ----
    story.append(PageBreak())
    story.append(Paragraph("Anhang: Prüfumfang", h2))
    story.append(Paragraph(f"Geprüft wurden {len(data['targets'])} Ziele:", body))
    for t in data["targets"]:
        story.append(Paragraph(f"  &bull; {_e(t)}", body))

    doc.build(story)
    return buf.getvalue()


# ============================================================================
# MinIO + DB-Persistenz
# ============================================================================

def _upload_to_minio(pdf_bytes: bytes, subscription_id: str, report_id: str) -> tuple[str, int]:
    """Lade PDF nach MinIO, return (object_key, size_bytes).

    Derselbe Client wie fuer die Auftragsberichte: MINIO_ENDPOINT traegt in
    Produktion nur den Hostnamen, der Port steht in MINIO_PORT.
    """
    from reporter.worker import REPORTS_BUCKET, _get_minio_client
    client = _get_minio_client()
    if not client.bucket_exists(REPORTS_BUCKET):
        client.make_bucket(REPORTS_BUCKET)
    obj_key = f"subscription-reports/{subscription_id}/{report_id}.pdf"
    buf = io.BytesIO(pdf_bytes)
    client.put_object(REPORTS_BUCKET, obj_key, buf, length=len(pdf_bytes),
                      content_type="application/pdf")
    return obj_key, len(pdf_bytes)


def process_status_report_job(job_data: dict, save_pdf_to: Optional[str] = None) -> Optional[str]:
    """Hauptfunktion: erzeuge PDF + persistiere in subscription_status_reports.

    Returns: report_id (UUID) bei Erfolg, None wenn die Subscription fehlt oder
    ein planmaessiger Bericht nicht (mehr) faellig ist.
    """
    subscription_id = job_data["subscriptionId"]
    trigger_reason = job_data.get("triggerReason", "on_demand")
    requested_by = job_data.get("requestedBy")

    db_url = os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan")
    conn = psycopg2.connect(db_url)
    try:
        if trigger_reason == "scheduled" and not _scheduled_report_due(conn, subscription_id):
            log.info("status_report_not_due", subscription_id=subscription_id)
            return None

        data = _load_subscription_data(conn, subscription_id)
        if not data:
            log.warning("status_report_subscription_not_found", subscription_id=subscription_id)
            return None

        sub = data["subscription"]
        period_end = (
            datetime.fromisoformat(job_data["periodEnd"]) if job_data.get("periodEnd")
            else datetime.now(timezone.utc)
        )
        if period_end.tzinfo is None:
            period_end = period_end.replace(tzinfo=timezone.utc)
        # Ohne started_at (Abo nie aktiviert) beginnt der Zeitraum mit der
        # ersten Posture-Messung, ohne Messung am Stichtag.
        if job_data.get("periodStart"):
            period_start = datetime.fromisoformat(job_data["periodStart"])
        elif sub.get("started_at"):
            period_start = sub["started_at"]
        elif data["history"]:
            period_start = data["history"][0]["snapshot_at"]
        else:
            period_start = period_end
        if period_start.tzinfo is None:
            period_start = period_start.replace(tzinfo=timezone.utc)

        log.info("status_report_generation_start",
                 subscription_id=subscription_id, trigger=trigger_reason)

        pdf_bytes = _build_pdf_bytes(data, period_start, period_end, trigger_reason)
        if save_pdf_to:
            with open(save_pdf_to, "wb") as fh:
                fh.write(pdf_bytes)
        report_id = str(uuid.uuid4())
        obj_key, size = _upload_to_minio(pdf_bytes, subscription_id, report_id)

        posture = data["posture"] or {}
        sc = posture.get("severity_counts") or {}
        if isinstance(sc, str):
            try:
                sc = json.loads(sc)
            except Exception:
                sc = {}
        open_total = sc.get("total_open", 0)
        resolved_total = sc.get("resolved_total", 0)
        regressed_total = sc.get("regressed_total", 0)

        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO subscription_status_reports
                     (id, subscription_id, period_start, period_end, trigger_reason,
                      posture_score, findings_open, findings_resolved, findings_regressed,
                      pdf_minio_key, pdf_size_bytes, generated_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (report_id, subscription_id, period_start, period_end, trigger_reason,
                 posture.get("posture_score"), open_total, resolved_total, regressed_total,
                 obj_key, size, requested_by),
            )
            cur.execute(
                "UPDATE subscriptions SET last_status_report_at = NOW() WHERE id = %s",
                (subscription_id,),
            )
        conn.commit()

        log.info("status_report_generated", report_id=report_id, size=size,
                 subscription_id=subscription_id)
        return report_id
    finally:
        conn.close()


def main(argv: Optional[list[str]] = None) -> int:
    """Statusbericht von Hand erzeugen (Ops-Job `ops-status-report`).

    Derselbe Weg wie der Queue-Job, also mit MinIO-Objekt und DB-Zeile;
    `--pdf` legt zusaetzlich eine Kopie ab, damit der Job sie als Artefakt
    herausreichen kann.
    """
    parser = argparse.ArgumentParser(prog="python -m reporter.status_report_generator")
    parser.add_argument("--subscription", required=True, help="subscriptions.id")
    parser.add_argument("--trigger", default="on_demand", choices=sorted(TRIGGER_LABELS))
    parser.add_argument("--pdf", help="Kopie des PDFs hierhin schreiben")
    args = parser.parse_args(argv)
    report_id = process_status_report_job(
        {"subscriptionId": args.subscription, "triggerReason": args.trigger},
        save_pdf_to=args.pdf,
    )
    if not report_id:
        print(f"kein Bericht erzeugt fuer {args.subscription}", file=sys.stderr)
        return 1
    print(report_id)
    return 0


__all__ = ["process_status_report_job"]


if __name__ == "__main__":
    sys.exit(main())

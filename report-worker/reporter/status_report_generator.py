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

Output: PDF in MinIO unter `subscription-reports/<sub_id>/<report_id>.pdf`,
plus Eintrag in subscription_status_reports.
"""

from __future__ import annotations

import io
import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

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
    SimpleDocTemplate, KeepTogether,
)

from reporter.pdf.branding import (
    COLORS, SEVERITY_COLORS, COMPANY_NAME, CLASSIFICATION_LABEL_DE,
    FONT_BODY, FONT_HEADING, FONT_SIZE_BODY, FONT_SIZE_HEADING1,
    FONT_SIZE_HEADING2,
)

log = structlog.get_logger()


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
            """SELECT id, host_ip, finding_type, port_or_path, status, severity,
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
        title="VectiScan Status-Report",
    )

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontName=FONT_HEADING,
                        fontSize=FONT_SIZE_HEADING1, textColor=HexColor(COLORS["primary"]))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontName=FONT_HEADING,
                        fontSize=FONT_SIZE_HEADING2, textColor=HexColor(COLORS["primary"]))
    body = ParagraphStyle("body", parent=styles["BodyText"], fontName=FONT_BODY,
                          fontSize=FONT_SIZE_BODY, textColor=HexColor(COLORS["text"]),
                          alignment=TA_LEFT, leading=14)
    score_style = ParagraphStyle("score", parent=body, fontSize=48,
                                 alignment=TA_CENTER, leading=52,
                                 textColor=HexColor(COLORS["primary"]))

    story: list = []
    sub = data["subscription"]
    posture = data["posture"] or {}
    findings = data["findings"]
    history = data["history"]

    # ---- Cover ----
    story.append(Paragraph(f"<b>{COMPANY_NAME}</b> — Status-Report", h1))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(f"Subscription: {sub['package'].upper()} ({sub['scan_interval']})", body))
    story.append(Paragraph(f"Kunde: {sub.get('company_name') or sub['customer_email']}", body))
    story.append(Paragraph(
        f"Berichtszeitraum: {period_start:%d.%m.%Y} – {period_end:%d.%m.%Y}", body))
    story.append(Paragraph(f"Trigger: {trigger_reason}", body))
    story.append(Paragraph(f"Erstellt am: {datetime.now(timezone.utc):%d.%m.%Y %H:%M UTC}", body))
    story.append(Spacer(1, 10 * mm))

    score = posture.get("posture_score")
    if score is not None:
        story.append(Paragraph("Aktueller Posture-Score:", body))
        story.append(Paragraph(f"<b>{int(round(float(score)))} / 100</b>", score_style))
        trend = posture.get("trend_direction") or "unknown"
        trend_label = {"improving": "verbessernd", "stable": "stabil",
                       "degrading": "verschlechternd", "unknown": "—"}.get(trend, trend)
        story.append(Paragraph(f"Trend: <b>{trend_label}</b>", body))
    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph(
        f"<i>Klassifikation: {CLASSIFICATION_LABEL_DE}</i>", body))
    story.append(PageBreak())

    # ---- Executive Summary ----
    story.append(Paragraph("Executive Summary", h1))
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
        ["Offene Findings (gesamt)", str(sc.get("total_open", 0))],
        ["  davon CRITICAL", str(open_counts.get("CRITICAL", 0))],
        ["  davon HIGH", str(open_counts.get("HIGH", 0))],
        ["  davon MEDIUM", str(open_counts.get("MEDIUM", 0))],
        ["  davon LOW", str(open_counts.get("LOW", 0))],
        ["Resolved (kumuliert)", str(sc.get("resolved_total", 0))],
        ["Regressed (kumuliert)", str(sc.get("regressed_total", 0))],
        ["Risk Accepted", str(sc.get("accepted_total", 0))],
    ]
    t = Table(summary_rows, colWidths=[80 * mm, 30 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor(COLORS["primary"])),
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
            f"Im letzten Scan: <b>{last['new_findings']} neu</b>, "
            f"<b>{last['resolved_findings']} resolved</b>, "
            f"<b>{last['regressed_findings']} regressed</b>.", body,
        ))

    # ---- Trend-Chart ----
    chart_png = _generate_trend_chart_png(history)
    if chart_png:
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph("Posture-Score Verlauf", h2))
        from reportlab.platypus import Image as RLImage
        img_buf = io.BytesIO(chart_png)
        story.append(RLImage(img_buf, width=170 * mm, height=60 * mm))

    story.append(PageBreak())

    # ---- Open Findings ----
    open_findings = [f for f in findings if f["status"] in ("open", "regressed")]
    story.append(Paragraph(f"Offene Befunde ({len(open_findings)})", h1))
    if open_findings:
        rows = [["Sev", "Host", "Befund", "Erstes Auftreten"]]
        for f in open_findings[:50]:  # cap
            rows.append([
                f["severity"][:4],
                str(f["host_ip"])[:25],
                (f["title"] or "")[:60],
                (f["first_seen_at"]).strftime("%d.%m.%Y") if f["first_seen_at"] else "-",
            ])
        ft = Table(rows, colWidths=[15 * mm, 35 * mm, 90 * mm, 30 * mm])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor(COLORS["primary"])),
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

    # ---- Resolved im Berichtszeitraum ----
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
                f"&#10003; <b>{f['severity']}</b> · {f['host_ip']} · {f['title']}", body))
    else:
        story.append(Paragraph("Keine Befunde im Berichtszeitraum behoben.", body))
    story.append(Spacer(1, 6 * mm))

    # ---- Regressed ----
    regressed = [f for f in findings if f["status"] == "regressed"]
    if regressed:
        story.append(Paragraph(f"&#9888; Wieder aufgetretene Befunde ({len(regressed)})", h2))
        for f in regressed[:30]:
            story.append(Paragraph(
                f"<b>{f['severity']}</b> · {f['host_ip']} · {f['title']}", body))
        story.append(Spacer(1, 6 * mm))

    # ---- Risk Accepted ----
    accepted = [f for f in findings if f["status"] == "risk_accepted"]
    if accepted:
        story.append(PageBreak())
        story.append(Paragraph(f"Akzeptierte Risiken ({len(accepted)})", h2))
        for f in accepted[:30]:
            story.append(Paragraph(
                f"<b>{f['severity']}</b> · {f['host_ip']} · {f['title']}", body))
            if f.get("risk_accepted_reason"):
                story.append(Paragraph(
                    f"<i>Begruendung: {f['risk_accepted_reason']}</i>", body))
            story.append(Spacer(1, 2 * mm))

    # ---- Anhang: Scope ----
    story.append(PageBreak())
    story.append(Paragraph("Anhang — Scope", h2))
    story.append(Paragraph(f"Geprueft wurden {len(data['targets'])} Targets:", body))
    for t in data["targets"]:
        story.append(Paragraph(f"  &bull; {t}", body))

    doc.build(story)
    return buf.getvalue()


# ============================================================================
# MinIO + DB-Persistenz
# ============================================================================

def _upload_to_minio(pdf_bytes: bytes, subscription_id: str, report_id: str) -> tuple[str, int]:
    """Lade PDF nach MinIO, return (object_key, size_bytes)."""
    from minio import Minio
    endpoint = os.environ.get("MINIO_ENDPOINT", "minio:9000")
    access_key = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
    secret_key = os.environ.get("MINIO_SECRET_KEY", "minioadmin")
    bucket = os.environ.get("MINIO_BUCKET", "scan-reports")
    client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=False)
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)
    obj_key = f"subscription-reports/{subscription_id}/{report_id}.pdf"
    buf = io.BytesIO(pdf_bytes)
    client.put_object(bucket, obj_key, buf, length=len(pdf_bytes), content_type="application/pdf")
    return obj_key, len(pdf_bytes)


def process_status_report_job(job_data: dict) -> Optional[str]:
    """Hauptfunktion: erzeuge PDF + persistiere in subscription_status_reports.

    Returns: report_id (UUID) bei Erfolg, None bei Subscription nicht gefunden.
    """
    subscription_id = job_data["subscriptionId"]
    trigger_reason = job_data.get("triggerReason", "on_demand")
    requested_by = job_data.get("requestedBy")

    db_url = os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan")
    conn = psycopg2.connect(db_url)
    try:
        data = _load_subscription_data(conn, subscription_id)
        if not data:
            log.warning("status_report_subscription_not_found", subscription_id=subscription_id)
            return None

        sub = data["subscription"]
        period_start = (
            datetime.fromisoformat(job_data["periodStart"]) if job_data.get("periodStart")
            else sub["started_at"]
        )
        if period_start.tzinfo is None:
            period_start = period_start.replace(tzinfo=timezone.utc)
        period_end = (
            datetime.fromisoformat(job_data["periodEnd"]) if job_data.get("periodEnd")
            else datetime.now(timezone.utc)
        )
        if period_end.tzinfo is None:
            period_end = period_end.replace(tzinfo=timezone.utc)

        log.info("status_report_generation_start",
                 subscription_id=subscription_id, trigger=trigger_reason)

        pdf_bytes = _build_pdf_bytes(data, period_start, period_end, trigger_reason)
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


__all__ = ["process_status_report_job"]

"""Subscription-Posture Aggregator (2026-05-03).

Akkumuliert Findings ueber alle Scans einer Subscription in
`consolidated_findings`, dedupliziert auf Schluessel
(host_ip, finding_type, port_or_path), trackt Lifecycle-States
(open / resolved / regressed / risk_accepted).

Aufruf nach jedem erfolgreichen Scan-Report aus reporter/worker.py:
    aggregate_into_posture(conn, order_id, findings_data)

Output:
    - upsert in consolidated_findings
    - insert in scan_finding_observations (welche Findings dieser Scan gesehen hat)
    - mark fehlende open-Findings → resolved
    - update subscription_posture (severity_counts, score, trend)
    - insert posture_history-Snapshot
    - returns PostureSnapshot mit Delta-Counts (new/resolved/regressed)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Optional

import psycopg2
import psycopg2.extras
import structlog

log = structlog.get_logger()

SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 5.0,
    "MEDIUM": 2.0,
    "LOW": 0.5,
    "INFO": 0.0,
}


@dataclass
class PostureSnapshot:
    subscription_id: str
    posture_score: float
    severity_counts: dict[str, Any]
    new_findings: int
    resolved_findings: int
    regressed_findings: int
    trend_direction: str
    has_critical_change: bool  # True wenn neue CRITICAL/HIGH oder Regression


def _derive_dedup_key(finding: dict) -> Optional[tuple[str, str, str]]:
    """Leite (host_ip, finding_type, port_or_path) aus einem Finding ab.

    Returns None wenn unzureichende Daten — Finding wird dann nicht
    dedupliziert (sondern als Order-spezifisch behandelt = NICHT in
    consolidated_findings aufgenommen).

    Erwartete Finding-Felder (aus deterministic_pipeline.py + Claude):
        - host_ip ODER affected_hosts[0] ODER affected (URL/Hostname)
        - policy_id (ideal) ODER finding_type ODER title-Hash (Fallback)
        - url_path/affected (fuer Pfad) ODER port (fuer non-HTTP)
    """
    host_ip = (
        finding.get("host_ip")
        or (finding.get("affected_hosts") or [None])[0]
        or _extract_host_from_affected(finding.get("affected") or finding.get("url"))
    )
    if not host_ip:
        return None

    finding_type = (
        finding.get("policy_id")
        or finding.get("finding_type")
        or _normalize_title_for_dedup(finding.get("title", ""))
    )
    if not finding_type:
        return None

    port_or_path = (
        finding.get("url_path")
        or _extract_path_from_affected(finding.get("affected") or finding.get("url") or "")
        or (str(finding.get("port")) if finding.get("port") else "")
    )
    return (str(host_ip).strip(), str(finding_type).strip(), str(port_or_path or "").strip())


_PORT_RE = None


def _extract_host_from_affected(affected: Optional[str]) -> Optional[str]:
    """Aus 'https://example.com:8443/login' → 'example.com' (best effort)."""
    if not affected:
        return None
    s = str(affected).strip()
    # URL-Schema strippen
    if "://" in s:
        s = s.split("://", 1)[1]
    # Pfad strippen
    s = s.split("/", 1)[0]
    # Port strippen
    s = s.split(":", 1)[0]
    return s or None


def _extract_path_from_affected(affected: str) -> str:
    """Aus 'https://example.com/login?x=1' → '/login'."""
    s = str(affected or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    if "/" in s:
        path = "/" + s.split("/", 1)[1]
        # Query weg
        path = path.split("?", 1)[0].split("#", 1)[0]
        return path
    return ""


def _normalize_title_for_dedup(title: str) -> str:
    """Fallback wenn keine policy_id: Titel auf Lowercase + erste 80 Zeichen."""
    return (title or "").lower().strip()[:80]


def _calculate_posture_score(severity_counts_open: dict[str, int]) -> float:
    """Berechne Posture-Score 0-100 aus open-Severity-Verteilung.

    Formel: score = 100 - sum(open[sev] * weight[sev]); clamp 0-100.
    """
    penalty = 0.0
    for sev, weight in SEVERITY_WEIGHTS.items():
        penalty += int(severity_counts_open.get(sev, 0)) * weight
    score = max(0.0, min(100.0, 100.0 - penalty))
    return round(score, 2)


def _determine_trend(conn, subscription_id: str, current_score: float) -> str:
    """Trend-Richtung relativ zum letzten posture_history-Snapshot.

    delta > +5 → improving
    delta < -5 → degrading
    sonst → stable
    Wenn keine History → unknown.
    """
    with conn.cursor() as cur:
        cur.execute(
            """SELECT posture_score FROM posture_history
                WHERE subscription_id = %s
                ORDER BY snapshot_at DESC LIMIT 1""",
            (subscription_id,),
        )
        row = cur.fetchone()
    if not row or row[0] is None:
        return "unknown"
    delta = float(current_score) - float(row[0])
    if delta > 5.0:
        return "improving"
    if delta < -5.0:
        return "degrading"
    return "stable"


def _get_subscription_id_for_order(conn, order_id: str) -> Optional[str]:
    """Hole subscription_id aus orders.subscription_id."""
    with conn.cursor() as cur:
        cur.execute("SELECT subscription_id FROM orders WHERE id = %s", (order_id,))
        row = cur.fetchone()
    if not row or not row[0]:
        return None
    return str(row[0])


def aggregate_into_posture(
    conn,
    order_id: str,
    findings_data: dict,
) -> Optional[PostureSnapshot]:
    """Hauptfunktion: aggregiere Order-Findings in Subscription-Posture.

    - findings_data["findings"]: Liste von Findings aus Reports (after deterministic_pipeline)
    - Order muss subscription_id haben (None → kein Aggregat, return None)
    - Bei psycopg2-Errors: Exception bubbelt; Caller sollte try/except setzen
    """
    subscription_id = _get_subscription_id_for_order(conn, order_id)
    if not subscription_id:
        log.info("posture_skip_no_subscription", order_id=order_id)
        return None

    findings = findings_data.get("findings", []) or []
    log.info("posture_aggregate_start", order_id=order_id,
             subscription_id=subscription_id, findings_in=len(findings))

    # Defensives Rollback bei Exception in der Transaktion damit der Caller
    # eine saubere conn weiterverwenden kann (siehe worker.py:8c).
    try:
        return _do_aggregate(conn, order_id, subscription_id, findings)
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise


def _do_aggregate(conn, order_id, subscription_id, findings):
    seen_finding_ids: set[str] = set()
    new_count = 0
    regressed_count = 0
    new_critical_high = 0
    has_regression = False

    with conn.cursor() as cur:
        for f in findings:
            key = _derive_dedup_key(f)
            if not key:
                continue
            host_ip, finding_type, port_or_path = key

            severity = (f.get("severity") or "INFO").upper()
            if severity not in SEVERITY_WEIGHTS:
                severity = "INFO"
            cvss = f.get("cvss_score")
            try:
                cvss_num = float(cvss) if cvss is not None else None
            except (TypeError, ValueError):
                cvss_num = None
            title = (f.get("title") or "")[:1000]
            description = f.get("description") or ""
            metadata = {
                "cwe": f.get("cwe"),
                "references": f.get("references") or [],
                "policy_id": f.get("policy_id"),
                "tool_source": f.get("tool_source"),
                "evidence": f.get("evidence"),
            }

            # Check existing
            cur.execute(
                """SELECT id, status FROM consolidated_findings
                   WHERE subscription_id = %s
                     AND host_ip = %s
                     AND finding_type = %s
                     AND port_or_path = %s""",
                (subscription_id, host_ip, finding_type, port_or_path),
            )
            existing = cur.fetchone()

            if existing is None:
                # NEU
                cur.execute(
                    """INSERT INTO consolidated_findings
                       (subscription_id, host_ip, finding_type, port_or_path,
                        status, severity, cvss_score, title, description,
                        first_seen_order_id, first_seen_at,
                        last_seen_order_id, last_seen_at, metadata)
                       VALUES (%s, %s, %s, %s, 'open', %s, %s, %s, %s,
                               %s, NOW(), %s, NOW(), %s)
                       RETURNING id""",
                    (subscription_id, host_ip, finding_type, port_or_path,
                     severity, cvss_num, title, description,
                     order_id, order_id, json.dumps(metadata)),
                )
                cf_id = cur.fetchone()[0]
                seen_finding_ids.add(str(cf_id))
                new_count += 1
                if severity in ("CRITICAL", "HIGH"):
                    new_critical_high += 1
            else:
                cf_id, current_status = existing
                seen_finding_ids.add(str(cf_id))
                if current_status == "resolved":
                    # → REGRESSED
                    cur.execute(
                        """UPDATE consolidated_findings
                            SET status = 'regressed',
                                severity = %s, cvss_score = %s, title = %s, description = %s,
                                last_seen_order_id = %s, last_seen_at = NOW(),
                                metadata = %s,
                                updated_at = NOW()
                          WHERE id = %s""",
                        (severity, cvss_num, title, description, order_id,
                         json.dumps(metadata), cf_id),
                    )
                    regressed_count += 1
                    has_regression = True
                elif current_status == "risk_accepted":
                    # bleibt akzeptiert; nur last_seen aktualisieren
                    cur.execute(
                        """UPDATE consolidated_findings
                            SET last_seen_order_id = %s, last_seen_at = NOW(),
                                updated_at = NOW()
                          WHERE id = %s""",
                        (order_id, cf_id),
                    )
                else:
                    # open ODER regressed → bleibt; nur Tracking-Felder
                    cur.execute(
                        """UPDATE consolidated_findings
                            SET severity = %s, cvss_score = %s, title = %s, description = %s,
                                last_seen_order_id = %s, last_seen_at = NOW(),
                                metadata = %s, updated_at = NOW()
                          WHERE id = %s""",
                        (severity, cvss_num, title, description, order_id,
                         json.dumps(metadata), cf_id),
                    )

            # Observation-Snapshot
            cur.execute(
                """INSERT INTO scan_finding_observations
                   (order_id, consolidated_finding_id, severity_at_observation)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (order_id, consolidated_finding_id) DO NOTHING""",
                (order_id, cf_id, severity),
            )

        # Fehlende open-Findings → RESOLVED
        # Alle consolidated_findings dieser Subscription mit status in
        # ('open','regressed') die NICHT in seen_finding_ids sind und
        # mindestens einmal vorher gesehen wurden → resolved.
        if seen_finding_ids:
            cur.execute(
                """UPDATE consolidated_findings
                    SET status = 'resolved',
                        resolved_at = NOW(), resolved_in_order_id = %s,
                        updated_at = NOW()
                  WHERE subscription_id = %s
                    AND status IN ('open', 'regressed')
                    AND id NOT IN %s
                  RETURNING id""",
                (order_id, subscription_id, tuple(seen_finding_ids)),
            )
        else:
            cur.execute(
                """UPDATE consolidated_findings
                    SET status = 'resolved',
                        resolved_at = NOW(), resolved_in_order_id = %s,
                        updated_at = NOW()
                  WHERE subscription_id = %s
                    AND status IN ('open', 'regressed')
                  RETURNING id""",
                (order_id, subscription_id),
            )
        resolved_now = cur.fetchall()
        resolved_count = len(resolved_now)

        # Severity-Counts (open) berechnen
        cur.execute(
            """SELECT severity, COUNT(*) FROM consolidated_findings
                WHERE subscription_id = %s AND status IN ('open', 'regressed')
                GROUP BY severity""",
            (subscription_id,),
        )
        rows = cur.fetchall()
        open_counts = {sev: 0 for sev in SEVERITY_WEIGHTS}
        for sev, cnt in rows:
            if sev in open_counts:
                open_counts[sev] = int(cnt)

        # Aggregierte Counts fuer JSONB
        cur.execute(
            """SELECT status, COUNT(*) FROM consolidated_findings
                WHERE subscription_id = %s GROUP BY status""",
            (subscription_id,),
        )
        status_rows = dict(cur.fetchall())

        severity_counts = {
            "open": open_counts,
            "resolved_total": int(status_rows.get("resolved", 0)),
            "regressed_total": int(status_rows.get("regressed", 0)),
            "accepted_total": int(status_rows.get("risk_accepted", 0)),
            "total_open": sum(open_counts.values()),
        }

        score = _calculate_posture_score(open_counts)
        trend = _determine_trend(conn, subscription_id, score)

        # Upsert subscription_posture
        cur.execute(
            """INSERT INTO subscription_posture
                 (subscription_id, last_scan_order_id, last_aggregated_at,
                  severity_counts, posture_score, trend_direction, updated_at)
               VALUES (%s, %s, NOW(), %s, %s, %s, NOW())
               ON CONFLICT (subscription_id) DO UPDATE SET
                  last_scan_order_id = EXCLUDED.last_scan_order_id,
                  last_aggregated_at = EXCLUDED.last_aggregated_at,
                  severity_counts = EXCLUDED.severity_counts,
                  posture_score = EXCLUDED.posture_score,
                  trend_direction = EXCLUDED.trend_direction,
                  updated_at = NOW()""",
            (subscription_id, order_id, json.dumps(severity_counts),
             score, trend),
        )

        # posture_history-Snapshot
        cur.execute(
            """INSERT INTO posture_history
                 (subscription_id, triggering_order_id, posture_score,
                  severity_counts, new_findings, resolved_findings, regressed_findings)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (subscription_id, order_id, score, json.dumps(severity_counts),
             new_count, resolved_count, regressed_count),
        )

    conn.commit()

    has_critical_change = (new_critical_high > 0) or has_regression
    snapshot = PostureSnapshot(
        subscription_id=subscription_id,
        posture_score=score,
        severity_counts=severity_counts,
        new_findings=new_count,
        resolved_findings=resolved_count,
        regressed_findings=regressed_count,
        trend_direction=trend,
        has_critical_change=has_critical_change,
    )
    log.info(
        "posture_aggregate_complete",
        order_id=order_id,
        subscription_id=subscription_id,
        new=new_count, resolved=resolved_count, regressed=regressed_count,
        score=score, trend=trend, critical_change=has_critical_change,
    )

    # PR-Posture Eskalations-Trigger: bei kritischer Verschlechterung
    # (neue CRITICAL/HIGH ODER Regression) sofort Status-Report enqueuen.
    if has_critical_change:
        try:
            _enqueue_status_report(subscription_id, "critical_escalation")
        except Exception as e:
            log.warning("status_report_enqueue_failed",
                        subscription_id=subscription_id, error=str(e))

    return snapshot


def _enqueue_status_report(subscription_id: str, trigger_reason: str) -> None:
    """Schiebt einen Status-Report-Job in die report-pending Queue.

    Best-effort — bei Redis-Fehlern wird nur geloggt, nicht reraised.
    """
    import os
    import redis
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    client = redis.from_url(redis_url)
    payload = json.dumps({
        "subscriptionId": subscription_id,
        "triggerReason": trigger_reason,
    })
    client.rpush("report-pending", payload)
    log.info("status_report_enqueued",
             subscription_id=subscription_id, trigger=trigger_reason)


__all__ = [
    "PostureSnapshot",
    "aggregate_into_posture",
    "SEVERITY_WEIGHTS",
]

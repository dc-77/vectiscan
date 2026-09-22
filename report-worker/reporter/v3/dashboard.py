# -*- coding: utf-8 -*-
"""Die Befundliste des Dashboards aus den Reportdaten v3.

``reports.findings_data`` ist die Quelle der Befundansicht im Kundenportal und im
Admin-Review (``api/src/routes/orders.ts``, ``frontend/.../ModernView.tsx``). Bis
S6 fuellte sie die alte KI-Kette, auch wenn der Bericht laengst aus dem
Pruefkatalog kam: der Worker liess die Kette allein dafuer mitlaufen, und das
kostete rund 1,85 USD je Bericht. Hier entsteht derselbe Umschlag aus den
Katalogbefunden.

Zwei Dinge sind anders als beim alten Umschlag, und beide mit Absicht:

* Es gibt kein ``cvss_score``. Der Bericht vergibt keine eigenen CVSS-Werte
  (spec/03 Regel 2); ein Fremdwert steht am Befund unter ``threat``.
* ``severity`` kommt aus der Abbildungstabelle in ``reporter/v3/levels.py``,
  derselben, aus der die Ampelfarbe des PDF folgt. Die Zahlen je Farbe im
  Dashboard sind damit dieselben wie im Bericht (Entscheidung DC).
"""
from __future__ import annotations

from typing import Any

from reporter.v3 import levels as L
from reporter.v3.models import Finding, ReportData

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def severity_of(finding: Finding) -> str:
    """Stufe eines Befunds fuer das Dashboard, aus derselben Tabelle wie die Farbe."""
    if finding.status == "rot":
        return "CRITICAL"
    return L.severity_for(finding.scale, finding.level)


def _finding(finding: Finding, severity: str) -> dict[str, Any]:
    empfehlung = "\n".join(f"{stufe}: {text}" for stufe, text in finding.recommendation)
    eintrag: dict[str, Any] = {
        "id": finding.id,
        "title": finding.title,
        "severity": severity,
        "category": finding.cat,
        "affected": finding.affected,
        "description": finding.found,
        "impact": finding.impact,
        "recommendation": empfehlung,
        "evidence": finding.evidence,
        "verification": finding.verify,
        "source": finding.source,
        "urgency": finding.urgency,
        "scale": finding.scale,
        "level": finding.level_label or finding.level,
        # Die Regel, unter der der Befund im Pruefkatalog steht. Das Feld heisst
        # policy_id, weil die API und das Dashboard es so lesen.
        "policy_id": finding.policy,
    }
    if finding.threat is not None:
        eintrag["threat"] = {
            "cves": list(finding.threat.cves),
            "kev": finding.threat.kev,
            "note": finding.threat.note,
        }
    return eintrag


def findings_data_from_v3(data: ReportData, package: str) -> dict[str, Any]:
    """Denselben Umschlag bauen, den der alte Weg aus der KI-Ausgabe baute."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    findings: list[dict[str, Any]] = []
    for finding in data.findings:
        severity = severity_of(finding)
        counts[severity] = counts.get(severity, 0) + 1
        findings.append(_finding(finding, severity))
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["id"]))

    positives = [{
        "id": f"VS-P{i + 1:02d}",
        "title": p.title,
        "description": p.text,
        "category": p.cat,
    } for i, p in enumerate(data.positives)]

    empfehlungen = [{
        "priority": row.prio,
        "action": row.action,
        "findings": list(row.refs),
        "effect": row.effect,
    } for row in data.plan]

    return {
        "overall_risk": data.glance.overall,
        "overall_description": data.glance.overall_text,
        "severity_counts": counts,
        "findings": findings,
        "positive_findings": positives,
        "recommendations": empfehlungen,
        "package": package,
        # Herkunft der Liste, damit im Dashboard und im Audit erkennbar bleibt,
        # welcher Weg sie erzeugt hat.
        "engine": "catalog",
        "catalog_version": data.meta.catalog_version,
        "facts_schema_version": data.meta.facts_schema_version,
    }


def policy_ids(data: ReportData) -> list[str]:
    """Verschiedene Regeln der Befunde, fuer reports.policy_id_distinct."""
    out: list[str] = []
    for finding in data.findings:
        for teil in finding.policy.split(","):
            regel = teil.strip()
            if regel and regel not in out:
                out.append(regel)
    return sorted(out)


__all__ = ["findings_data_from_v3", "policy_ids", "severity_of", "SEVERITY_ORDER"]

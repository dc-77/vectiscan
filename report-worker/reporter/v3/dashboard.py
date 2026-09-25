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

from reporter.facts import schema as FS
from reporter.facts import systems as SYS
from reporter.facts.serialize import sort_key
from reporter.v3 import levels as L
from reporter.v3.chapters import UNKNOWN, TechLine, tech_lines
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


# ---------------------------------------------------------------- Technologien

# Hostkarte und Techniktabelle im Dashboard lesen ``reports.tech_profiles[].tech_rows``
# (frontend/src/lib/api.ts ``TechRow``). Im Katalogweg entstehen die Zeilen aus
# denselben ``tech_lines`` wie die Technologietabelle im Bericht (spec/09 Q11): gleiche
# Normalisierung, gleicher Lebenszyklus-Abgleich, gleiche Quelle. Bis S6a2 baute sie
# der alte ``tech_table_builder`` aus den rohen Profilen und las
# "5.5.5-10.11.18-MariaDB" als MySQL 5.5 mit EOL 2018 und "9.6.0 or later" als 9.6.

# Faktenstatus -> (status, patch_status). TechTable.tsx kennt nur eol, minor_eol,
# outdated, current und unbekannt und hat fuer andere Werte keinen Rueckfall.
_TECH_STATUS: dict[str, tuple[str, str]] = {
    "eol": ("eol", "eol"),
    "supported": ("current", "aktuell"),
    "unknown": ("unbekannt", "unbekannt"),
}

# Faktenart -> Kategorie im Vokabular des alten Builders.
_TECH_CATEGORY: dict[str, str] = {
    "database": "Datenbank",
    "webserver": "Web-Server",
    "mail": "Mail",
    "ssh": "Remote-Access",
    "ftp": "File-Transfer",
    "language": "Sprache",
    "library": "Bibliothek",
    "cms_core": "CMS",
    "theme": "CMS-Theme",
    "plugin": "CMS-Plugin",
    "control_panel": "Verwaltungsoberfläche",
    "application": "Anwendung",
    "os": "OS",
    "appliance": "Network-Appliance",
}


def tech_row(line: TechLine) -> dict[str, Any]:
    """Eine Dashboard-Zeile im Feldformat des alten Builders.

    Das Dashboard sagt nichts, was der Bericht nicht sagt: ein EOL-Datum nur bei
    Status eol (TechTable.tsx zeigt jedes gesetzte Datum als "EOL <Datum>"), kein
    Patchstand, keine CVE-Zuordnung.
    """
    status, patch_status = _TECH_STATUS.get(line.eol_status, _TECH_STATUS["unknown"])
    return {
        "name": line.product,
        "version": "" if line.version == UNKNOWN else line.version,
        "category": _TECH_CATEGORY.get(line.software.kind, "Sonstiges"),
        "status": status,
        "patch_status": patch_status,
        "is_mega_cve": False,
        "eol_date": (line.eol_date or "") if status == "eol" else "",
        "latest_patch": "",
        "cves": [],
        "vuln_name": "",
        "confidence": line.confidence,
        "confidence_label": line.conf_label,
        "source": line.sources,
        "detection_source": line.sources,
        "top_cve": None,
    }


def tech_profiles_from_facts(facts: FS.Facts, profiles: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Profile mit ``tech_rows`` aus den Fakten, fuer ``reports.tech_profiles``.

    Die Profilfelder (Ports, WAF, Weiterleitungen) bleiben, nur die Zeilen sind neu.
    Ein Host mit Zeilen im Bericht, aber ohne Profil, bekommt ein Minimalprofil,
    damit Bericht und Dashboard dieselben Hosts zeigen.
    """
    lines = tech_lines(facts)
    angehaengt = additional_ips(facts, lines)
    mitglieder = {entry["ip"] for extra in angehaengt.values() for entry in extra}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for profile in profiles or []:
        if not isinstance(profile, dict):
            continue
        ip = str(profile.get("ip") or "")
        if ip in mitglieder:
            continue
        entry = {**profile, "tech_rows": [tech_row(line) for line in lines.get(ip, [])]}
        if ip in angehaengt:
            entry["additional_ips"] = angehaengt[ip]
        out.append(entry)
        seen.add(ip)
    fqdns = {h.ip: list(h.fqdns) for h in facts.hosts}
    for ip in sorted(set(lines) | set(angehaengt), key=sort_key):
        if ip in seen:
            continue
        entry = {"ip": ip, "fqdns": fqdns.get(ip, []),
                 "tech_rows": [tech_row(line) for line in lines.get(ip, [])]}
        if ip in angehaengt:
            entry["additional_ips"] = angehaengt[ip]
        out.append(entry)
    return out


# Hinweis zu einer weiteren Adresse ohne eigene Messung, nach ihrer Erreichbarkeit.
_REACH_NOTE: dict[str, str] = {
    "no_ipv6_route": "über IPv6 vom Prüfstand aus nicht erreichbar",
    "unreachable_from_scanner": "vom Prüfstand aus nicht erreichbar",
    "no_open_ports": "kein offener Port",
}


def additional_ips(facts: FS.Facts, lines: dict[str, list[TechLine]]) -> dict[str, list[dict[str, str]]]:
    """Leitadresse eines Systems -> weitere Adressen ohne eigene Messung.

    Nachtrag 3 zu S6b-1 (Entscheidung DC 25.09., spec/09 Q16): IPv4 und IPv6 mit
    gleichem rDNS sind ein System. Eine Adresse ohne eigene Technikzeilen und ohne
    offenen Dienst bekommt keine eigene Hostkarte; sie steht in der Karte des Systems
    als weitere Adresse mit dem Grund, wie Kapitel 2.1 im Bericht.
    """
    eigene = [h for h in facts.hosts if h.third_party is None]
    offen = {s.host_ip for s in facts.services if s.state == "open"}
    out: dict[str, list[dict[str, str]]] = {}
    for members in SYS.system_groups(eigene).values():
        if len(members) < 2:
            continue
        lead, rest = members[0], members[1:]
        extra = [{"ip": h.ip,
                  "note": _REACH_NOTE.get(h.reach.status if h.reach else "", "ohne eigene Messung")}
                 for h in rest if not lines.get(h.ip) and h.ip not in offen]
        if extra:
            out[lead.ip] = extra
    return out


def policy_ids(data: ReportData) -> list[str]:
    """Verschiedene Regeln der Befunde, fuer reports.policy_id_distinct."""
    out: list[str] = []
    for finding in data.findings:
        for teil in finding.policy.split(","):
            regel = teil.strip()
            if regel and regel not in out:
                out.append(regel)
    return sorted(out)


__all__ = ["findings_data_from_v3", "policy_ids", "severity_of", "SEVERITY_ORDER",
           "tech_profiles_from_facts", "tech_row"]

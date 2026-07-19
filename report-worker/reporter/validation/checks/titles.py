"""Titles-Check: prueft Finding-Titles auf Defekte.

Adressiert aus Doc 01 (Fehleranalyse_und_Korrekturplan.md):
- P0-01: Unaufgeloeste Title-Platzhalter ({host}, {port} etc.)
- P0-04: Duplikat-Titles (zwei oder mehr Findings mit identischem Title)
- P0-05: Bareword-Numbers im Title (z.B. "Port 27 offen" wo 27 keine Standard-
  Portnummer ist → Hinweis auf zerschossene Templates).

Zusaetzlich optional:
- info_disclosure_banner-Findings mit identischem Title aber unterschiedlichen
  Service-Kontexten (SSH-vs-HTTP Banner ableitbar aus evidence/title_vars).

Plan: M1 ValidationGate (`~/.claude/plans/ich-m-chte-gerne-das-iterative-nova.md`).
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

from reporter.validation.gate import ValidationIssue

# Unaufgelöste Platzhalter im Title – {anything_lower_with_underscores}
_PLACEHOLDER_RE = re.compile(r"\{[a-z_][a-z0-9_]*\}", re.IGNORECASE)

# Standard-Service-Ports, die in Titles legitim sind
_KNOWN_PORTS = {
    "20", "21", "22", "23", "25", "53", "80", "110", "143",
    "443", "465", "587", "636", "993", "995",
    "1433", "1521", "1723", "2049", "3306", "3389",
    "5432", "5900", "6379", "8080", "8443", "9200", "9300",
    "27017", "11211", "5060", "5061",
}

# Bareword-Number: nicht gefolgt von einer Einheit (Plugins/Hosts etc.)
_NUMBER_WITH_UNIT_RE = re.compile(
    r"\b(\d+)\s*"
    r"(Plugins?|Hosts?|Subdomains?|Findings?|Komponenten|Zeilen|Tage|"
    r"Stunden|Tagen|Stunden|Monate|Monaten|Jahre|Jahren|Versionen|"
    r"MB|GB|KB|TB|kbit|Mbit|Gbit|%)",
    re.IGNORECASE,
)
# Bare standalone numbers (ohne Einheit dahinter)
_BARE_NUMBER_RE = re.compile(r"\b\d+\b")
# Version- ODER IP-Pattern: mehrteilige Zahl-mit-Punkt (2.4.49, 3.4.1, 88.99.35.112).
# WICHTIG: mehr als zwei Segmente muessen VOLLSTAENDIG erfasst werden, sonst bleibt
# das letzte Segment (".1" aus "3.4.1", ".112" aus einer IP) als vermeintliche
# Bareword-Number uebrig und flaggt ein voellig legitimes Finding.
_VERSION_OR_IP_RE = re.compile(r"\b\d+(?:\.\d+)+")
# Port-Kontext: eine Zahl direkt hinter "Port"/"Ports" (optional mit : oder Klammer)
# ist ein legitimer Port — auch Nicht-Standard-Ports wie Webmin 10000 oder 8081.
_PORT_CONTEXT_RE = re.compile(r"\b[Pp]orts?\b[\s:()]*\d+")


def _extract_service_hint(finding: dict[str, Any]) -> str:
    """Versuche aus evidence/title_vars einen Service-Hint zu extrahieren."""
    title_vars = finding.get("title_vars") or {}
    if isinstance(title_vars, dict) and title_vars.get("service"):
        return str(title_vars["service"]).lower()
    ev = finding.get("evidence")
    if isinstance(ev, dict):
        for key in ("service", "protocol", "scheme"):
            v = ev.get(key)
            if v:
                return str(v).lower()
    return ""


def check(
    findings_data: dict,
    report_data: dict,
    context: dict,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    findings = findings_data.get("findings", []) or []

    # 1) Platzhalter-Check + Bareword-Number-Check pro Finding
    for f in findings:
        fid = f.get("id")
        title = (f.get("title") or "").strip()
        if not title:
            issues.append(ValidationIssue(
                check="titles",
                severity="error",
                finding_id=fid,
                message="Title ist leer",
            ))
            continue

        # P0-01: Unaufgelöste Platzhalter
        placeholders = _PLACEHOLDER_RE.findall(title)
        if placeholders:
            issues.append(ValidationIssue(
                check="titles",
                severity="error",
                finding_id=fid,
                message=f"Unaufgelöste Platzhalter im Title: {placeholders}",
                detail={"title": title, "placeholders": placeholders},
            ))

        # P0-05: Bareword-Numbers
        # Strategy: Title nach _NUMBER_WITH_UNIT_RE Whitelist-Tokens "ausblenden",
        # dann auf reine Zahlen scannen. Bekannte Ports + Versionen sind OK.
        title_for_numbers = _NUMBER_WITH_UNIT_RE.sub("", title)
        # Zahlen mit "Port"-Kontext (auch Nicht-Standard-Ports wie 10000) sind legitim.
        title_for_numbers = _PORT_CONTEXT_RE.sub("", title_for_numbers)
        # Versionen UND IPs (mehrteilige Zahl.Zahl.Zahl…) vollstaendig entfernen.
        title_no_versions = _VERSION_OR_IP_RE.sub("", title_for_numbers)
        bare_numbers = _BARE_NUMBER_RE.findall(title_no_versions)
        # Filter: alles was ein Standard-Port ist, ist OK.
        suspicious = [n for n in bare_numbers if n not in _KNOWN_PORTS]
        if suspicious:
            issues.append(ValidationIssue(
                check="titles",
                severity="warning",
                finding_id=fid,
                message=(
                    f"Bareword-Number(s) im Title ohne Port/Version-Kontext: "
                    f"{suspicious}"
                ),
                detail={"title": title, "suspicious_numbers": suspicious},
            ))

    # 2) Duplikat-Titles
    groups: dict[str, list[str]] = defaultdict(list)
    for f in findings:
        title = (f.get("title") or "").strip().lower()
        if not title:
            continue
        groups[title].append(f.get("id") or "")
    for title_key, fids in groups.items():
        if len(fids) >= 2:
            issues.append(ValidationIssue(
                check="titles",
                severity="error",
                finding_id=None,
                message=f"{len(fids)} Findings teilen denselben Title",
                detail={"duplicate_title": title_key, "finding_ids": fids},
            ))

    # 3) Optional: info_disclosure_banner mit gleichem Title aber unterschiedlichen Services
    banner_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        if f.get("finding_type") == "info_disclosure_banner":
            title_key = (f.get("title") or "").strip().lower()
            if title_key:
                banner_groups[title_key].append(f)
    for title_key, group in banner_groups.items():
        if len(group) < 2:
            continue
        services = {_extract_service_hint(f) for f in group}
        services.discard("")
        if len(services) >= 2:
            issues.append(ValidationIssue(
                check="titles",
                severity="warning",
                finding_id=None,
                message=(
                    "info_disclosure_banner-Findings mit identischem Title "
                    "aber unterschiedlichen Services"
                ),
                detail={
                    "title": title_key,
                    "services": sorted(services),
                    "finding_ids": [f.get("id") for f in group],
                },
            ))

    return issues

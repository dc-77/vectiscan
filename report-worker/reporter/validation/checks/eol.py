"""EOL-Check: prueft Konsistenz zwischen EOL-Datum im Finding-Body
und der EOL-Tabelle.

Adressiert aus Doc 01 (Fehleranalyse_und_Korrekturplan.md):
- P1-03: EOL-Datum im Finding-Description weicht von dem in der Tech-Tabelle
  ab; oder Finding nennt MariaDB, EOL-Lookup wuerde MySQL liefern (Mix-Up).

Defensive: Wenn eol_detector nicht importierbar oder Tech-Profile leer, return []
mit Warning-Log.
"""
from __future__ import annotations

import json
import re
from typing import Any

import structlog

from reporter.validation.gate import ValidationIssue

log = structlog.get_logger()


# Datums-Patterns
_ISO_DATE_RE = re.compile(r"\b(20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b")
_MONTH_NAMES_DE_EN = {
    "januar": "01", "january": "01", "jan": "01",
    "februar": "02", "february": "02", "feb": "02",
    "maerz": "03", "märz": "03", "march": "03", "mar": "03",
    "april": "04", "apr": "04",
    "mai": "05", "may": "05",
    "juni": "06", "june": "06", "jun": "06",
    "juli": "07", "july": "07", "jul": "07",
    "august": "08", "aug": "08",
    "september": "09", "sep": "09", "sept": "09",
    "oktober": "10", "october": "10", "oct": "10", "okt": "10",
    "november": "11", "nov": "11",
    "dezember": "12", "december": "12", "dec": "12", "dez": "12",
}

_DATE_TEXT_RE = re.compile(
    r"\b(\d{1,2}\.?\s*)?(" + "|".join(_MONTH_NAMES_DE_EN.keys()) + r")\s*(\d{4})\b",
    re.IGNORECASE,
)

# Tech-Name vs MariaDB/MySQL-Mixup-Tokens
_MIXUP_PAIRS = [
    ("mariadb", "mysql"),
    ("mysql", "mariadb"),
]


def _find_dates(text: str) -> list[str]:
    """Extrahiere alle Datums-Strings (ISO oder Text) aus text."""
    dates: list[str] = []
    if not text:
        return dates
    for m in _ISO_DATE_RE.finditer(text):
        dates.append(m.group(0))
    for m in _DATE_TEXT_RE.finditer(text):
        month_name = m.group(2).lower()
        month_num = _MONTH_NAMES_DE_EN.get(month_name, "??")
        year = m.group(3)
        dates.append(f"{year}-{month_num}")
    return dates


def _body_text(f: dict[str, Any]) -> str:
    parts = []
    for k in ("description", "impact", "recommendation"):
        if f.get(k):
            parts.append(str(f[k]))
    ev = f.get("evidence")
    if isinstance(ev, str):
        parts.append(ev)
    elif isinstance(ev, (dict, list)):
        try:
            parts.append(json.dumps(ev, ensure_ascii=False, default=str))
        except Exception:
            parts.append(str(ev))
    return "\n".join(parts)


def _get_tech_rows(context: dict[str, Any]) -> list[dict[str, Any]]:
    profiles = context.get("tech_profiles") or []
    if not profiles or not isinstance(profiles, list):
        return []
    try:
        from reporter.tech_table_builder import build_tech_table_for_host
    except ImportError:
        log.warning("eol_check_tech_table_builder_unavailable")
        return []
    rows: list[dict[str, Any]] = []
    for p in profiles:
        if not isinstance(p, dict):
            continue
        try:
            rows.extend(build_tech_table_for_host(p))
        except Exception as e:
            log.warning("eol_check_tech_build_failed", error=str(e))
    return rows


def check(
    findings_data: dict,
    report_data: dict,
    context: dict,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    findings = findings_data.get("findings", []) or []
    tech_rows = _get_tech_rows(context or {})

    # Mappe tech-name (first token, lower) → eol_date aus Tech-Tabelle
    tech_eol: dict[str, str] = {}
    for r in tech_rows:
        name = (r.get("name") or "").strip().lower()
        if not name:
            continue
        first = name.split()[0]
        eol_date = r.get("eol_date")
        if eol_date and first not in tech_eol:
            tech_eol[first] = eol_date

    for f in findings:
        fid = f.get("id")
        title = (f.get("title") or "")
        body = _body_text(f)
        title_lower = title.lower()
        body_lower = body.lower()

        # MariaDB-vs-MySQL-Mixup
        for tok_a, tok_b in _MIXUP_PAIRS:
            if tok_a in title_lower and tok_b in body_lower and tok_a not in body_lower:
                issues.append(ValidationIssue(
                    check="eol",
                    severity="warning",
                    finding_id=fid,
                    message=(
                        f"Title nennt {tok_a.upper()}, Body referenziert "
                        f"{tok_b.upper()} (DB-Mix-Up?)"
                    ),
                    detail={"title_db": tok_a, "body_db": tok_b},
                ))
                break

        # EOL-Datum-Konsistenz: matche einen tech-name aus Tech-Tabelle
        # gegen den Finding-Text, und vergleiche EOL-Datum.
        for tech_name, tech_date in tech_eol.items():
            if len(tech_name) < 3:
                continue
            if tech_name in title_lower or tech_name in body_lower:
                # finde Datum-Token im Body
                body_dates = _find_dates(body)
                if not body_dates:
                    continue
                # Vergleich: Body-Datum vs Tech-Tabellen-Datum.
                # Normalisiere beide auf YYYY-MM (Praezision auf Monat).
                norm_tech = tech_date[:7] if len(tech_date) >= 7 else tech_date
                conflict = False
                conflict_body_date = None
                for bd in body_dates:
                    nb = bd[:7] if len(bd) >= 7 else bd
                    if nb and norm_tech and nb != norm_tech:
                        conflict = True
                        conflict_body_date = bd
                        break
                if conflict:
                    issues.append(ValidationIssue(
                        check="eol",
                        severity="warning",
                        finding_id=fid,
                        message=(
                            f"EOL-Datum im Finding ({conflict_body_date}) "
                            f"weicht von Tech-Tabelle ({tech_date}) ab "
                            f"fuer {tech_name}"
                        ),
                        detail={
                            "tech_name": tech_name,
                            "finding_date": conflict_body_date,
                            "tech_table_date": tech_date,
                        },
                    ))
                break  # Pro Finding nur ein EOL-Issue

    if not tech_rows:
        log.info("eol_check_no_tech_rows")

    return issues

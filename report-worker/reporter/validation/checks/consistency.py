"""Consistency-Check: prueft Title-vs-Body- und Title-vs-Tech-Versions-Inkonsistenzen.

Adressiert aus Doc 01 (Fehleranalyse_und_Korrekturplan.md):
- P0-02: Versionskonflikt zwischen Title/Description und Tech-Tabelle
  (z.B. Finding sagt "WordPress 6.9.4", Tech-Tabelle hat 6.4.2).
- P0-03: Title nennt Dienst A, aber Description/Evidence beschreibt Dienst B
  (typische Verwechslung SPF/DKIM, SSH/HTTP, RDP/SSH etc.).

Defensive Programmierung: Wenn Tech-Tabelle nicht zugaenglich, wird die
P0-02-Pruefung uebersprungen (Warning), die P0-03-Pruefung laeuft trotzdem.
"""
from __future__ import annotations

import json
import re
from typing import Any

import structlog

from reporter.validation.gate import ValidationIssue

log = structlog.get_logger()


# Token-Paare: wenn Title Token A enthaelt und Body Token B, aber Title NICHT
# Token B enthaelt → Konflikt. Reihenfolge (A, B) — A im Title, B im Body.
CONFLICTING_PAIRS: list[tuple[str, str]] = [
    ("SPF", "DKIM"),
    ("SPF", "DMARC"),
    ("DKIM", "SPF"),
    ("DKIM", "DMARC"),
    ("DMARC", "SPF"),
    ("DMARC", "DKIM"),
    ("SSH", "HTTP"),
    ("HTTP", "SSH"),
    ("RDP", "SSH"),
    ("SSH", "RDP"),
    ("FTP", "SFTP"),
    ("SFTP", "FTP"),
]

_STOPWORDS = {
    "und", "oder", "mit", "ohne", "auf", "der", "die", "das", "ist", "sein",
    "werden", "kann", "wird", "eines", "einer", "einem", "fuer", "für", "von",
    "den", "des", "dem", "nicht", "nach", "vor", "bei", "aus", "ueber", "über",
    "this", "that", "with", "without", "into", "from", "the", "and", "are",
    "service", "dienst", "server", "system",
}

_WORD_RE = re.compile(r"\b\w{4,}\b", re.UNICODE)

# Version-Patterns: z.B. "WordPress 6.9.4", "Apache 2.4.49"
_VERSION_PATTERN_TEMPLATE = (
    r"\b{name}[/\s\-_]+v?(\d+(?:\.\d+){{1,3}})"
)


def _word_token_match(token: str, text: str) -> bool:
    """Pruefe ob token in text als ganzes Wort vorkommt (Wortgrenze)."""
    pat = re.compile(rf"\b{re.escape(token)}\b", re.IGNORECASE)
    return bool(pat.search(text))


def _body_text(finding: dict[str, Any]) -> str:
    """Konkateniert description + evidence (als String) zu einem Body."""
    parts: list[str] = []
    if finding.get("description"):
        parts.append(str(finding["description"]))
    if finding.get("impact"):
        parts.append(str(finding["impact"]))
    if finding.get("recommendation"):
        parts.append(str(finding["recommendation"]))
    ev = finding.get("evidence")
    if isinstance(ev, str):
        parts.append(ev)
    elif isinstance(ev, (dict, list)):
        try:
            parts.append(json.dumps(ev, ensure_ascii=False, default=str))
        except Exception:
            parts.append(str(ev))
    return "\n".join(parts)


def _get_tech_versions(
    report_data: dict[str, Any],
    context: dict[str, Any],
) -> list[dict[str, str]]:
    """Hole alle Tech-Tabellen-Eintraege mit Version aus report_data oder context.

    Returns liste von Dicts mit `name`/`vendor`/`version`. Pragmatisch — wenn
    keine Daten zugaenglich, leere Liste.
    """
    rows: list[dict[str, str]] = []

    # 1. context.tech_profiles (durchgereicht vom Worker-Hook seit M1)
    profiles = context.get("tech_profiles") or []
    if profiles and isinstance(profiles, list):
        try:
            from reporter.tech_table_builder import build_tech_table_for_host
            for p in profiles:
                if not isinstance(p, dict):
                    continue
                try:
                    host_rows = build_tech_table_for_host(p)
                except Exception as e:
                    log.warning("tech_table_build_failed_in_check",
                                ip=p.get("ip"), error=str(e))
                    continue
                for r in host_rows:
                    if r.get("version"):
                        rows.append({
                            "name": r.get("name", ""),
                            "version": r.get("version", ""),
                            "category": r.get("category", ""),
                        })
        except ImportError:
            log.warning("tech_table_builder_unavailable")

    # 2. Fallback: report_data["scope"]["subsections"][*]["host_tech_blocks"]
    #    enthaelt Paragraph-Objekte — fuer Validation nicht praktikabel.
    #    Wir verlassen uns auf den Hook-Pfad.

    return rows


def check(
    findings_data: dict,
    report_data: dict,
    context: dict,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    findings = findings_data.get("findings", []) or []
    tech_rows = _get_tech_versions(report_data or {}, context or {})

    for f in findings:
        fid = f.get("id")
        title = (f.get("title") or "").strip()
        if not title:
            continue
        body = _body_text(f)

        # P0-03: Service-Verwechslung
        for tok_a, tok_b in CONFLICTING_PAIRS:
            if (
                _word_token_match(tok_a, title)
                and not _word_token_match(tok_b, title)
                and _word_token_match(tok_b, body)
            ):
                issues.append(ValidationIssue(
                    check="consistency",
                    severity="error",
                    finding_id=fid,
                    message=(
                        f"Title nennt {tok_a}, Body beschreibt {tok_b} "
                        f"(Service-Verwechslung)"
                    ),
                    detail={
                        "title_token": tok_a,
                        "body_token": tok_b,
                        "title": title,
                    },
                ))
                break  # Pro Finding nur ein Conflict-Issue

        # Title-Body-Keyword-Overlap (Warning bei sehr generischen Titles)
        title_words = {w.lower() for w in _WORD_RE.findall(title)} - _STOPWORDS
        body_words = {w.lower() for w in _WORD_RE.findall(body)} - _STOPWORDS
        if title_words and body_words and not (title_words & body_words):
            issues.append(ValidationIssue(
                check="consistency",
                severity="warning",
                finding_id=fid,
                message=(
                    "Title und Body teilen kein gemeinsames Schluesselwort — "
                    "moeglicherweise sehr generischer Title"
                ),
                detail={
                    "title": title,
                    "title_keywords": sorted(title_words),
                    "body_keywords_sample": sorted(body_words)[:8],
                },
            ))

        # P0-02: Versionskonflikt zwischen Description und Tech-Tabelle
        if tech_rows:
            for row in tech_rows:
                name = row.get("name", "").strip()
                tech_v = row.get("version", "").strip()
                if not name or not tech_v:
                    continue
                # Suche `<name> <version>` in Description/Title
                # Name kann z.B. "WordPress" oder "Apache HTTP Server" sein —
                # nutze nur das erste Token fuer den Match-Versuch.
                first_token = name.split()[0]
                if len(first_token) < 3:
                    continue
                pat = re.compile(
                    _VERSION_PATTERN_TEMPLATE.format(name=re.escape(first_token)),
                    re.IGNORECASE,
                )
                for haystack in (title, f.get("description") or ""):
                    if not haystack:
                        continue
                    m = pat.search(str(haystack))
                    if m:
                        found_v = m.group(1)
                        if found_v != tech_v and not (
                            found_v.startswith(tech_v) or tech_v.startswith(found_v)
                        ):
                            issues.append(ValidationIssue(
                                check="consistency",
                                severity="error",
                                finding_id=fid,
                                message=(
                                    f"Versionskonflikt {first_token}: "
                                    f"Finding nennt {found_v}, Tech-Tabelle hat {tech_v}"
                                ),
                                detail={
                                    "software": first_token,
                                    "finding_version": found_v,
                                    "tech_version": tech_v,
                                },
                            ))
                            break
        # Wenn tech_rows leer: P0-02 nicht pruefbar — geloggt, aber kein Issue.

    if not tech_rows:
        log.info("consistency_check_no_tech_rows",
                 reason="context.tech_profiles empty or unavailable")

    return issues

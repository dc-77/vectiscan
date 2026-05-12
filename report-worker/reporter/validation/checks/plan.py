"""Plan-Check: prueft Massnahmen-/Recommendations-Konsistenz.

Adressiert aus Doc 01 (Fehleranalyse_und_Korrekturplan.md):
- P2-03: Orphan-Recommendations (verweisen auf nicht-existente Finding-IDs)
  und Recommendations, die einen Port nennen, der in keinem Finding vorkommt
  (falsche Massnahme zu falschem Befund).
"""
from __future__ import annotations

import json
import re
from typing import Any

from reporter.validation.gate import ValidationIssue

# Port-Patterns in Recommendation-Text
_PORT_RE_LABELED = re.compile(r"\bPort\s+(\d{2,5})\b", re.IGNORECASE)
_PORT_RE_TCP_UDP = re.compile(r"\b(\d{2,5})\s*/\s*(tcp|udp)\b", re.IGNORECASE)


def _collect_finding_ports(findings: list[dict[str, Any]]) -> set[str]:
    """Sammle alle Port-Nummern, die in irgendeinem Finding vorkommen."""
    ports: set[str] = set()
    for f in findings:
        haystack_parts = [
            f.get("title", ""),
            f.get("description", ""),
            f.get("impact", ""),
            f.get("recommendation", ""),
            f.get("affected", ""),
        ]
        # explicit port-field falls vorhanden
        if f.get("port"):
            ports.add(str(f["port"]))
        ev = f.get("evidence")
        if isinstance(ev, dict):
            for key in ("port", "ports", "dst_port", "service_port"):
                v = ev.get(key)
                if v is None:
                    continue
                if isinstance(v, (list, tuple)):
                    for p in v:
                        ports.add(str(p))
                else:
                    ports.add(str(v))
            try:
                haystack_parts.append(json.dumps(ev, ensure_ascii=False, default=str))
            except Exception:
                haystack_parts.append(str(ev))
        elif isinstance(ev, list):
            try:
                haystack_parts.append(json.dumps(ev, ensure_ascii=False, default=str))
            except Exception:
                haystack_parts.append(str(ev))
        elif isinstance(ev, str):
            haystack_parts.append(ev)

        for part in haystack_parts:
            if not part:
                continue
            for m in _PORT_RE_LABELED.finditer(str(part)):
                ports.add(m.group(1))
            for m in _PORT_RE_TCP_UDP.finditer(str(part)):
                ports.add(m.group(1))
    return ports


def _normalize_rec(rec: Any) -> tuple[str, list[str]]:
    """Reduziere Recommendation auf (text, finding_refs)."""
    if isinstance(rec, str):
        return rec, []
    if isinstance(rec, dict):
        text = rec.get("text") or rec.get("title") or rec.get("description") or ""
        refs = rec.get("finding_refs") or rec.get("refs") or []
        if not isinstance(refs, list):
            refs = [refs]
        refs = [str(r) for r in refs if r]
        return str(text), refs
    return "", []


def check(
    findings_data: dict,
    report_data: dict,
    context: dict,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    findings = findings_data.get("findings", []) or []
    recommendations = findings_data.get("recommendations", []) or []

    finding_ids = {f.get("id") for f in findings if f.get("id")}
    finding_ports = _collect_finding_ports(findings)

    for idx, rec in enumerate(recommendations):
        text, refs = _normalize_rec(rec)
        rec_label = f"recommendation #{idx + 1}"

        # Orphan: keine finding_refs
        if not refs:
            issues.append(ValidationIssue(
                check="plan",
                severity="warning",
                finding_id=None,
                message=(
                    f"{rec_label} hat keine finding_refs (Orphan-Massnahme)"
                ),
                detail={"rec_index": idx, "rec_text": text[:200]},
            ))

        # Tote Refs
        for ref in refs:
            if ref not in finding_ids:
                issues.append(ValidationIssue(
                    check="plan",
                    severity="error",
                    finding_id=None,
                    message=(
                        f"{rec_label} referenziert nicht-existente Finding-ID "
                        f"{ref}"
                    ),
                    detail={
                        "rec_index": idx,
                        "missing_ref": ref,
                        "rec_text": text[:200],
                    },
                ))

        # Port-Konsistenz: Rec nennt Port, aber kein Finding tut das
        rec_ports: set[str] = set()
        for m in _PORT_RE_LABELED.finditer(text):
            rec_ports.add(m.group(1))
        for m in _PORT_RE_TCP_UDP.finditer(text):
            rec_ports.add(m.group(1))

        for p in rec_ports:
            if p not in finding_ports:
                issues.append(ValidationIssue(
                    check="plan",
                    severity="error",
                    finding_id=None,
                    message=(
                        f"{rec_label} nennt Port {p}, der in keinem Finding "
                        f"vorkommt"
                    ),
                    detail={
                        "rec_index": idx,
                        "rec_port": p,
                        "rec_text": text[:200],
                        "finding_ports_sample": sorted(finding_ports)[:12],
                    },
                ))

    return issues

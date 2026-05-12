"""IDs-Check: prueft Finding-IDs auf Korrektheit (Format, Luecken, Duplikate).

Adressiert aus Doc 01 (Fehleranalyse_und_Korrekturplan.md):
- P0-06: Loechrige/inkonsistente Finding-IDs (z.B. VS-2026-001 → -003).
  ID-Agent renumeriert in report_mapper.py; dieser Check wirkt als Safety-Net,
  falls die Renumerierung scheitert oder eine Quelle (Recommendations etc.)
  alte IDs referenziert.

ID-Format: `VS-YYYY-NNN` (3+ Stellen, fuehrende Nullen).
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any

from reporter.validation.gate import ValidationIssue

_ID_RE = re.compile(r"^VS-(\d{4})-(\d{3,})$")


def check(
    findings_data: dict,
    report_data: dict,
    context: dict,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    findings = findings_data.get("findings", []) or []

    raw_ids: list[str] = []
    valid_nums: list[int] = []
    year_seen: set[str] = set()

    for f in findings:
        raw = f.get("id")
        if not raw:
            issues.append(ValidationIssue(
                check="ids",
                severity="error",
                finding_id=None,
                message="Finding ohne ID",
                detail={"raw_id": None, "title": f.get("title")},
            ))
            continue
        raw_ids.append(raw)
        m = _ID_RE.match(raw)
        if not m:
            issues.append(ValidationIssue(
                check="ids",
                severity="error",
                finding_id=raw,
                message=f"Finding-ID-Format passt nicht zu VS-YYYY-NNN: {raw!r}",
                detail={"raw_id": raw},
            ))
            continue
        year_seen.add(m.group(1))
        valid_nums.append(int(m.group(2)))

    # Duplikate
    counter = Counter(raw_ids)
    for rid, count in counter.items():
        if count >= 2:
            issues.append(ValidationIssue(
                check="ids",
                severity="warning",
                finding_id=rid,
                message=f"ID {rid} wird {count}× vergeben",
                detail={"raw_id": rid, "count": count},
            ))

    if not valid_nums:
        return issues

    # Start bei 001?
    sorted_nums = sorted(set(valid_nums))
    if sorted_nums[0] != 1:
        issues.append(ValidationIssue(
            check="ids",
            severity="error",
            finding_id=None,
            message=f"Finding-IDs starten nicht bei 001 (erstes: {sorted_nums[0]:03d})",
            detail={"first_number": sorted_nums[0]},
        ))

    # Lueckenlos?
    expected = sorted_nums[0]
    for n in sorted_nums:
        while expected < n:
            year_for_msg = sorted(year_seen)[0] if year_seen else "????"
            missing_id = f"VS-{year_for_msg}-{expected:03d}"
            prev = f"VS-{year_for_msg}-{(expected - 1):03d}"
            nxt = f"VS-{year_for_msg}-{n:03d}"
            issues.append(ValidationIssue(
                check="ids",
                severity="error",
                finding_id=None,
                message=f"Luecke zwischen {prev} und {nxt}",
                detail={"missing": missing_id},
            ))
            expected += 1
        expected = n + 1

    return issues

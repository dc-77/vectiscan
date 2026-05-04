"""Deterministische Top-N-Auswahl pro Paket.

Spec: docs/deterministic/04-deterministic-selection.md

Ersetzt die Sonnet-getriebene implizite Auswahl durch reine Sortier- und
Konsolidierungs-Logik.

Aufruf-Reihenfolge im Reporter:
    1. severity_policy.apply_policy(findings, scan_context)
    2. business_impact.recompute(findings, package, domain)
    3. selection.select_findings(findings, package)  ← HIER
    4. claude_client.generate_narrative(selected)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ====================================================================
# KONFIG
# ====================================================================
TOP_N_PER_PACKAGE: dict[str, int] = {
    "webcheck":     8,
    "perimeter":   15,
    "compliance":  20,
    "supplychain": 15,
    "insurance":   15,
    # tlscompliance laeuft eigenen Pfad ohne Top-N
}

# A3: Mindest-Findings pro Paket. Wenn Top-N weniger liefert (z.B. KI gab nur
# 4 Findings zurueck obwohl perimeter 6 Min haette), werden Findings aus
# `additional[]` (sortiert by business_impact) nachgezogen. Wenn auch additional
# leer: Reporter-Retry-Hint wird ueber selection_result.retry_hint gemeldet.
MIN_N_PER_PACKAGE: dict[str, int] = {
    "webcheck":     3,
    "perimeter":   6,
    "compliance":  10,
    "supplychain": 6,
    "insurance":   6,
}

# Legacy-Aliase (CLAUDE.md): basic→webcheck, professional→perimeter, nis2→compliance
PACKAGE_ALIASES: dict[str, str] = {
    "basic": "webcheck",
    "professional": "perimeter",
    "nis2": "compliance",
}

DEFAULT_TOP_N = 10


# ====================================================================
# DATA CLASSES
# ====================================================================
@dataclass
class SelectionResult:
    """Output von select_findings()."""
    selected: list[dict] = field(default_factory=list)
    additional: list[dict] = field(default_factory=list)
    consolidation_groups: int = 0
    original_count: int = 0
    package: str = ""
    top_n: int = 0
    floor_applied: int = 0  # A3: Anzahl aus additional[] nachgezogen
    retry_hint: str | None = None  # A3: bei Unterproduktion fuer KI-Retry

    def __len__(self) -> int:
        return len(self.selected)

    def to_dict(self) -> dict:
        return {
            "selected": self.selected,
            "additional": self.additional,
            "stats": {
                "consolidation_groups": self.consolidation_groups,
                "original_count": self.original_count,
                "selected_count": len(self.selected),
                "additional_count": len(self.additional),
                "package": self.package,
                "top_n": self.top_n,
            },
        }


# ====================================================================
# KONSOLIDIERUNG ueber Hosts
# ====================================================================
STABLE_EVIDENCE_KEYS = (
    "header_name", "cookie_name", "cipher_suite", "tls_version",
    "cve_id", "cwe_id", "missing_directive", "exposed_path",
)


def _normalized_evidence_hash(finding: dict) -> str:
    """Hash ueber stabile Felder, die ein Finding ueber Hosts hinweg
    als „dasselbe" identifizieren.

    NICHT enthalten (variieren pro Host): host, ip, port, timestamp, finding_id.
    Enthalten: finding_type, policy_id, cvss_vector, ausgewaehlte evidence-Felder.
    """
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        evidence = {}
    stable_evidence = {
        k: evidence.get(k)
        for k in STABLE_EVIDENCE_KEYS
        if k in evidence and evidence.get(k) is not None
    }
    keypart = {
        "finding_type": finding.get("finding_type") or finding.get("type"),
        "policy_id": finding.get("policy_id"),
        "cvss_vector": finding.get("cvss_vector"),
        "evidence": stable_evidence,
    }
    serialized = json.dumps(keypart, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def _affected_host(finding: dict) -> str:
    """Affected-Host-Identifier fuer Konsolidierung.

    Multi-VHost-Probe (Mai 2026): vhost (FQDN) hat Vorrang vor host_ip,
    damit zwei VHosts auf derselben IP NICHT zu einem affected_host
    konsolidiert werden — Findings sollen pro VHost getrennt sichtbar
    bleiben.
    """
    return (finding.get("vhost") or finding.get("fqdn")
            or finding.get("host") or finding.get("host_ip") or finding.get("ip")
            or finding.get("affected") or "unknown")


def consolidate(findings: list[dict]) -> tuple[list[dict], int]:
    """Konsolidiert Findings, die ueber mehrere Hosts hinweg dasselbe Problem
    beschreiben, zu einem Finding mit affected_hosts-Liste.

    Returns: (consolidated_list, num_groups)
    """
    groups: dict[str, list[dict]] = {}
    insertion_order: list[str] = []
    for f in findings:
        h = _normalized_evidence_hash(f)
        if h not in groups:
            insertion_order.append(h)
        groups.setdefault(h, []).append(f)

    consolidated: list[dict] = []
    for hash_ in insertion_order:
        group = groups[hash_]
        if len(group) == 1:
            f = dict(group[0])
            f.setdefault("affected_hosts", [_affected_host(f)])
            consolidated.append(f)
            continue

        # Mehrere Findings → konsolidieren (Basis = erstes Finding)
        base = dict(group[0])
        affected = sorted({_affected_host(f) for f in group})
        base["affected_hosts"] = affected
        base["confidence"] = max(
            float(f.get("confidence") or 0.0) for f in group
        )
        base["business_impact_score"] = max(
            float(f.get("business_impact_score") or 0.0) for f in group
        )

        host_count = len(affected)
        if host_count > 1:
            base["title"] = (
                f"{base.get('title', '<untitled>')} "
                f"({host_count} Hosts betroffen)"
            )
        consolidated.append(base)

    return consolidated, len(groups)


# ====================================================================
# SORTIERUNG
# ====================================================================
def _sort_key(finding: dict) -> tuple:
    """Stabiler Sortier-Schluessel.

    Reihenfolge:
    1. business_impact_score DESC
    2. cvss_score DESC
    3. epss_score DESC
    4. confidence DESC
    5. finding_id ASC  ← Tiebreaker fuer 100% Determinismus
    """
    return (
        -float(finding.get("business_impact_score") or 0.0),
        -float(finding.get("cvss_score") or 0.0),
        -float(finding.get("epss_score") or 0.0),
        -float(finding.get("confidence") or 0.0),
        str(finding.get("finding_id") or finding.get("id") or ""),
    )


# ====================================================================
# HAUPT-FUNKTION
# ====================================================================
def select_findings(findings: list[dict],
                    package: str,
                    *,
                    top_n_override: Optional[int] = None,
                    drop_false_positives: bool = True) -> SelectionResult:
    """Waehlt deterministisch die Top-N Findings fuer ein Paket aus.

    Args:
        findings: Liste von Finding-Dicts (nach severity_policy + business_impact)
        package: webcheck | perimeter | compliance | supplychain | insurance
        top_n_override: optionaler Override
        drop_false_positives: Wenn True (default), werden is_false_positive=True
            Findings vor der Auswahl verworfen — sie tauchen weder in selected
            noch in additional auf.
    """
    if not findings:
        return SelectionResult(package=package, top_n=top_n_override or 0)

    # Optional: FP entfernen (Default True)
    pool = (
        [f for f in findings if not f.get("is_false_positive")]
        if drop_false_positives else list(findings)
    )

    package_norm = PACKAGE_ALIASES.get(
        package.lower().strip(), package.lower().strip()
    )
    top_n = top_n_override or TOP_N_PER_PACKAGE.get(package_norm, DEFAULT_TOP_N)
    original_count = len(findings)

    # 1. Konsolidieren ueber Hosts
    consolidated, group_count = consolidate(pool)

    # 2. Sortieren
    consolidated.sort(key=_sort_key)

    # 3. Top-N + Rest
    selected = consolidated[:top_n]
    additional = consolidated[top_n:]

    # 4. Floor (A3) — wenn KI weniger Findings lieferte als Min, fuelle aus
    # additional auf. Wenn auch das nicht reicht, retry_hint fuer Reporter.
    # Floor greift nur bei Standard-top_n; explizites top_n_override
    # respektiert was der Caller verlangt.
    floor_applied = 0
    retry_hint: str | None = None
    min_n = MIN_N_PER_PACKAGE.get(package_norm, 0) if top_n_override is None else 0
    if min_n > 0 and len(selected) < min_n:
        deficit = min_n - len(selected)
        if additional:
            extra = additional[:deficit]
            selected = selected + extra
            additional = additional[deficit:]
            floor_applied = len(extra)
        if len(selected) < min_n:
            retry_hint = (
                f"package={package_norm} hat nur {len(selected)} Findings "
                f"(Min {min_n}); KI lieferte zu wenig — Retry mit Hinweis "
                f"sinnvoll."
            )
            logger.warning(
                "selection_floor_underrun package=%s selected=%d min=%d",
                package_norm, len(selected), min_n,
            )

    logger.info(
        "Selection [%s]: %d original -> %d consolidated -> %d selected (top %d, floor +%d)",
        package_norm, original_count, len(consolidated), len(selected), top_n, floor_applied,
    )

    return SelectionResult(
        selected=selected,
        additional=additional,
        consolidation_groups=group_count,
        original_count=original_count,
        package=package_norm,
        top_n=top_n,
        floor_applied=floor_applied,
        retry_hint=retry_hint,
    )


# ====================================================================
# REPORTER-INTEGRATION-HELPER
# ====================================================================
def _shrink_for_prompt(finding: dict) -> dict:
    """Reduziert ein Finding auf die Felder, die der Reporter zur
    Narrative-Generierung braucht. Spart Tokens.
    """
    return {
        "finding_id": finding.get("finding_id") or finding.get("id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "policy_id": finding.get("policy_id"),
        "cvss_score": finding.get("cvss_score"),
        "cvss_vector": finding.get("cvss_vector"),
        "cwe_id": finding.get("cwe_id") or finding.get("cwe"),
        "owasp_id": finding.get("owasp_id"),
        "affected_hosts": finding.get("affected_hosts", []),
        "evidence_summary": (
            (finding.get("evidence") or {}).get("summary", "")
            if isinstance(finding.get("evidence"), dict)
            else str(finding.get("evidence") or "")[:300]
        ),
        "rationale": (
            finding.get("severity_provenance", {}).get("rationale", "")
        ),
        "business_impact_score": finding.get("business_impact_score"),
    }


def prepare_for_reporter(selection_result: SelectionResult,
                         scan_summary: dict) -> dict:
    """Formatiert die Selection fuer den Reporter (Sonnet, Narrative-only)."""
    return {
        "package": selection_result.package,
        "scan_summary": scan_summary,
        "selected_findings": [
            _shrink_for_prompt(f) for f in selection_result.selected
        ],
        "additional_findings": [
            {
                "finding_id": f.get("finding_id") or f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "policy_id": f.get("policy_id"),
            }
            for f in selection_result.additional
        ],
    }


__all__ = [
    "TOP_N_PER_PACKAGE",
    "PACKAGE_ALIASES",
    "DEFAULT_TOP_N",
    "SelectionResult",
    "consolidate",
    "select_findings",
    "prepare_for_reporter",
]

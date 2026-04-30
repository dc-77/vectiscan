"""
report-worker/reporter/selection.py

Deterministische Top-N-Auswahl pro Paket.
Spec: docs/specs/2026-Q2-determinism/04-deterministic-selection.md

Ersetzt die Sonnet-getriebene implizite Auswahl durch reine Sortier-
und Konsolidierungs-Logik.

Aufruf-Reihenfolge im Reporter:
    1. severity_policy.apply_policy(findings)
    2. business_impact.recompute(findings)
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
    # tlscompliance läuft eigenen Pfad ohne Top-N
}

DEFAULT_TOP_N = 10  # falls Paket nicht gemappt


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
            },
        }


# ====================================================================
# KONSOLIDIERUNG
# ====================================================================
def _normalized_evidence_hash(finding: dict) -> str:
    """
    Hash über stabile Felder, die ein Finding über mehrere Hosts hinweg
    als „dasselbe" identifizieren.

    NICHT enthalten (variieren pro Host):
    - host, ip, port (das ist ja gerade die affected_hosts-Liste)
    - timestamp
    - finding_id
    - tool_metrics

    Enthalten:
    - finding_type, policy_id
    - cvss_vector (wenn gesetzt)
    - relevante evidence-Felder (cipher_suite, cookie_name, header_name, …)

    TODO(claude-code): Liste der „stabilen" Evidence-Felder ggf. anpassen
    nach realen Daten. Lieber konservativ (= weniger konsolidieren) als
    aggressiv (= unterschiedliche Findings zusammenwerfen).
    """
    evidence = finding.get("evidence", {})
    stable_evidence_keys = (
        "header_name", "cookie_name", "cipher_suite", "tls_version",
        "cve_id", "cwe_id", "missing_directive", "exposed_path",
    )
    stable_evidence = {
        k: evidence.get(k)
        for k in stable_evidence_keys
        if k in evidence and evidence.get(k) is not None
    }

    keypart = {
        "finding_type": finding.get("finding_type") or finding.get("type"),
        "policy_id": finding.get("policy_id"),
        "cvss_vector": finding.get("cvss_vector"),
        "evidence": stable_evidence,
    }
    serialized = json.dumps(keypart, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


def consolidate(findings: list[dict]) -> tuple[list[dict], int]:
    """
    Konsolidiert Findings, die über mehrere Hosts hinweg dasselbe Problem
    beschreiben, zu einem Finding mit affected_hosts-Liste.

    Returns: (consolidated_list, num_groups)
    """
    groups: dict[str, list[dict]] = {}
    for f in findings:
        h = _normalized_evidence_hash(f)
        groups.setdefault(h, []).append(f)

    consolidated = []
    for hash_, group in groups.items():
        if len(group) == 1:
            # Single host — affected_hosts trotzdem setzen für Konsistenz
            f = dict(group[0])
            host = f.get("host") or f.get("ip") or "unknown"
            f.setdefault("affected_hosts", [host])
            consolidated.append(f)
        else:
            # Mehrere Hosts → konsolidieren
            base = dict(group[0])  # Erstes Finding als Basis
            affected = sorted({
                f.get("host") or f.get("ip") or "unknown" for f in group
            })
            base["affected_hosts"] = affected

            # Confidence = max der Gruppe (irgendeiner war sicher)
            base["confidence"] = max(
                (f.get("confidence", 0.0) or 0.0) for f in group
            )

            # business_impact_score = max der Gruppe (max betroffener Host)
            base["business_impact_score"] = max(
                (f.get("business_impact_score", 0.0) or 0.0) for f in group
            )

            # Title / Description ergänzen mit Host-Anzahl
            host_count = len(affected)
            if host_count > 1:
                base["title"] = (
                    f"{base.get('title', '<untitled>')} ({host_count} Hosts betroffen)"
                )

            consolidated.append(base)

    return consolidated, len(groups)


# ====================================================================
# SORTIERUNG
# ====================================================================
def _sort_key(finding: dict) -> tuple:
    """
    Stabiler Sortier-Schlüssel.

    Negative Werte für DESC-Sortierung auf numerischen Feldern.
    finding_id als String → ASC-Sortierung als Tiebreaker.

    Reihenfolge der Kriterien:
    1. business_impact_score DESC  (Hauptkriterium)
    2. cvss_score DESC
    3. epss_score DESC
    4. confidence DESC
    5. finding_id ASC  ← Tiebreaker für 100% Determinismus
    """
    return (
        -float(finding.get("business_impact_score") or 0.0),
        -float(finding.get("cvss_score") or 0.0),
        -float(finding.get("epss_score") or 0.0),
        -float(finding.get("confidence") or 0.0),
        str(finding.get("finding_id") or ""),
    )


# ====================================================================
# HAUPTFUNKTION
# ====================================================================
def select_findings(findings: list[dict],
                    package: str,
                    *,
                    top_n_override: Optional[int] = None) -> SelectionResult:
    """
    Wählt deterministisch die Top-N Findings für ein Paket aus.

    Args:
        findings: Liste von Finding-Dicts (nach severity_policy + business_impact)
        package: "webcheck" | "perimeter" | "compliance" | "supplychain" | "insurance"
        top_n_override: optionale Override für Top-N (für Tests/Edge-Cases)

    Returns:
        SelectionResult mit selected (Top-N) und additional (Rest)
    """
    if not findings:
        return SelectionResult(package=package)

    package_norm = package.lower().strip()
    top_n = top_n_override or TOP_N_PER_PACKAGE.get(package_norm, DEFAULT_TOP_N)

    original_count = len(findings)

    # 1. Konsolidieren über Hosts
    consolidated, group_count = consolidate(findings)

    # 2. Sortieren
    consolidated.sort(key=_sort_key)

    # 3. Top-N + Rest
    selected = consolidated[:top_n]
    additional = consolidated[top_n:]

    logger.info(
        "Selection [%s]: %d original → %d consolidated → %d selected (top %d)",
        package_norm, original_count, len(consolidated), len(selected), top_n,
    )

    return SelectionResult(
        selected=selected,
        additional=additional,
        consolidation_groups=group_count,
        original_count=original_count,
        package=package_norm,
    )


# ====================================================================
# REPORTER-INTEGRATION-HELPER
# ====================================================================
def prepare_for_reporter(selection_result: SelectionResult,
                         scan_summary: dict) -> dict:
    """
    Formatiert die Selection für den Reporter (Sonnet, Narrative-only).

    Returns: dict mit Schema, das der REPORTER_NARRATIVE_ONLY_PROMPT erwartet.
    """
    return {
        "package": selection_result.package,
        "scan_summary": scan_summary,
        "selected_findings": [
            _shrink_for_prompt(f) for f in selection_result.selected
        ],
        "additional_findings": [
            {
                "finding_id": f.get("finding_id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "policy_id": f.get("policy_id"),
            }
            for f in selection_result.additional
        ],
    }


def _shrink_for_prompt(finding: dict) -> dict:
    """
    Reduziert ein Finding auf die Felder, die der Reporter zur
    Narrative-Generierung braucht. Spart Tokens.
    """
    return {
        "finding_id": finding.get("finding_id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "policy_id": finding.get("policy_id"),
        "cvss_score": finding.get("cvss_score"),
        "cvss_vector": finding.get("cvss_vector"),
        "cwe_id": finding.get("cwe_id"),
        "owasp_id": finding.get("owasp_id"),
        "affected_hosts": finding.get("affected_hosts", []),
        "evidence_summary": finding.get("evidence", {}).get("summary", ""),
        "rationale": (
            finding.get("severity_provenance", {}).get("rationale", "")
        ),
        "business_impact_score": finding.get("business_impact_score"),
    }


# ====================================================================
# EXPORTS
# ====================================================================
__all__ = [
    "TOP_N_PER_PACKAGE",
    "SelectionResult",
    "consolidate",
    "select_findings",
    "prepare_for_reporter",
]

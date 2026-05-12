"""CVSS-Konsistenz: Vektor<->Score deterministisch ableiten, Format normalisieren.

Spec: docs/report-erstellung/01_Fehleranalyse_und_Korrekturplan.md Phase C
Plan: M2 Track 2a

CVSS-Score wird IMMER aus dem Vektor berechnet (FIRST-cvss-Library).
Findings ohne Impact-Komponente werden mit Hygiene-Skala markiert,
nicht mit CVSS.
"""

from __future__ import annotations

from typing import Any

try:
    from cvss import CVSS3
    _CVSS_AVAILABLE = True
except ImportError:
    CVSS3 = None
    _CVSS_AVAILABLE = False


CVSS31_PREFIX = "CVSS:3.1/"
_VECTOR_FIELDS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def normalize_vector(vector: str | None) -> str | None:
    """Prefix `CVSS:3.1/` erzwingen. None bei leerem/ungueltigem Vektor."""
    if not vector or vector in ("—", "-", ""):
        return None
    v = vector.strip()
    if not v:
        return None
    # Falls Prefix doppelt vorkommt (Tool-Drift), nur einer bleibt
    while v.upper().startswith("CVSS:3.1/CVSS:3.1/"):
        v = v[len(CVSS31_PREFIX):]
    if not v.upper().startswith("CVSS:3.0/") and not v.upper().startswith("CVSS:3.1/"):
        v = CVSS31_PREFIX + v
    # CVSS:3.0 hochstufen auf 3.1 (gleicher Format-Spec, gleiche Felder)
    if v.upper().startswith("CVSS:3.0/"):
        v = CVSS31_PREFIX + v[len("CVSS:3.0/"):]
    return v


def is_zero_impact_vector(vector: str) -> bool:
    """True wenn C:N/I:N/A:N -- keine Vertraulichkeits-/Integritaets-/
    Verfuegbarkeits-Auswirkung. Solche Findings gehoeren in die Hygiene-Skala.
    """
    v = vector.upper()
    return ("C:N" in v) and ("I:N" in v) and ("A:N" in v)


def score_from_vector(vector: str) -> float | None:
    """Score aus Vektor via FIRST-cvss-Library berechnen.

    Returns: float Score (gerundet auf 1 Nachkommastelle, identisch zu NVD).
             None wenn Library nicht verfuegbar oder Vektor ungueltig.
    """
    if not _CVSS_AVAILABLE or not vector:
        return None
    try:
        c = CVSS3(vector)
        return round(float(c.scores()[0]), 1)
    except Exception:
        return None


# ====================================================================
# HYGIENE-SKALA
# ====================================================================
# Findings ohne sinnvolle CVSS-Bewertung (fehlende Header, Cookie-Flags,
# Best-Practice-Abweichungen). Bekommen scale="hygiene" + hygiene_level
# statt CVSS-Score.
HYGIENE_FINDING_TYPES: set[str] = {
    "header_hsts_missing",
    "header_hsts_no_subdomains",
    "header_hsts_short_maxage",
    "header_hsts_no_preload",
    "header_xcto_missing",
    "header_xfo_missing",
    "header_referrer_policy_missing",
    "header_permissions_policy_missing",
    "csp_missing",
    "csp_weak",
    "csp_unsafe_inline",
    "csp_unsafe_eval",
    "csp_wildcard_source",
    "cookie_missing_secure",
    "cookie_missing_httponly",
    "cookie_missing_samesite",
    "session_cookie_missing_secure",
    "session_cookie_missing_samesite",
    "sri_missing",
    "info_disclosure_banner",
    "info_disclosure_meta_generator",
    "private_ip_disclosure",
    "framework_dev_build_exposed",
}


HYGIENE_BY_FINDING_TYPE: dict[str, str] = {
    # high = aktive Angriffsvektoren (Downgrade, Injection)
    "header_hsts_missing": "high",
    "header_hsts_no_subdomains": "medium",
    "header_hsts_short_maxage": "medium",
    "header_hsts_no_preload": "low",
    "csp_missing": "medium",
    "csp_weak": "medium",
    "csp_unsafe_inline": "high",
    "csp_unsafe_eval": "high",
    "csp_wildcard_source": "medium",
    "cookie_missing_secure": "high",
    "cookie_missing_httponly": "medium",
    "cookie_missing_samesite": "medium",
    "session_cookie_missing_secure": "high",
    "session_cookie_missing_samesite": "high",
    "header_xcto_missing": "low",
    "header_xfo_missing": "low",
    "header_referrer_policy_missing": "low",
    "header_permissions_policy_missing": "low",
    "sri_missing": "low",
    "info_disclosure_banner": "low",
    "info_disclosure_meta_generator": "low",
    "private_ip_disclosure": "low",
    "framework_dev_build_exposed": "medium",
}


def hygiene_level_for(finding_type: str | None) -> str | None:
    if not finding_type:
        return None
    return HYGIENE_BY_FINDING_TYPE.get(finding_type)


def is_hygiene_finding(finding: dict) -> bool:
    """True wenn das Finding in die Hygiene-Skala statt CVSS gehoert."""
    ft = (finding.get("finding_type") or finding.get("type") or "").strip().lower()
    return ft in HYGIENE_FINDING_TYPES


def _is_severity_info_with_intent(finding: dict) -> bool:
    """Tools setzen manchmal INFO + C:N/I:N/A:N als intendierten reinen
    Informationshinweis (z.B. "Service erkannt"). Diese sind keine
    Hygiene-Findings, die wir mit Stufe markieren wollen -- wir lassen
    sie als CVSS-Path mit Score 0.0 (legitim laut FIRST).
    """
    sev = (finding.get("severity") or "").upper()
    policy_id = finding.get("policy_id") or ""
    return sev == "INFO" and isinstance(policy_id, str) and policy_id.startswith("SP-INFO-")


def apply_consistency(finding: dict) -> dict:
    """Hauptfunktion: normalisiere Vektor, berechne Score, setze Hygiene-Skala.

    Mutiert das Finding in-place und liefert es zurueck.
    Felder am Ende:
      - cvss_vector: normalisierter Vektor (oder None) -- `CVSS:3.1/...`
      - cvss_score: float aus Vektor berechnet (oder None bei Hygiene)
      - scale: "cvss" | "hygiene" -- neuer Diskriminator
      - hygiene_level: "low"|"medium"|"high" (nur bei scale="hygiene")
      - score_provenance: "vector" | "policy_fallback" | "hygiene_skala"
    """
    raw_vec = finding.get("cvss_vector")
    if isinstance(raw_vec, str):
        norm_vec = normalize_vector(raw_vec)
    else:
        norm_vec = None
    finding["cvss_vector"] = norm_vec

    # Hygiene-Pfad: explizit kein CVSS
    if is_hygiene_finding(finding) or (
        norm_vec
        and is_zero_impact_vector(norm_vec)
        and not _is_severity_info_with_intent(finding)
    ):
        # Bei "is_zero_impact_vector AND finding nicht explizit als hygiene
        # typisiert" wird die Hygiene-Skala automatisch gesetzt -- verhindert
        # CVSS 0.0 in Audit-Spalten.
        finding["scale"] = "hygiene"
        finding["cvss_vector"] = None
        finding["cvss_score"] = None
        ft = (finding.get("finding_type") or finding.get("type") or "").lower()
        finding["hygiene_level"] = hygiene_level_for(ft) or "low"
        finding["score_provenance"] = "hygiene_skala"
        # Severity wird auf INFO gesetzt (kein CVSS-Tier-Mapping)
        if not finding.get("severity"):
            finding["severity"] = "INFO"
        return finding

    # CVSS-Pfad
    finding["scale"] = "cvss"
    score = score_from_vector(norm_vec) if norm_vec else None
    if score is not None:
        finding["cvss_score"] = score
        finding["score_provenance"] = "vector"
    else:
        # Fallback: behalte vorhandenen Score (z.B. aus severity_policy-Regel
        # gesetzt). Wird vom validation-cvss.py-Check geprueft.
        finding["score_provenance"] = "policy_fallback"
    return finding


__all__ = [
    "CVSS31_PREFIX",
    "normalize_vector",
    "is_zero_impact_vector",
    "score_from_vector",
    "is_hygiene_finding",
    "hygiene_level_for",
    "apply_consistency",
    "HYGIENE_FINDING_TYPES",
    "HYGIENE_BY_FINDING_TYPE",
]

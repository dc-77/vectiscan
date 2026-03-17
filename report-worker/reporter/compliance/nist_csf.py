"""NIST Cybersecurity Framework mapping.

Maps scan findings to NIST CSF 2.0 functions and categories.
Used as supplementary references across report variants.
"""

from __future__ import annotations

from typing import Any

# NIST CSF 2.0 categories relevant to external assessments
NIST_CSF_CATEGORIES: dict[str, dict[str, str]] = {
    "ID.AM": {"function": "IDENTIFY", "title": "Asset Management"},
    "ID.RA": {"function": "IDENTIFY", "title": "Risk Assessment"},
    "PR.AC": {"function": "PROTECT", "title": "Access Control"},
    "PR.DS": {"function": "PROTECT", "title": "Data Security"},
    "PR.IP": {"function": "PROTECT", "title": "Information Protection"},
    "PR.PT": {"function": "PROTECT", "title": "Protective Technology"},
    "DE.CM": {"function": "DETECT", "title": "Continuous Monitoring"},
    "DE.AE": {"function": "DETECT", "title": "Anomalies and Events"},
    "RS.AN": {"function": "RESPOND", "title": "Analysis"},
}

_KEYWORD_MAPPING: list[tuple[list[str], str]] = [
    (["ssl", "tls", "cipher", "encryption", "certificate"], "PR.DS"),
    (["authentication", "login", "password", "mfa", "credential"], "PR.AC"),
    (["firewall", "waf", "header", "security-header"], "PR.PT"),
    (["cve-", "vulnerability", "patch", "schwachstell"], "ID.RA"),
    (["monitoring", "log", "alert"], "DE.CM"),
    (["asset", "inventory", "port", "service"], "ID.AM"),
]


def map_finding_to_nist(finding: dict[str, Any]) -> str:
    """Map a finding to the most relevant NIST CSF category."""
    text = (finding.get("title", "") + " " + finding.get("description", "")).lower()

    for keywords, category in _KEYWORD_MAPPING:
        if any(kw in text for kw in keywords):
            return category

    return "ID.RA"  # Default: Risk Assessment


def get_category_title(ref: str) -> str:
    """Get the title for a NIST CSF category."""
    cat = NIST_CSF_CATEGORIES.get(ref, {})
    return f"{cat.get('function', '?')} — {cat.get('title', ref)}"

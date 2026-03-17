"""ISO 27001 Annex A compliance mapping.

Maps scan findings to ISO 27001:2022 Annex A controls.
Used primarily for the SupplyChain report variant.
"""

from __future__ import annotations

from typing import Any

# ISO 27001:2022 Annex A controls relevant to external security assessments
ISO27001_CONTROLS: dict[str, dict[str, str]] = {
    "A.5.1": {"title": "Informationssicherheitspolitik", "category": "Organisatorisch"},
    "A.5.7": {"title": "Bedrohungsintelligenz", "category": "Organisatorisch"},
    "A.5.23": {"title": "Informationssicherheit bei Cloud-Diensten", "category": "Organisatorisch"},
    "A.8.1": {"title": "Verwaltung von Vermögenswerten", "category": "Technologisch"},
    "A.8.5": {"title": "Sichere Authentifizierung", "category": "Technologisch"},
    "A.8.8": {"title": "Management technischer Schwachstellen", "category": "Technologisch"},
    "A.8.9": {"title": "Konfigurationsmanagement", "category": "Technologisch"},
    "A.8.20": {"title": "Netzwerksicherheit", "category": "Technologisch"},
    "A.8.21": {"title": "Sicherheit von Netzwerkdiensten", "category": "Technologisch"},
    "A.8.24": {"title": "Einsatz von Kryptografie", "category": "Technologisch"},
    "A.8.25": {"title": "Sichere Entwicklung", "category": "Technologisch"},
    "A.8.28": {"title": "Sichere Programmierung", "category": "Technologisch"},
}

# Keyword-based auto-mapping
_KEYWORD_MAPPING: list[tuple[list[str], str]] = [
    (["ssl", "tls", "cipher", "encryption", "hsts", "certificate", "kryptogra"], "A.8.24"),
    (["port", "firewall", "netzwerk", "network", "exponiert", "exposed"], "A.8.20"),
    (["cve-", "schwachstell", "vulnerability", "patch", "update"], "A.8.8"),
    (["header", "security-header", "konfiguration", "default", "misconfigur"], "A.8.9"),
    (["authentication", "login", "passwort", "password", "mfa", "credential"], "A.8.5"),
    (["xss", "injection", "sqli", "rce", "code execution"], "A.8.28"),
    (["cloud", "aws", "azure", "s3", "bucket"], "A.5.23"),
    (["cisa", "exploit", "threat", "bedrohung"], "A.5.7"),
    (["asset", "inventar", "inventory"], "A.8.1"),
]


def map_finding_to_iso27001(finding: dict[str, Any]) -> str:
    """Map a finding to the most relevant ISO 27001 Annex A control."""
    text = (
        finding.get("title", "") + " " +
        finding.get("description", "") + " " +
        finding.get("recommendation", "")
    ).lower()

    for keywords, control in _KEYWORD_MAPPING:
        if any(kw in text for kw in keywords):
            return control

    return "A.8.8"  # Default: Schwachstellenmanagement


def get_control_title(control_ref: str) -> str:
    """Get the title for an ISO 27001 control reference."""
    control = ISO27001_CONTROLS.get(control_ref, {})
    return control.get("title", control_ref)


def build_iso27001_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build ISO 27001 mapping summary for a set of findings."""
    controls_found: set[str] = set()
    for f in findings:
        ref = f.get("iso27001_ref", map_finding_to_iso27001(f))
        controls_found.add(ref)

    covered = sorted(controls_found)
    all_controls = set(ISO27001_CONTROLS.keys())
    partial = sorted(all_controls - controls_found)

    return {
        "controls_covered": covered,
        "controls_partial": partial[:5],  # Top 5 not fully covered
        "total_controls_assessed": len(covered),
        "scope_note": (
            "Dieser Scan deckt technische Controls der ISO 27001 Annex A ab. "
            "Organisatorische, personelle und physische Controls erfordern "
            "ein separates Audit."
        ),
    }

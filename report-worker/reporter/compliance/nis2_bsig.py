"""NIS2 / §30 BSIG compliance mapping.

Maps scan findings to §30 BSIG (NIS2UmsuCG) requirements.
Refactored from v1 inline logic into a reusable module.
"""

from __future__ import annotations

from typing import Any

# §30 BSIG Abs. 2 requirements
BSIG_REQUIREMENTS: dict[str, dict[str, str]] = {
    "nr1": {
        "ref": "§30 Abs. 2 Nr. 1 BSIG",
        "title": "Risikoanalyse und Sicherheitskonzepte",
        "description": "Konzepte für die Risikoanalyse und für die Sicherheit von Informationssystemen.",
    },
    "nr2": {
        "ref": "§30 Abs. 2 Nr. 2 BSIG",
        "title": "Bewältigung von Sicherheitsvorfällen",
        "description": "Bewältigung von Sicherheitsvorfällen.",
    },
    "nr3": {
        "ref": "§30 Abs. 2 Nr. 3 BSIG",
        "title": "Aufrechterhaltung und Wiederherstellung",
        "description": "Aufrechterhaltung des Betriebs und Krisenmanagement.",
    },
    "nr4": {
        "ref": "§30 Abs. 2 Nr. 4 BSIG",
        "title": "Sicherheit der Lieferkette",
        "description": "Sicherheit der Lieferkette einschließlich sicherheitsbezogener Aspekte.",
    },
    "nr5": {
        "ref": "§30 Abs. 2 Nr. 5 BSIG",
        "title": "Schwachstellenmanagement",
        "description": "Sicherheitsmaßnahmen bei Erwerb, Entwicklung und Wartung von Systemen, einschließlich Schwachstellenmanagement.",
    },
    "nr6": {
        "ref": "§30 Abs. 2 Nr. 6 BSIG",
        "title": "Bewertung der Wirksamkeit",
        "description": "Konzepte und Verfahren zur Bewertung der Wirksamkeit von Risikomanagementmaßnahmen.",
    },
    "nr7": {
        "ref": "§30 Abs. 2 Nr. 7 BSIG",
        "title": "Cyberhygiene und Schulungen",
        "description": "Grundlegende Verfahren im Bereich der Cyberhygiene und Schulungen.",
    },
    "nr8": {
        "ref": "§30 Abs. 2 Nr. 8 BSIG",
        "title": "Kryptografie und Verschlüsselung",
        "description": "Konzepte und Verfahren für den Einsatz von Kryptografie und Verschlüsselung.",
    },
    "nr9": {
        "ref": "§30 Abs. 2 Nr. 9 BSIG",
        "title": "Personalsicherheit und Zugriffskontrolle",
        "description": "Sicherheit des Personals, Konzepte für die Zugriffskontrolle und das Management von Anlagen.",
    },
    "nr10": {
        "ref": "§30 Abs. 2 Nr. 10 BSIG",
        "title": "Multi-Faktor-Authentifizierung",
        "description": "Verwendung von MFA, gesicherte Kommunikation und ggf. gesicherte Notfallkommunikation.",
    },
}

# Keyword-based auto-mapping rules
_KEYWORD_MAPPING: list[tuple[list[str], str]] = [
    # Nr. 8: Kryptografie
    (["ssl", "tls", "cipher", "encryption", "hsts", "certificate", "zertifikat",
      "kryptogra", "verschlüsselung", "dnssec"], "nr8"),
    # Nr. 5: Schwachstellenmanagement
    (["port", "firewall", "header", "security-header", "information disclosure",
      "robots.txt", "banner", "cve-", "schwachstell", "vulnerability", "patch",
      "exponiert", "exposed"], "nr5"),
    # Nr. 10: MFA
    (["mfa", "multi-faktor", "authentifizierung", "authentication", "2fa"], "nr10"),
    # Nr. 9: Zugriffskontrolle
    (["access", "zugriff", "permission", "privilege", "authorization"], "nr9"),
    # Nr. 4: Lieferkette
    (["supply chain", "lieferkette", "third-party", "drittanbieter"], "nr4"),
    # Nr. 1: Risikoanalyse (catch-all for general findings)
    (["risiko", "risk", "general", "allgemein"], "nr1"),
]


def map_finding_to_bsig(finding: dict[str, Any]) -> str:
    """Map a finding to the most relevant §30 BSIG requirement.

    Returns the requirement key (e.g., "nr5") or "nr5" as default.
    """
    text = (
        finding.get("title", "") + " " +
        finding.get("description", "") + " " +
        finding.get("recommendation", "")
    ).lower()

    for keywords, req_key in _KEYWORD_MAPPING:
        if any(kw in text for kw in keywords):
            return req_key

    return "nr5"  # Default: Schwachstellenmanagement


def get_bsig_ref(req_key: str) -> str:
    """Get the full §30 BSIG reference string for a requirement key."""
    req = BSIG_REQUIREMENTS.get(req_key, BSIG_REQUIREMENTS["nr5"])
    return req["ref"]


def build_compliance_summary(findings: list[dict[str, Any]]) -> dict[str, str]:
    """Build NIS2 compliance summary based on findings.

    Returns dict with nr1..nr10 → COVERED|PARTIAL|NOT_IN_SCOPE.
    """
    summary: dict[str, str] = {
        "nr1_risikoanalyse": "PARTIAL",
        "nr2_vorfallbewaeltigung": "PARTIAL",
        "nr3_aufrechterhaltung": "NOT_IN_SCOPE",
        "nr4_lieferkette": "COVERED",
        "nr5_schwachstellenmanagement": "COVERED",
        "nr6_wirksamkeitsbewertung": "COVERED",
        "nr7_cyberhygiene": "NOT_IN_SCOPE",
        "nr8_kryptografie": "PARTIAL",
        "nr9_zugriffskontrolle": "NOT_IN_SCOPE",
        "nr10_mfa": "NOT_IN_SCOPE",
        "scope_note": (
            "Dieser Scan deckt die externe Angriffsoberfläche ab. "
            "Interne Prozesse, Schulungen und organisatorische Maßnahmen "
            "können durch einen externen Scan nicht bewertet werden."
        ),
    }

    # Check if TLS was scanned → nr8 = COVERED
    for f in findings:
        text = (f.get("title", "") + " " + f.get("description", "")).lower()
        if any(kw in text for kw in ("tls", "ssl", "cipher", "certificate")):
            summary["nr8_kryptografie"] = "COVERED"
            break

    return summary

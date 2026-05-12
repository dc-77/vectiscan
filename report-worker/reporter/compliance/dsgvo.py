"""DSGVO / GDPR compliance mapping (M5 Track 5c, Doc 02 Anhang D).

Maps scan findings to GDPR articles relevant to technical and
organizational measures (TOMs). Focus on Art. 32 (Datensicherheit)
since that is the technical-measures backbone of GDPR.

This module is parallel to nis2_bsig.py / iso27001.py / bsi_grundschutz.py
and provides `map_finding_to_dsgvo(finding)` plus reference helpers.
"""

from __future__ import annotations

from typing import Any


# DSGVO articles relevant for external security assessments.
# Each entry: ref_string + short title.
DSGVO_ARTICLES: dict[str, dict[str, str]] = {
    "Art. 32 Abs. 1 lit. a": {
        "title": "Pseudonymisierung und Verschluesselung personenbezogener Daten",
    },
    "Art. 32 Abs. 1 lit. b": {
        "title": (
            "Vertraulichkeit, Integritaet, Verfuegbarkeit und Belastbarkeit "
            "der Verarbeitungssysteme"
        ),
    },
    "Art. 32 Abs. 1 lit. c": {
        "title": (
            "Wiederherstellung der Verfuegbarkeit personenbezogener Daten "
            "nach Zwischenfall"
        ),
    },
    "Art. 32 Abs. 1 lit. d": {
        "title": (
            "Verfahren zur regelmaessigen Ueberpruefung, Bewertung und "
            "Evaluierung der Wirksamkeit der technischen Massnahmen"
        ),
    },
    "Art. 5 Abs. 1 lit. f": {
        "title": (
            "Integritaet und Vertraulichkeit (Grundsatz)"
        ),
    },
    "Art. 25": {
        "title": "Datenschutz durch Technikgestaltung und durch Voreinstellungen",
    },
    "Art. 33": {
        "title": "Meldung von Verletzungen des Schutzes personenbezogener Daten",
    },
}


# Keyword-based mapping. Reihenfolge ist wichtig — der erste Treffer gewinnt.
# Spezifischere Patterns nach oben.
_KEYWORD_MAPPING: list[tuple[list[str], str]] = [
    # Privacy-by-Default / Header-Hygiene / Cookie-Flags -> Art. 25
    # WICHTIG: vor dem TLS-Bucket gelistet, weil HSTS/Strict-Transport-
    # Header zwar transport-bezogen sind, aber als Browser-Direktive zur
    # "Datenschutz-by-Default"-Domain gehoeren.
    (
        ["hsts", "strict-transport-security", "csp",
         "content-security-policy", "x-content-type-options",
         "x-frame-options", "referrer-policy", "permissions-policy",
         "cookie", "samesite", "httponly", "secure flag", "secure-flag",
         "subresource-integrity", "sri"],
        "Art. 25",
    ),
    # Verschluesselung / TLS / Krypto -> Art. 32 Abs. 1 lit. a
    (
        ["tls", "ssl", "cipher", "encryption", "verschluess", "kryptogra",
         "certificate", "zertifikat", "tr-03116", "rc4", "starttls"],
        "Art. 32 Abs. 1 lit. a",
    ),
    # Vorfallmeldung (Compromise/Threat-Intel)
    (
        ["urlhaus", "kompromittiert", "compromised", "abuse", "leak"],
        "Art. 33",
    ),
    # Wiederherstellung / Backup
    (
        ["backup", "sicherung", "restore", "wiederherstell"],
        "Art. 32 Abs. 1 lit. c",
    ),
    # Wirksamkeitspruefung / Patch / EOL / CVE
    (
        ["patch", "update", "eol", "end-of-life", "outdated", "veraltet",
         "cve-", "schwachstell", "vulnerability"],
        "Art. 32 Abs. 1 lit. d",
    ),
    # Spoofing / Authentizitaet -> Integritaet/Vertraulichkeit Grundsatz
    (
        ["spf", "dkim", "dmarc", "spoofing", "mta-sts", "bimi", "dnssec"],
        "Art. 5 Abs. 1 lit. f",
    ),
    # Klartext-Login / FTP / Telnet -> Vertraulichkeit
    (
        ["klartext", "cleartext", "ftp", "telnet", "klar", "http statt https",
         "http-login"],
        "Art. 32 Abs. 1 lit. b",
    ),
]

# Default (Catch-all) — Art. 32 Abs. 1 lit. b ist die generische TOM-Klausel.
_DEFAULT = "Art. 32 Abs. 1 lit. b"


def map_finding_to_dsgvo(finding: dict[str, Any]) -> str:
    """Map a finding to the most relevant DSGVO article.

    Returns a string suitable for direct rendering ("Art. 32 Abs. 1 lit. b").
    Default ist Art. 32 Abs. 1 lit. b (allgemeine TOM-Klausel).
    """
    text = (
        (finding.get("title") or "") + " " +
        (finding.get("description") or "") + " " +
        (finding.get("recommendation") or "") + " " +
        (finding.get("policy_id") or "") + " " +
        (finding.get("finding_type") or "")
    ).lower()

    for keywords, ref in _KEYWORD_MAPPING:
        if any(kw in text for kw in keywords):
            return ref

    return _DEFAULT


def get_article_title(ref: str) -> str:
    """Get the short title for a DSGVO article reference."""
    return DSGVO_ARTICLES.get(ref, {}).get("title", "")


__all__ = [
    "DSGVO_ARTICLES",
    "map_finding_to_dsgvo",
    "get_article_title",
]

"""BSI-Grundschutz compliance mapping.

Maps scan findings to BSI IT-Grundschutz Kompendium bausteine.
Used as supplementary references in ComplianceScan reports.
"""

from __future__ import annotations

from typing import Any

# BSI-Grundschutz bausteine relevant to external assessments
BSI_BAUSTEINE: dict[str, dict[str, str]] = {
    "APP.3.1": {"title": "Webanwendungen und Webservices", "layer": "APP"},
    "APP.3.2": {"title": "Webserver", "layer": "APP"},
    "NET.1.1": {"title": "Netzarchitektur und -design", "layer": "NET"},
    "NET.3.2": {"title": "Firewall", "layer": "NET"},
    "OPS.1.1.4": {"title": "Schutz vor Schadprogrammen", "layer": "OPS"},
    "OPS.1.1.5": {"title": "Protokollierung", "layer": "OPS"},
    "CON.1": {"title": "Kryptokonzept", "layer": "CON"},
    "CON.3": {"title": "Datensicherungskonzept", "layer": "CON"},
    "SYS.1.1": {"title": "Allgemeiner Server", "layer": "SYS"},
    "SYS.1.6": {"title": "Containerisierung", "layer": "SYS"},
}

_KEYWORD_MAPPING: list[tuple[list[str], str]] = [
    (["ssl", "tls", "cipher", "encryption", "certificate", "kryptogra"], "CON.1"),
    (["web", "http", "html", "webapp", "cms", "wordpress"], "APP.3.1"),
    (["server", "nginx", "apache", "iis"], "APP.3.2"),
    (["firewall", "port", "netzwerk", "network"], "NET.3.2"),
    (["backup", "sicherung", "restore"], "CON.3"),
    (["container", "docker", "kubernetes"], "SYS.1.6"),
    (["malware", "virus", "ransomware"], "OPS.1.1.4"),
    (["log", "protokoll", "audit"], "OPS.1.1.5"),
]


def map_finding_to_bsi(finding: dict[str, Any]) -> str:
    """Map a finding to the most relevant BSI-Grundschutz baustein."""
    text = (finding.get("title", "") + " " + finding.get("description", "")).lower()

    for keywords, baustein in _KEYWORD_MAPPING:
        if any(kw in text for kw in keywords):
            return baustein

    return "SYS.1.1"  # Default: Allgemeiner Server


def get_baustein_title(ref: str) -> str:
    """Get the title for a BSI-Grundschutz baustein."""
    return BSI_BAUSTEINE.get(ref, {}).get("title", ref)

"""Package configuration — defines tool sets and limits per scan package.

VectiScan v2: 6 packages (webcheck, perimeter, compliance, supplychain, insurance, tlscompliance).
Compliance, SupplyChain and Insurance share the perimeter scan config —
they differ only in report generation (prompts, mapper, PDF sections).
TLSCompliance is a dedicated TLS-only audit against BSI TR-03116-4.
"""

from typing import Any

# ---------------------------------------------------------------------------
# Perimeter+ base config (shared by perimeter, compliance, supplychain, insurance)
# ---------------------------------------------------------------------------
_PERIMETER_BASE: dict[str, Any] = {
    "phase0a_tools": ["shodan", "abuseipdb", "securitytrails", "whois"],
    "phase0a_timeout": 120,       # 2 Minuten
    # amass v5 entfernt (2026-05-03): die neue Engine+DB-Architektur ist
    # fuer 1-Shot-Subdomain-Discovery untauglich; enum schreibt 0 Bytes,
    # subs findet "No names". subfinder mit -all -recursive deckt
    # 30+ Sources ab (chaos, alienvault, anubis, bevigil, binaryedge,
    # bufferover, c99, censys, certspotter, crtsh, etc.). Plus wir haben
    # certspotter direkt + securitytrails als zusaetzliche CT-Quellen.
    "phase0b_tools": ["crtsh", "subfinder", "gobuster_dns", "axfr", "dnsx",
                      "dnssec", "caa", "mta_sts", "dane_tlsa"],
    "phase0b_timeout": 900,       # 15 Minuten
    "max_hosts": 15,
    "nmap_ports": "--top-ports 1000",
    "phase1_tools": ["nmap", "webtech", "wafw00f", "cms_fingerprint"],
    "phase2_tools": ["zap_spider", "zap_active",
                     "ffuf", "feroxbuster",
                     "headers", "httpx", "wpscan"],
    "phase3_tools": ["nvd", "epss", "cisa_kev", "exploitdb", "correlator",
                     "fp_filter", "business_impact"],
    "phase3_timeout": 300,        # 5 Minuten
    "total_timeout": 7200,        # 120 Minuten
    "zap_min_risk": "Low",            # Low+ alerts (skip Informational)
}


PACKAGE_CONFIG: dict[str, dict[str, Any]] = {
    # ------------------------------------------------------------------
    # WebCheck — "Ist meine Website sicher?"
    # Schnellscan, wenige Tools, max 3 Hosts, einfacher Report
    # ------------------------------------------------------------------
    "webcheck": {
        "phase0a_tools": ["whois"],
        "phase0a_timeout": 30,        # nur WHOIS
        "phase0b_tools": ["crtsh", "subfinder", "dnsx",
                          "dnssec", "caa", "mta_sts"],
        "phase0b_timeout": 300,       # 5 Minuten
        "max_hosts": 3,
        "nmap_ports": "--top-ports 100",
        "phase1_tools": ["nmap", "webtech", "wafw00f", "cms_fingerprint"],
        "phase2_tools": ["zap_spider", "zap_passive",
                         "headers", "httpx", "wpscan"],
        "phase3_tools": ["nvd", "cisa_kev", "correlator", "fp_filter"],
        "phase3_timeout": 120,        # 2 Minuten
        "total_timeout": 1200,        # 20 Minuten
        "zap_min_risk": "Low",            # Same as perimeter
    },

    # ------------------------------------------------------------------
    # PerimeterScan — "Wie sieht unsere Angriffsfläche aus?"
    # Vollscan, alle Tools, max 15 Hosts, PTES-konformer Report
    # ------------------------------------------------------------------
    "perimeter": {**_PERIMETER_BASE},

    # ------------------------------------------------------------------
    # ComplianceScan — "Erfüllen wir NIS2?"
    # = Perimeter-Scan, Report mit §30 BSIG-Mapping
    # ------------------------------------------------------------------
    "compliance": {**_PERIMETER_BASE},

    # ------------------------------------------------------------------
    # SupplyChain — "Nachweis für NIS2-pflichtigen Auftraggeber"
    # = Perimeter-Scan, Report mit ISO 27001 Mapping
    # ------------------------------------------------------------------
    "supplychain": {**_PERIMETER_BASE},

    # ------------------------------------------------------------------
    # InsuranceReport — "Nachweis für Cyberversicherung"
    # = Perimeter-Scan, Report mit Versicherungs-Fragebogen
    # ------------------------------------------------------------------
    "insurance": {**_PERIMETER_BASE},

    # ------------------------------------------------------------------
    # TLSCompliance — "BSI TR-03116-4 Compliance-Prüfung"
    # Nur testssl + Headers, kein Deep-Scan, schnell (~5–10 Min)
    # ------------------------------------------------------------------
    "tlscompliance": {
        "phase0a_tools": ["whois"],
        "phase0a_timeout": 30,
        "phase0b_tools": ["crtsh", "subfinder", "dnsx", "dnssec", "caa", "mta_sts"],
        "phase0b_timeout": 300,          # 5 Minuten — vollständige Recon wie WebCheck
        "max_hosts": 15,
        "nmap_ports": "443,8443,993,995,465,587,636,989,990,5061",
        "phase1_tools": ["nmap"],        # Nur Port-Scan (webtech/wafw00f über Config gesteuert)
        "phase2_tools": ["testssl", "headers"],
        "phase3_tools": [],              # Kein Enrichment
        "phase3_timeout": 0,
        "total_timeout": 600,            # 10 Minuten
        "testssl_severity": "",          # Leer = kein --severity Filter → ALLE Einträge inkl. OK/INFO
        "zap_min_risk": "Low",
        "skip_ai_decisions": True,       # Kein AI Host Strategy / Tech Analysis / Phase-2 Config
    },
}

# Backwards-compat aliases (v1 package names → v2)
_PACKAGE_ALIASES: dict[str, str] = {
    "basic": "webcheck",
    "professional": "perimeter",
    "nis2": "compliance",
}


def get_config(package: str) -> dict[str, Any]:
    """Return the configuration for a scan package.

    Args:
        package: One of 'webcheck', 'perimeter', 'compliance', 'supplychain',
                 'insurance'. Legacy names 'basic', 'professional', 'nis2'
                 are also accepted for backwards compatibility.

    Returns:
        Configuration dict with tool lists, timeouts, and limits.

    Raises:
        ValueError: If package name is not recognized.
    """
    resolved = _PACKAGE_ALIASES.get(package, package)
    if resolved not in PACKAGE_CONFIG:
        raise ValueError(
            f"Unknown package: {package}. "
            f"Must be one of: {', '.join(PACKAGE_CONFIG.keys())}."
        )
    return PACKAGE_CONFIG[resolved]


def resolve_package(package: str) -> str:
    """Resolve a legacy package name to its v2 equivalent.

    Returns the canonical v2 package name (unchanged if already v2).
    """
    return _PACKAGE_ALIASES.get(package, package)

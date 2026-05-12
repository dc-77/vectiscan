"""Business-Impact-Recompute fuer den Reporter.

Spec: docs/deterministic/02-severity-policy.md §10
     docs/deterministic/04-deterministic-selection.md

Wird AUFGERUFEN nach severity_policy.apply_policy() — die finale Severity,
ggf. ein gecapptes CVSS und policy_id stehen jetzt fest. Wir berechnen den
business_impact_score auf dieser Basis neu.

Differenz zur scan-worker-Version (scan-worker/scanner/correlation/business_impact.py):
- Operiert auf dict-Findings (BullMQ-Payload, JSON-serialisierbar) statt CorrelatedFinding
- Liest Severity aus finding["severity"] (vom Policy gesetzt) statt aus primary.severity
- CVSS-Quelle: finding["cvss_score"] (ggf. von Policy gecappt) > enrichment.nvd > Severity-Approximation
"""

from __future__ import annotations

from typing import Any

import structlog

log = structlog.get_logger()

SEVERITY_CVSS_MAP: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}

PACKAGE_WEIGHTS: dict[str, dict[str, float]] = {
    "insurance": {
        "rdp_smb": 2.0,
        "default_login": 1.8,
        "encryption": 1.3,
    },
    "compliance": {
        "encryption": 1.5,
        "access_control": 1.3,
        "logging": 1.3,
    },
    "supplychain": {
        "api_security": 1.5,
        "authentication": 1.5,
        "data_exposure": 1.3,
    },
    "perimeter": {},
    "webcheck": {},
}

RANSOMWARE_PORTS = {3389, 445, 139, 5900, 5985, 5986, 23, 5800}

# F-RPT-003: deterministische policy_id -> Kategorien-Mapping ersetzt
# Keyword-Match in _classify_finding. Sprachunabhaengig (KI generiert
# deutsche Narratives — englische Keywords matchten nicht).
# Synchron pflegen mit reporter/severity_policy.py SEVERITY_POLICIES.
POLICY_ID_TO_CATEGORIES: dict[str, set[str]] = {
    # Header / Encryption-Hardening
    "SP-HDR-001": {"encryption"}, "SP-HDR-002": {"encryption"},
    "SP-HDR-003": {"encryption"}, "SP-HDR-004": {"encryption"},
    "SP-HDR-005": set(), "SP-HDR-006": {"access_control"},
    "SP-HDR-007": set(), "SP-HDR-008": set(),
    "SP-HDR-009": {"encryption"},
    # CSP
    "SP-CSP-001": {"access_control"}, "SP-CSP-002": {"access_control"},
    "SP-CSP-003": {"access_control"}, "SP-CSP-004": {"access_control"},
    "SP-CSP-005": {"access_control"},
    # Cookies
    "SP-COOK-001": {"encryption"}, "SP-COOK-002": {"access_control"},
    "SP-COOK-003": {"access_control"},
    "SP-COOK-004": {"encryption", "authentication"},
    "SP-COOK-005": {"access_control", "authentication"},
    # CSRF
    "SP-CSRF-001": {"access_control", "authentication"},
    "SP-CSRF-002": {"access_control"}, "SP-CSRF-003": {"access_control"},
    # Disclosure
    "SP-DISC-001": set(), "SP-DISC-002": set(),
    "SP-DISC-003": {"data_exposure"}, "SP-DISC-004": {"data_exposure"},
    "SP-DISC-005": {"data_exposure"}, "SP-DISC-006": {"data_exposure"},
    "SP-DISC-007": {"data_exposure"}, "SP-DISC-008": {"data_exposure"},
    "SP-DISC-009": {"data_exposure"},
    "SP-DISC-010": {"data_exposure"},  # Framework-Dev-Build (react.development.js etc.)
    # TLS
    "SP-TLS-001": {"encryption"}, "SP-TLS-002": {"encryption"},
    "SP-TLS-003": {"encryption"}, "SP-TLS-004": {"encryption"},
    "SP-TLS-005": {"encryption"}, "SP-TLS-006": {"encryption"},
    "SP-TLS-007": {"encryption"},
    # DNS / Mail-Auth
    "SP-DNS-001": {"encryption"}, "SP-DNS-002": {"encryption"},
    "SP-DNS-003": {"encryption"},
    "SP-DNS-004": {"authentication"}, "SP-DNS-005": {"authentication"},
    "SP-DNS-006": {"authentication"}, "SP-DNS-007": {"authentication"},
    "SP-DNS-008": {"authentication", "encryption"},
    "SP-DNS-009": {"authentication"}, "SP-DNS-010": {"authentication"},
    # F-P0A-002 — TLS-RPT, BIMI, DMARC pct<100, NSEC3-Iterations
    "SP-DNS-011": {"encryption", "logging"},
    "SP-DNS-012": set(),  # BIMI = Branding, kein Security-Hebel
    "SP-DNS-013": {"authentication"},
    "SP-DNS-014": {"encryption"},
    # CVE — KEV-Pfade hoechstes Risiko
    "SP-CVE-001": {"encryption", "access_control"},
    "SP-CVE-002": {"access_control"}, "SP-CVE-003": {"access_control"},
    "SP-CVE-004": {"access_control"},
    # EOL — meist Daten-/Encryption-Risiko
    "SP-EOL-001": {"data_exposure", "encryption", "access_control"},
    "SP-EOL-002": {"data_exposure", "access_control"},
    "SP-EOL-003": {"data_exposure", "access_control"},
    "SP-EOL-004": {"access_control"},
    # M2 Track 2d: EOL + Internet-facing + tech_critical
    "SP-EOL-005": {"data_exposure", "encryption", "access_control"},
    # WordPress / User-Enum
    "SP-WP-001": {"access_control"},
    "SP-WP-002": {"data_exposure"},
    "SP-ENUM-001": {"data_exposure"},
    # Database-Port (M2 Track 2d: SP-DB-002 EOL, SP-DB-003 Multi-Host)
    "SP-DB-001": {"data_exposure", "default_login"},
    "SP-DB-002": {"data_exposure", "default_login", "access_control"},
    "SP-DB-003": {"data_exposure", "default_login", "access_control"},
    # Remote-Desktop (M2 Track 2d, SP-RDP-*)
    # Ransomware-Initialvektor #1 — rdp_smb-Kategorie + default_login
    "SP-RDP-001": {"rdp_smb", "default_login", "access_control"},
    "SP-RDP-002": {"rdp_smb", "default_login", "access_control"},
    "SP-RDP-003": {"rdp_smb", "default_login", "access_control"},
    # CORS / JS / SRI / SSH
    "SP-CORS-001": {"access_control", "api_security"},
    "SP-JS-001": {"access_control"},
    "SP-SRI-001": {"access_control"},
    "SP-SSH-001": {"default_login", "access_control"},
    # F-P0A-003 — URLhaus Compromise-Detection (Datenabfluss + Access)
    "SP-URLHAUS-001": {"data_exposure", "access_control"},
    # Fallback-Findings (ohne Policy) bekommen keine Kategorien
    "SP-FALLBACK": set(),
}


def _get_cvss(finding: dict) -> float:
    """Extract CVSS from finding dict, with fallback chain."""
    # 1. Policy-gesetztes oder vom Tool gesetztes cvss_score
    cvss = finding.get("cvss_score")
    if cvss is not None:
        try:
            return float(cvss)
        except (ValueError, TypeError):
            pass

    # 2. NVD-Enrichment
    enrichment = finding.get("enrichment") or {}
    nvd = enrichment.get("nvd") if isinstance(enrichment, dict) else None
    if isinstance(nvd, dict) and nvd.get("cvss_score"):
        try:
            return float(nvd["cvss_score"])
        except (ValueError, TypeError):
            pass

    # 3. Approximation aus Severity
    severity = (finding.get("severity") or "info").lower()
    return SEVERITY_CVSS_MAP.get(severity, 3.0)


def _classify_finding(finding: dict) -> set[str]:
    """Klassifiziert ein Finding fuer Package-Weights.

    F-RPT-003: deterministisches Mapping ueber policy_id (statt Keyword-
    Match in title+description). Sprachunabhaengig. RANSOMWARE_PORTS
    (orthogonal zu policy_id) bleibt als Port-Match-Fallback.
    """
    categories: set[str] = set()
    # Primaer: policy_id (deterministisch, sprachunabhaengig)
    pid = (finding.get("policy_id") or "").strip()
    if pid in POLICY_ID_TO_CATEGORIES:
        categories |= POLICY_ID_TO_CATEGORIES[pid]
    # Sekundaer: Port-basierte rdp_smb-Erkennung (orthogonal)
    port = finding.get("port")
    if port:
        try:
            if int(port) in RANSOMWARE_PORTS:
                categories.add("rdp_smb")
        except (ValueError, TypeError):
            pass
    return categories


def _compute_score(finding: dict, package: str, domain: str) -> float:
    """Compute business-impact score (0–10) for a single finding."""
    base = _get_cvss(finding)

    # ── EPSS Multiplier ─────────────────────────────────
    enrichment = finding.get("enrichment") or {}
    epss = enrichment.get("epss") if isinstance(enrichment, dict) else {}
    epss_score = epss.get("epss") if isinstance(epss, dict) else 0.0
    if epss_score is None:
        epss_score = 0.0
    if epss_score > 0.5:
        base *= 1.3
    elif epss_score > 0.2:
        base *= 1.1

    # ── CISA KEV Multiplier ─────────────────────────────
    kev = enrichment.get("cisa_kev") if isinstance(enrichment, dict) else None
    if kev:
        base *= 1.5
        if isinstance(kev, dict) and \
                str(kev.get("known_ransomware", "")).lower() == "known":
            base *= 1.2

    # ── Asset Value Multiplier ──────────────────────────
    fqdn = (finding.get("fqdn") or "").lower()
    if not fqdn:
        # Fallback: aus affected/host
        affected = (finding.get("affected") or finding.get("host") or "").lower()
        fqdn = affected
    if domain:
        domain_lower = domain.lower()
        if fqdn == domain_lower or fqdn == f"www.{domain_lower}":
            base *= 1.2
        elif fqdn.startswith(("mail.", "mx.", "smtp.")):
            base *= 1.1

    # ── Package-specific Weighting ──────────────────────
    categories = _classify_finding(finding)
    weights = PACKAGE_WEIGHTS.get((package or "").lower(), {})
    max_weight = 1.0
    for cat in categories:
        weight = weights.get(cat, 1.0)
        max_weight = max(max_weight, weight)
    base *= max_weight

    # ── Confidence Adjustment ───────────────────────────
    confidence = finding.get("confidence")
    try:
        confidence = float(confidence) if confidence is not None else 1.0
    except (ValueError, TypeError):
        confidence = 1.0
    if confidence < 0.5:
        base *= 0.7

    return min(round(base, 1), 10.0)


def recompute(findings: list[dict],
              package: str = "perimeter",
              domain: str = "") -> list[dict]:
    """Recompute business_impact_score IN-PLACE auf der finalen Severity.

    Aufruf nach severity_policy.apply_policy(). False-Positives ueberspringen
    wir hier nicht — die werden erst in selection.py rausgefiltert.
    """
    for f in findings:
        if f.get("is_false_positive"):
            f.setdefault("business_impact_score", 0.0)
            continue
        f["business_impact_score"] = _compute_score(f, package, domain)
    return findings


def order_score(findings: list[dict]) -> float:
    """Aggregat-Score fuer die ganze Order: gewichteter Mittel der Top-5."""
    scores = [
        float(f.get("business_impact_score") or 0.0)
        for f in findings if not f.get("is_false_positive")
    ]
    if not scores:
        return 0.0
    scores.sort(reverse=True)
    top = scores[:5]
    weights = [1.0, 0.8, 0.6, 0.4, 0.2]
    weighted_sum = sum(s * w for s, w in zip(top, weights))
    weight_total = sum(weights[:len(top)])
    return round(weighted_sum / weight_total, 1)


__all__ = [
    "SEVERITY_CVSS_MAP",
    "PACKAGE_WEIGHTS",
    "RANSOMWARE_PORTS",
    "POLICY_ID_TO_CATEGORIES",
    "recompute",
    "order_score",
]

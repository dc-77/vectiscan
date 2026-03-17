"""Business-Impact-Scoring — translates technical findings into business risk.

Combines CVSS, EPSS, CISA KEV, asset value, and package-specific weights
into a single 0–10 business impact score.
"""

from __future__ import annotations

from typing import Any

import structlog

from scanner.correlation.correlator import CorrelatedFinding

log = structlog.get_logger()

# Severity → base CVSS approximation (when no exact CVSS available)
SEVERITY_CVSS_MAP: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}

# Package-specific multipliers for certain finding types
PACKAGE_WEIGHTS: dict[str, dict[str, float]] = {
    "insurance": {
        "rdp_smb": 2.0,       # RDP/SMB open → Ransomware vector
        "default_login": 1.8,  # Default credentials → high risk
        "encryption": 1.3,    # Weak encryption
    },
    "compliance": {
        "encryption": 1.5,    # §30 BSIG Nr. 4: Verschlüsselung
        "access_control": 1.3, # §30 BSIG Nr. 1: Zugriffskontrolle
        "logging": 1.3,       # §30 BSIG Nr. 5: Logging
    },
    "supplychain": {
        "api_security": 1.5,  # Supply chain API interfaces
        "authentication": 1.5, # Authentication weaknesses
        "data_exposure": 1.3, # Data leakage
    },
    "perimeter": {},
    "webcheck": {},
}

# Ports that indicate ransomware attack vectors
RANSOMWARE_PORTS = {3389, 445, 139, 5900, 5985, 5986}


def _get_cvss_from_finding(finding: CorrelatedFinding) -> float:
    """Extract or approximate CVSS score from a finding."""
    # Try NVD enrichment first (authoritative)
    nvd = finding.enrichment.get("nvd", {})
    if nvd and nvd.get("cvss_score"):
        return float(nvd["cvss_score"])

    # Try nuclei CVSS
    if finding.primary.raw:
        cvss = finding.primary.raw.get("info", {}).get("classification", {}).get("cvss-score")
        if cvss:
            try:
                return float(cvss)
            except (ValueError, TypeError):
                pass

    # Fall back to severity-based approximation
    return SEVERITY_CVSS_MAP.get(finding.primary.severity, 3.0)


def _classify_finding(finding: CorrelatedFinding) -> set[str]:
    """Classify a finding into categories for package-specific weighting."""
    categories: set[str] = set()
    title = finding.primary.title.lower()
    desc = finding.primary.description.lower()
    combined = f"{title} {desc}"
    port = finding.primary.port

    # RDP/SMB detection
    if port and port in RANSOMWARE_PORTS:
        categories.add("rdp_smb")
    if any(term in combined for term in ("rdp", "smb", "remote desktop", "samba")):
        categories.add("rdp_smb")

    # Encryption
    if any(term in combined for term in ("ssl", "tls", "cipher", "encryption",
                                          "hsts", "certificate")):
        categories.add("encryption")

    # Default login
    if any(term in combined for term in ("default", "login", "credential",
                                          "password", "admin")):
        categories.add("default_login")

    # Access control
    if any(term in combined for term in ("access", "authorization", "permission",
                                          "privilege", "bypass")):
        categories.add("access_control")

    # API security
    if any(term in combined for term in ("api", "graphql", "swagger", "endpoint",
                                          "rest", "oauth")):
        categories.add("api_security")

    # Authentication
    if any(term in combined for term in ("authentication", "auth", "session",
                                          "token", "jwt")):
        categories.add("authentication")

    # Data exposure
    if any(term in combined for term in ("exposure", "disclosure", "leak",
                                          "sensitive", "backup", "database")):
        categories.add("data_exposure")

    # Logging
    if any(term in combined for term in ("logging", "audit", "trace")):
        categories.add("logging")

    return categories


def calculate_business_impact(
    finding: CorrelatedFinding,
    package: str = "perimeter",
    domain: str = "",
) -> float:
    """Calculate business impact score (0.0–10.0) for a single finding.

    Factors:
    1. CVSS Base Score (technical severity)
    2. EPSS Score (exploit probability)
    3. CISA KEV (actively exploited?)
    4. Asset value (base domain > subdomain > mail)
    5. Package-specific weighting
    """
    base = _get_cvss_from_finding(finding)

    # ── EPSS Multiplier ──────────────────────────────────
    epss = finding.enrichment.get("epss", {})
    epss_score = epss.get("epss", 0.0) if isinstance(epss, dict) else 0.0
    if epss_score > 0.5:
        base *= 1.3  # High exploit probability
    elif epss_score > 0.2:
        base *= 1.1

    # ── CISA KEV Multiplier ──────────────────────────────
    kev = finding.enrichment.get("cisa_kev")
    if kev:
        base *= 1.5  # Actively exploited → critical
        # Ransomware campaigns are even worse
        if isinstance(kev, dict) and kev.get("known_ransomware", "").lower() == "known":
            base *= 1.2

    # ── Asset Value Multiplier ───────────────────────────
    fqdn = finding.primary.fqdn.lower()
    if domain:
        domain_lower = domain.lower()
        if fqdn == domain_lower or fqdn == f"www.{domain_lower}":
            base *= 1.2  # Base domain = most important
        elif fqdn.startswith("mail.") or fqdn.startswith("mx.") or \
             fqdn.startswith("smtp."):
            base *= 1.1  # Mail server
        # Subdomains keep base multiplier (1.0)

    # ── Package-specific Weighting ───────────────────────
    categories = _classify_finding(finding)
    weights = PACKAGE_WEIGHTS.get(package, {})
    max_weight = 1.0
    for cat in categories:
        weight = weights.get(cat, 1.0)
        max_weight = max(max_weight, weight)
    base *= max_weight

    # ── Confidence Adjustment ────────────────────────────
    # Low-confidence findings should not have high impact
    if finding.confidence < 0.5:
        base *= 0.7

    return min(round(base, 1), 10.0)


def calculate_order_impact(
    findings: list[CorrelatedFinding],
    package: str = "perimeter",
    domain: str = "",
) -> float:
    """Calculate overall business impact score for the entire scan order.

    Uses the top-5 findings (weighted average) as the order-level score.
    """
    if not findings:
        return 0.0

    # Calculate individual scores
    scores: list[float] = []
    for f in findings:
        if f.is_false_positive:
            continue
        score = calculate_business_impact(f, package, domain)
        scores.append(score)

    if not scores:
        return 0.0

    # Weighted average of top 5 findings
    scores.sort(reverse=True)
    top = scores[:5]

    # Weight: first finding counts most, declining weights
    weights = [1.0, 0.8, 0.6, 0.4, 0.2]
    weighted_sum = sum(s * w for s, w in zip(top, weights))
    weight_total = sum(weights[:len(top)])

    order_score = weighted_sum / weight_total
    log.info("business_impact_calculated", order_score=round(order_score, 1),
             total_findings=len(scores), top_5=top)
    return round(order_score, 1)

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

RANSOMWARE_PORTS = {3389, 445, 139, 5900, 5985, 5986}


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
    """Klassifiziert ein Finding fuer Package-Weights."""
    categories: set[str] = set()
    title = (finding.get("title") or "").lower()
    desc = (finding.get("description") or "").lower()
    combined = f"{title} {desc}"
    port = finding.get("port")

    if port:
        try:
            if int(port) in RANSOMWARE_PORTS:
                categories.add("rdp_smb")
        except (ValueError, TypeError):
            pass
    if any(t in combined for t in ("rdp", "smb", "remote desktop", "samba")):
        categories.add("rdp_smb")

    if any(t in combined for t in ("ssl", "tls", "cipher", "encryption",
                                   "hsts", "certificate")):
        categories.add("encryption")

    if any(t in combined for t in ("default", "credential", "password", "admin login")):
        categories.add("default_login")

    if any(t in combined for t in ("access", "authorization", "permission",
                                   "privilege", "bypass")):
        categories.add("access_control")

    if any(t in combined for t in ("api", "graphql", "swagger", "endpoint",
                                   "rest", "oauth")):
        categories.add("api_security")

    if any(t in combined for t in ("authentication", "auth ", "session",
                                   "token", "jwt")):
        categories.add("authentication")

    if any(t in combined for t in ("exposure", "disclosure", "leak",
                                   "sensitive", "backup", "database")):
        categories.add("data_exposure")

    if any(t in combined for t in ("logging", "audit", "trace")):
        categories.add("logging")

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
    "recompute",
    "order_score",
]

"""ZAP Alert → VectiScan Finding mapper.

Converts ZAP alert objects from the REST API into normalized Finding dicts
that can be fed into the Phase 3 correlation pipeline.
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse

import structlog

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# ZAP Risk → VectiScan severity
# ---------------------------------------------------------------------------

_RISK_TO_SEVERITY: dict[str, str] = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}

# ---------------------------------------------------------------------------
# ZAP Confidence → multiplier (for base_confidence calculation)
# ---------------------------------------------------------------------------

_CONFIDENCE_MULTIPLIER: dict[str, float] = {
    "Confirmed": 1.0,
    "High": 0.9,
    "Medium": 0.7,
    "Low": 0.4,
    "False Positive": 0.0,
}

# ---------------------------------------------------------------------------
# Default CVSS 3.1 scores per severity (overridden by NVD in Phase 3)
# ---------------------------------------------------------------------------

_SEVERITY_CVSS: dict[str, tuple[float, str]] = {
    "high": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "medium": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "low": (3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "info": (0.0, ""),
}

# ---------------------------------------------------------------------------
# CWE mapping table — top ZAP alerts
# ZAP provides cweid in the alert, but this table serves as validation/fallback.
# ---------------------------------------------------------------------------

_PLUGIN_CWE: dict[int, int] = {
    # Passive scanner alerts
    10010: 1004,   # Cookie No HttpOnly Flag
    10011: 614,    # Cookie Without Secure Flag
    10015: 525,    # Incomplete Cache-control Header
    10017: 200,    # Cross-Domain JavaScript Source Inclusion
    10020: 1021,   # X-Frame-Options Header Not Set
    10021: 693,    # X-Content-Type-Options Missing
    10023: 200,    # Information Disclosure — Debug Errors
    10024: 200,    # Information Disclosure — Sensitive Info in URL
    10025: 200,    # Information Disclosure — Sensitive Info in Response
    10027: 200,    # Information Disclosure — Suspicious Comments
    10035: 319,    # Strict-Transport-Security Missing
    10036: 200,    # Server Leaks Version Information
    10037: 200,    # Server Leaks Information via X-Powered-By
    10038: 693,    # Content-Security-Policy Not Set
    10040: 523,    # Secure Pages Include Mixed Content
    10049: 200,    # Storable and Cacheable Content
    10055: 693,    # CSP Wildcard Directive
    10063: 693,    # Permissions-Policy Not Set
    10096: 200,    # Timestamp Disclosure
    10098: 264,    # Cross-Domain Misconfiguration
    10202: 352,    # Absence of Anti-CSRF Tokens
    # Active scanner alerts
    6: 22,         # Path Traversal
    7: 98,         # Remote File Inclusion
    40003: 113,    # CRLF Injection
    40009: 918,    # Server Side Request Forgery
    40012: 79,     # Cross Site Scripting (Reflected)
    40014: 79,     # Cross Site Scripting (Persistent)
    40016: 79,     # Cross Site Scripting (DOM-based)
    40017: 79,     # Cross Site Scripting (jQuery)
    40018: 89,     # SQL Injection
    40019: 89,     # SQL Injection — MySQL
    40020: 89,     # SQL Injection — Hypersonic
    40021: 89,     # SQL Injection — Oracle
    40022: 89,     # SQL Injection — PostgreSQL
    40024: 89,     # SQL Injection — SQLite
    40034: 215,    # .htaccess Information Leak
    40042: 215,    # Spring Actuator Exposure
    40043: 117,    # Log4Shell
    40046: 918,    # Server Side Request Forgery (SSRF)
    90019: 97,     # Server Side Include
    90020: 78,     # Remote OS Command Injection
    90023: 611,    # XML External Entity
    90024: 209,    # Generic Padding Oracle
    90025: 94,     # Expression Language Injection
    10054: 113,    # Cookie without SameSite
}

# Passive scanner plugin ID ranges
_PASSIVE_RANGES = [(10000, 19999), (90000, 99999)]
# Active scanner plugin ID ranges
_ACTIVE_RANGES = [(0, 9999), (20000, 49999)]


def _is_passive(plugin_id: int) -> bool:
    """Check if a plugin ID belongs to the passive scanner."""
    return any(lo <= plugin_id <= hi for lo, hi in _PASSIVE_RANGES)


class ZapAlertMapper:
    """Maps ZAP alerts to VectiScan Finding dicts.

    Produces dicts with the same fields as the Finding dataclass in
    scanner.correlation.correlator — so they can be deserialized directly
    by extract_findings() in Phase 3.
    """

    def map_alerts(
        self,
        alerts: list[dict[str, Any]],
        host_ip: str,
        fqdn: str,
    ) -> list[dict[str, Any]]:
        """Convert ZAP alerts to Finding-compatible dicts.

        Filters out False Positive confidence, deduplicates, and classifies
        each alert as zap_passive or zap_active.
        """
        # Step 1: Filter out False Positive confidence + low-value noise
        # Skip Informational by default (configurable via min_risk param)
        filtered = [a for a in alerts
                     if a.get("confidence", "") != "False Positive"
                     and a.get("risk", "") not in ("Informational",)]

        # Step 2: Deduplicate
        deduped = self._dedup_alerts(filtered)

        # Step 3: Map to Finding dicts
        findings: list[dict[str, Any]] = []
        for alert in deduped:
            finding = self._map_single(alert, host_ip, fqdn)
            if finding:
                findings.append(finding)

        log.info("zap_mapper_complete",
                 input_alerts=len(alerts),
                 after_fp_filter=len(filtered),
                 after_dedup=len(deduped),
                 findings=len(findings))
        return findings

    def _map_single(
        self,
        alert: dict[str, Any],
        host_ip: str,
        fqdn: str,
    ) -> dict[str, Any] | None:
        """Map a single ZAP alert to a Finding-compatible dict."""
        tool = self._classify_source(alert)
        severity = self._map_severity(alert.get("risk", "Informational"))
        cwe_id = self._resolve_cwe(alert)

        # Build CVE-ID if available (ZAP rarely provides CVE, but some plugins do)
        cve_id: Optional[str] = None
        reference = alert.get("reference", "")
        if "CVE-" in reference:
            import re
            cve_match = re.search(r"(CVE-\d{4}-\d+)", reference)
            if cve_match:
                cve_id = cve_match.group(1)

        # Extract port from URL
        port: Optional[int] = None
        url = alert.get("url", "")
        if url:
            parsed = urlparse(url)
            if parsed.port:
                port = parsed.port
            elif parsed.scheme == "https":
                port = 443
            elif parsed.scheme == "http":
                port = 80

        # CVSS defaults
        cvss_score, cvss_vector = _SEVERITY_CVSS.get(severity, (0.0, ""))

        return {
            "tool": tool,
            "host_ip": host_ip,
            "fqdn": fqdn,
            "cve_id": cve_id,
            "title": alert.get("name", alert.get("alert", "")),
            "severity": severity,
            "description": alert.get("description", "")[:500],
            "evidence": alert.get("evidence", "") or alert.get("url", ""),
            "port": port,
            "service": "http" if port in (80, 8080, 8888) else "https" if port in (443, 8443) else "",
            "technology": "",
            "raw": {
                "pluginId": alert.get("pluginId", ""),
                "alertRef": alert.get("alertRef", ""),
                "cweid": cwe_id,
                "wascid": alert.get("wascid", ""),
                "confidence": alert.get("confidence", ""),
                "url": url,
                "param": alert.get("param", ""),
                "method": alert.get("method", ""),
                "solution": alert.get("solution", "")[:300],
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
            },
        }

    def _classify_source(self, alert: dict[str, Any]) -> str:
        """Determine if alert is from passive or active scanner."""
        try:
            plugin_id = int(alert.get("pluginId", 0))
        except (ValueError, TypeError):
            plugin_id = 0

        if _is_passive(plugin_id):
            return "zap_passive"
        return "zap_active"

    def _map_severity(self, zap_risk: str) -> str:
        """Map ZAP risk level to VectiScan severity."""
        return _RISK_TO_SEVERITY.get(zap_risk, "info")

    def _resolve_cwe(self, alert: dict[str, Any]) -> int | None:
        """Get CWE-ID from alert, with fallback to our mapping table."""
        # ZAP provides cweid directly
        try:
            cwe = int(alert.get("cweid", 0))
            if cwe > 0:
                return cwe
        except (ValueError, TypeError):
            pass

        # Fallback: our mapping table
        try:
            plugin_id = int(alert.get("pluginId", 0))
            return _PLUGIN_CWE.get(plugin_id)
        except (ValueError, TypeError):
            return None

    def _dedup_alerts(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Remove duplicate alerts: same alertRef + same URL path → keep highest confidence."""
        seen: dict[str, dict[str, Any]] = {}

        for alert in alerts:
            alert_ref = alert.get("alertRef", alert.get("pluginId", ""))
            url = alert.get("url", "")
            # Normalize URL path (ignore query string for dedup)
            path = urlparse(url).path if url else ""
            key = f"{alert_ref}:{path}"

            if key in seen:
                # Keep the one with higher confidence
                existing_conf = _CONFIDENCE_MULTIPLIER.get(
                    seen[key].get("confidence", ""), 0.0)
                new_conf = _CONFIDENCE_MULTIPLIER.get(
                    alert.get("confidence", ""), 0.0)
                if new_conf > existing_conf:
                    seen[key] = alert
            else:
                seen[key] = alert

        return list(seen.values())

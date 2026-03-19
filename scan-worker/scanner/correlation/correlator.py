"""Cross-Tool-Correlator — correlates findings across tool boundaries.

Deduplicates, clusters, and assigns confidence scores to findings from
multiple Phase 2 tools. Key differentiator of VectiScan v2.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

import structlog

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Base confidence per tool
# ---------------------------------------------------------------------------

TOOL_BASE_CONFIDENCE: dict[str, float] = {
    "nuclei": 0.85,
    "nmap": 0.80,
    "testssl": 0.90,
    "nikto": 0.40,
    "wpscan": 0.85,
    "ffuf": 0.60,
    "feroxbuster": 0.60,
    "gobuster_dir": 0.60,
    "header_check": 0.95,
    "dalfox": 0.75,
    "httpx": 0.70,
    "katana": 0.50,
    "zap_passive": 0.85,
    "zap_active": 0.75,
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single finding from a scan tool."""
    tool: str
    host_ip: str
    fqdn: str = ""
    cve_id: Optional[str] = None
    title: str = ""
    severity: str = "info"
    description: str = ""
    evidence: str = ""
    port: Optional[int] = None
    service: str = ""
    technology: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def base_confidence(self) -> float:
        return TOOL_BASE_CONFIDENCE.get(self.tool, 0.50)


@dataclass
class CorrelatedFinding:
    """A finding after cross-tool correlation."""
    primary: Finding
    corroborating: list[Finding] = field(default_factory=list)
    confidence: float = 0.0
    correlation_type: str = ""  # cve_match, port_service, tech_version, header, cms
    cluster_id: Optional[str] = None
    enrichment: dict[str, Any] = field(default_factory=dict)
    is_false_positive: bool = False
    fp_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.primary.cve_id,
            "title": self.primary.title,
            "severity": self.primary.severity,
            "confidence": round(self.confidence, 2),
            "source_tool": self.primary.tool,
            "corroborating_tools": [f.tool for f in self.corroborating],
            "correlation_type": self.correlation_type,
            "cluster_id": self.cluster_id,
            "host_ip": self.primary.host_ip,
            "fqdn": self.primary.fqdn,
            "port": self.primary.port,
            "description": self.primary.description[:500],
            "evidence": self.primary.evidence[:500],
            "enrichment": self.enrichment,
            "is_false_positive": self.is_false_positive,
            "fp_reason": self.fp_reason,
        }


# ---------------------------------------------------------------------------
# Finding extraction from Phase 2 results
# ---------------------------------------------------------------------------

def extract_findings(phase2_results: list[dict[str, Any]]) -> list[Finding]:
    """Extract normalized findings from all Phase 2 host results."""
    findings: list[Finding] = []

    for host_result in phase2_results:
        ip = host_result.get("ip", "")
        fqdn = host_result.get("fqdn", "")

        # nuclei findings
        for nf in host_result.get("nuclei", []) or []:
            cve_id = None
            # Extract CVE from nuclei classification
            classification = nf.get("info", {}).get("classification", {})
            cve_ids = classification.get("cve-id") or []
            if cve_ids:
                cve_id = cve_ids[0] if isinstance(cve_ids, list) else str(cve_ids)

            findings.append(Finding(
                tool="nuclei",
                host_ip=ip,
                fqdn=fqdn,
                cve_id=cve_id,
                title=nf.get("info", {}).get("name", ""),
                severity=nf.get("info", {}).get("severity", "info"),
                description=nf.get("info", {}).get("description", ""),
                evidence=nf.get("matched-at", ""),
                technology=", ".join(nf.get("info", {}).get("tags", [])[:5]),
                raw=nf,
            ))

        # nikto findings
        nikto = host_result.get("nikto")
        if isinstance(nikto, dict):
            for vuln in nikto.get("vulnerabilities", []):
                osvdb = vuln.get("OSVDB", "")
                findings.append(Finding(
                    tool="nikto",
                    host_ip=ip,
                    fqdn=fqdn,
                    title=vuln.get("msg", ""),
                    severity="medium" if osvdb else "info",
                    evidence=vuln.get("url", ""),
                    raw=vuln,
                ))

        # testssl findings
        testssl = host_result.get("testssl")
        if isinstance(testssl, list):
            for entry in testssl:
                sev = entry.get("severity", "INFO").lower()
                if sev in ("ok", "info"):
                    sev = "info"
                elif sev in ("low",):
                    sev = "low"
                elif sev in ("medium",):
                    sev = "medium"
                elif sev in ("high", "critical"):
                    sev = "high"

                # Extract CVE from testssl if present
                cve_id = None
                finding_str = entry.get("finding", "")
                cve_match = re.search(r"(CVE-\d{4}-\d+)", finding_str)
                if cve_match:
                    cve_id = cve_match.group(1)

                findings.append(Finding(
                    tool="testssl",
                    host_ip=ip,
                    fqdn=fqdn,
                    cve_id=cve_id,
                    title=entry.get("id", ""),
                    severity=sev,
                    description=finding_str,
                    port=443,
                    service="ssl/tls",
                    raw=entry,
                ))

        # header_check findings
        headers = host_result.get("headers")
        if isinstance(headers, dict):
            sec_headers = headers.get("security_headers", {})
            for header_name, info in sec_headers.items():
                if not info.get("present", True):
                    findings.append(Finding(
                        tool="header_check",
                        host_ip=ip,
                        fqdn=fqdn,
                        title=f"Missing security header: {header_name}",
                        severity="low",
                        description=f"The HTTP security header '{header_name}' is not set.",
                        raw={"header": header_name, **info},
                    ))

        # wpscan findings
        wpscan = host_result.get("wpscan")
        if isinstance(wpscan, dict):
            for finding_entry in wpscan.get("interesting_findings", []):
                cve_refs = finding_entry.get("references", {}).get("cve", [])
                cve_id = f"CVE-{cve_refs[0]}" if cve_refs else None
                findings.append(Finding(
                    tool="wpscan",
                    host_ip=ip,
                    fqdn=fqdn,
                    cve_id=cve_id,
                    title=finding_entry.get("to_s", ""),
                    severity="medium",
                    technology="wordpress",
                    raw=finding_entry,
                ))

        # dalfox findings
        for df in host_result.get("dalfox", []) or []:
            findings.append(Finding(
                tool="dalfox",
                host_ip=ip,
                fqdn=fqdn,
                title=f"XSS: {df.get('type', 'reflected')}",
                severity="high",
                description=df.get("message", ""),
                evidence=df.get("proof_of_concept", df.get("url", "")),
                raw=df,
            ))

        # ZAP findings (pre-mapped to Finding dicts by zap_mapper in phase2)
        for zf in host_result.get("zap_findings", []) or []:
            findings.append(Finding(
                tool=zf.get("tool", "zap_active"),
                host_ip=ip,
                fqdn=fqdn,
                cve_id=zf.get("cve_id"),
                title=zf.get("title", ""),
                severity=zf.get("severity", "info"),
                description=zf.get("description", ""),
                evidence=zf.get("evidence", ""),
                port=zf.get("port"),
                service=zf.get("service", ""),
                technology=zf.get("technology", ""),
                raw=zf.get("raw", {}),
            ))

    log.info("findings_extracted", total=len(findings),
             by_tool={t: sum(1 for f in findings if f.tool == t)
                      for t in set(f.tool for f in findings)})
    return findings


# ---------------------------------------------------------------------------
# CrossToolCorrelator
# ---------------------------------------------------------------------------

class CrossToolCorrelator:
    """Correlates findings across tool boundaries.

    Correlation rules:
    1. CVE-Match: Same CVE-ID from different tools → merge, confidence++
    2. Port-Service-Match: nmap finds service X, nuclei finds CVE for X → correlated
    3. Tech-Version-Match: webtech detects nginx 1.18, nuclei finds nginx CVE → correlated
    4. Header-Correlation: missing HSTS + weak TLS → group as "Transport Security" cluster
    5. CMS-Correlation: wpscan + nuclei find same plugin vulnerability → merge
    """

    def __init__(self, tech_profiles: list[dict[str, Any]] | None = None,
                 has_waf: bool = False,
                 shodan_services: dict[str, dict[str, str]] | None = None):
        self.tech_profiles = tech_profiles or []
        self.has_waf = has_waf
        self.shodan_services = shodan_services or {}

    def correlate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        """Run all correlation steps and return correlated findings."""
        if not findings:
            return []

        # Step 1: CVE-based dedup and merge
        correlated = self._correlate_by_cve(findings)

        # Step 2: Non-CVE findings get their own CorrelatedFinding
        cve_finding_ids = set()
        for cf in correlated:
            cve_finding_ids.add(id(cf.primary))
            for f in cf.corroborating:
                cve_finding_ids.add(id(f))

        for f in findings:
            if id(f) not in cve_finding_ids:
                cf = CorrelatedFinding(
                    primary=f,
                    confidence=f.base_confidence,
                )
                correlated.append(cf)

        # Step 3: Apply correlation boosts
        self._apply_tech_version_boost(correlated)
        self._apply_shodan_boost(correlated)

        # Step 4: Cluster related findings
        self._build_clusters(correlated)

        # Step 5: Apply WAF degrade
        if self.has_waf:
            self._apply_waf_degrade(correlated)

        # Step 6: Clamp confidence to [0, 0.99]
        for cf in correlated:
            cf.confidence = max(0.0, min(cf.confidence, 0.99))

        log.info("correlation_complete", input=len(findings),
                 output=len(correlated),
                 high_conf=sum(1 for c in correlated if c.confidence >= 0.8),
                 low_conf=sum(1 for c in correlated if c.confidence < 0.5))

        return correlated

    def _correlate_by_cve(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        """Merge findings with the same CVE-ID from different tools."""
        cve_groups: dict[str, list[Finding]] = {}
        for f in findings:
            if f.cve_id:
                cve_groups.setdefault(f.cve_id, []).append(f)

        correlated: list[CorrelatedFinding] = []
        for cve_id, group in cve_groups.items():
            if len(group) == 1:
                correlated.append(CorrelatedFinding(
                    primary=group[0],
                    confidence=group[0].base_confidence,
                    correlation_type="single_tool",
                ))
                continue

            # Multiple tools found the same CVE — merge
            # Pick the tool with the highest base confidence as primary
            group.sort(key=lambda f: -f.base_confidence)
            primary = group[0]
            corroborating = group[1:]

            # Confidence boost: +0.10 per additional confirming tool
            unique_tools = {f.tool for f in group}
            boost = 0.10 * (len(unique_tools) - 1)
            confidence = primary.base_confidence + boost

            correlated.append(CorrelatedFinding(
                primary=primary,
                corroborating=corroborating,
                confidence=confidence,
                correlation_type="cve_match",
            ))

        return correlated

    def _apply_tech_version_boost(self, correlated: list[CorrelatedFinding]) -> None:
        """Boost confidence if tech version from webtech/httpx matches the finding."""
        # Build tech version map from profiles
        tech_versions: dict[str, list[str]] = {}  # ip → [tech strings]
        for profile in self.tech_profiles:
            ip = profile.get("ip", "")
            techs = []
            if profile.get("server"):
                techs.append(profile["server"].lower())
            if profile.get("cms"):
                techs.append(profile["cms"].lower())
            tech_versions[ip] = techs

        for cf in correlated:
            ip = cf.primary.host_ip
            if ip not in tech_versions:
                continue

            techs = tech_versions[ip]
            # Check if finding's technology matches detected tech
            finding_tech = cf.primary.technology.lower()
            if finding_tech and any(t in finding_tech or finding_tech in t for t in techs):
                cf.confidence += 0.05
                cf.correlation_type = cf.correlation_type or "tech_version"

    def _apply_shodan_boost(self, correlated: list[CorrelatedFinding]) -> None:
        """Boost confidence if Shodan service version matches the finding."""
        if not self.shodan_services:
            return

        for cf in correlated:
            ip = cf.primary.host_ip
            if ip not in self.shodan_services:
                continue

            services = self.shodan_services[ip]
            # Check if finding's port/service matches Shodan data
            port = cf.primary.port
            if port and str(port) in services:
                cf.confidence += 0.10

    def _apply_waf_degrade(self, correlated: list[CorrelatedFinding]) -> None:
        """Degrade confidence for findings behind WAF when single-tool only."""
        for cf in correlated:
            if not cf.corroborating and cf.primary.tool in ("nikto",):
                cf.confidence -= 0.10

            # General WAF penalty for all single-tool findings
            if not cf.corroborating:
                cf.confidence -= 0.10

    def _build_clusters(self, correlated: list[CorrelatedFinding]) -> None:
        """Group related findings into clusters."""
        for cf in correlated:
            # SSL/TLS cluster
            if cf.primary.service in ("ssl/tls", "ssl", "https") or \
               cf.primary.tool == "testssl" or \
               "ssl" in cf.primary.title.lower() or "tls" in cf.primary.title.lower():
                cf.cluster_id = f"transport_security_{cf.primary.host_ip}"

            # Header cluster
            elif cf.primary.tool == "header_check" or \
                 "header" in cf.primary.title.lower():
                cf.cluster_id = f"security_headers_{cf.primary.host_ip}"

            # XSS cluster
            elif cf.primary.tool == "dalfox" or \
                 "xss" in cf.primary.title.lower():
                cf.cluster_id = f"xss_{cf.primary.host_ip}"

            # CMS cluster
            elif cf.primary.tool == "wpscan" or \
                 cf.primary.technology and any(cms in cf.primary.technology.lower()
                    for cms in ("wordpress", "shopware", "typo3", "joomla", "drupal")):
                cf.cluster_id = f"cms_{cf.primary.host_ip}"

            # Discovery cluster (gobuster, ffuf, feroxbuster)
            elif cf.primary.tool in ("gobuster_dir", "ffuf", "feroxbuster"):
                cf.cluster_id = f"discovery_{cf.primary.host_ip}"

            # ZAP web vulnerability clusters
            elif cf.primary.tool in ("zap_active", "zap_passive"):
                title_lower = cf.primary.title.lower()
                if "xss" in title_lower or "cross site scripting" in title_lower:
                    cf.cluster_id = f"xss_{cf.primary.host_ip}"
                elif "sql" in title_lower:
                    cf.cluster_id = f"sqli_{cf.primary.host_ip}"
                elif "header" in title_lower or "csp" in title_lower or "hsts" in title_lower:
                    cf.cluster_id = f"security_headers_{cf.primary.host_ip}"
                else:
                    cf.cluster_id = f"web_vulns_{cf.primary.host_ip}"

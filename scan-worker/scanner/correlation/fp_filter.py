"""False-Positive Filter — systematic FP reduction for correlated findings.

Six rules to eliminate noise and false positives from scan results:
1. WAF-Filter
2. Version-Mismatch
3. CMS-Mismatch
4. SSL-Dedup
5. Header-Dedup
6. Info-Noise
"""

from __future__ import annotations

import re
from typing import Any

import structlog

from scanner.correlation.correlator import CorrelatedFinding

log = structlog.get_logger()


class FalsePositiveFilter:
    """Filters and marks false positives in correlated findings."""

    def __init__(
        self,
        tech_profiles: list[dict[str, Any]] | None = None,
        has_waf: bool = False,
        detected_cms: str | None = None,
    ):
        self.tech_profiles = tech_profiles or []
        self.has_waf = has_waf
        self.detected_cms = (detected_cms or "").lower()

        # Build version map: ip → {product: version}
        self._version_map: dict[str, dict[str, str]] = {}
        for profile in self.tech_profiles:
            ip = profile.get("ip", "")
            versions: dict[str, str] = {}
            server = profile.get("server", "")
            if server and "/" in server:
                parts = server.split("/", 1)
                versions[parts[0].lower()] = parts[1]
            elif server:
                versions[server.lower()] = ""
            self._version_map[ip] = versions

    def filter(self, findings: list[CorrelatedFinding]) -> list[CorrelatedFinding]:
        """Apply all FP rules. Marks findings as FP but does not remove them.

        Returns the same list with is_false_positive and fp_reason set where applicable.
        """
        stats = {"waf": 0, "version": 0, "cms": 0, "ssl_dedup": 0,
                 "header_dedup": 0, "info_noise": 0}

        findings = self._filter_waf(findings, stats)
        findings = self._filter_version_mismatch(findings, stats)
        findings = self._filter_cms_mismatch(findings, stats)
        findings = self._dedup_ssl(findings, stats)
        findings = self._dedup_headers(findings, stats)
        findings = self._filter_info_noise(findings, stats)

        total_fp = sum(1 for f in findings if f.is_false_positive)
        log.info("fp_filter_complete", total=len(findings), false_positives=total_fp,
                 stats=stats)
        return findings

    def _filter_waf(self, findings: list[CorrelatedFinding],
                    stats: dict[str, int]) -> list[CorrelatedFinding]:
        """Rule 1: WAF-Filter — single-tool findings behind WAF are likely FP."""
        if not self.has_waf:
            return findings

        for f in findings:
            if f.is_false_positive:
                continue
            # Single-tool findings behind WAF with low confidence
            if f.primary.tool == "zap_active" and not f.corroborating and f.confidence < 0.5:
                f.is_false_positive = True
                f.fp_reason = "WAF detected, ZAP active-only finding with low confidence"
                stats["waf"] += 1

        return findings

    def _filter_version_mismatch(self, findings: list[CorrelatedFinding],
                                  stats: dict[str, int]) -> list[CorrelatedFinding]:
        """Rule 2: Version-Mismatch — CVE for wrong version is FP."""
        for f in findings:
            if f.is_false_positive or not f.primary.cve_id:
                continue

            ip = f.primary.host_ip
            versions = self._version_map.get(ip, {})
            if not versions:
                continue

            # Check if the finding mentions a specific version
            title_lower = f.primary.title.lower()
            desc_lower = f.primary.description.lower()
            combined = f"{title_lower} {desc_lower}"

            for product, detected_version in versions.items():
                if not detected_version:
                    continue
                if product not in combined:
                    continue

                # Extract version from finding title/description
                version_pattern = rf"{re.escape(product)}\s*([\d.]+)"
                match = re.search(version_pattern, combined)
                if match:
                    finding_version = match.group(1)
                    # If versions clearly don't match (major version differs)
                    finding_major = finding_version.split(".")[0]
                    detected_major = detected_version.split(".")[0]
                    if finding_major != detected_major:
                        f.is_false_positive = True
                        f.fp_reason = (f"Version mismatch: finding targets {product} "
                                       f"{finding_version}, detected {detected_version}")
                        stats["version"] += 1

        return findings

    def _filter_cms_mismatch(self, findings: list[CorrelatedFinding],
                              stats: dict[str, int]) -> list[CorrelatedFinding]:
        """Rule 3: CMS-Mismatch — WordPress templates on non-WordPress site."""
        if not self.detected_cms:
            return findings

        cms_tag_map = {
            "wordpress": {"wordpress", "wp-plugin", "wp-theme"},
            "shopware": {"shopware"},
            "typo3": {"typo3"},
            "joomla": {"joomla"},
            "drupal": {"drupal"},
        }

        for f in findings:
            if f.is_false_positive:
                continue

            # Check ZAP findings for CMS-specific template mismatches
            tags_raw = f.primary.raw.get("info", {}).get("tags", [])
            tags = set(tags_raw) if isinstance(tags_raw, list) else set()
            if not tags:
                continue

            for cms_name, cms_tags in cms_tag_map.items():
                if cms_name == self.detected_cms:
                    continue  # This is the correct CMS
                if tags & cms_tags:
                    f.is_false_positive = True
                    f.fp_reason = (f"CMS mismatch: {cms_name} templates, "
                                   f"but detected CMS is {self.detected_cms}")
                    stats["cms"] += 1
                    break

        return findings

    def _dedup_ssl(self, findings: list[CorrelatedFinding],
                   stats: dict[str, int]) -> list[CorrelatedFinding]:
        """Rule 4: SSL-Dedup — testssl and ZAP both report SSL issues."""
        ssl_findings: dict[str, list[CorrelatedFinding]] = {}

        for f in findings:
            if f.is_false_positive:
                continue
            if f.cluster_id and f.cluster_id.startswith("transport_security_"):
                key = f.cluster_id
                ssl_findings.setdefault(key, []).append(f)

        for cluster_key, cluster in ssl_findings.items():
            if len(cluster) <= 1:
                continue

            # Keep the highest-confidence finding, mark others as dedup
            cluster.sort(key=lambda c: -c.confidence)
            for f in cluster[1:]:
                # Only dedup if same general issue (both about weak cipher, etc.)
                primary_title = cluster[0].primary.title.lower()
                this_title = f.primary.title.lower()
                # Check for keyword overlap
                primary_words = set(primary_title.split())
                this_words = set(this_title.split())
                overlap = primary_words & this_words
                # If significant overlap, it's likely the same issue
                if len(overlap) >= 2 or (f.primary.cve_id and
                                          f.primary.cve_id == cluster[0].primary.cve_id):
                    f.is_false_positive = True
                    f.fp_reason = f"SSL dedup: same issue as {cluster[0].primary.title}"
                    stats["ssl_dedup"] += 1

        return findings

    def _dedup_headers(self, findings: list[CorrelatedFinding],
                       stats: dict[str, int]) -> list[CorrelatedFinding]:
        """Rule 5: Header-Dedup — header_check, ZAP report same missing header."""
        header_findings: dict[str, list[CorrelatedFinding]] = {}

        for f in findings:
            if f.is_false_positive:
                continue
            title = f.primary.title.lower()
            # Detect header-related findings
            for header in ("x-frame-options", "x-content-type-options",
                           "strict-transport-security", "content-security-policy",
                           "x-xss-protection", "referrer-policy", "permissions-policy"):
                if header in title:
                    key = f"{header}_{f.primary.host_ip}"
                    header_findings.setdefault(key, []).append(f)
                    break

        for header_key, cluster in header_findings.items():
            if len(cluster) <= 1:
                continue

            # Keep the header_check finding (deterministic, highest base confidence)
            cluster.sort(key=lambda c: (-1 if c.primary.tool == "header_check" else 0,
                                        -c.confidence))
            for f in cluster[1:]:
                f.is_false_positive = True
                f.fp_reason = f"Header dedup: same header as {cluster[0].primary.tool} finding"
                stats["header_dedup"] += 1

        return findings

    def _filter_info_noise(self, findings: list[CorrelatedFinding],
                           stats: dict[str, int]) -> list[CorrelatedFinding]:
        """Rule 6: Info-Noise — pure informational findings with no security value."""
        noise_patterns = [
            r"^server:\s*\w+$",  # Just server identification without version
            r"robots\.txt",      # robots.txt found (not a vulnerability)
            r"sitemap\.xml",     # sitemap found
            r"^options method",  # OPTIONS enabled (usually harmless)
        ]

        for f in findings:
            if f.is_false_positive:
                continue
            if f.primary.severity != "info":
                continue

            title = f.primary.title.lower()
            for pattern in noise_patterns:
                if re.search(pattern, title, re.IGNORECASE):
                    f.is_false_positive = True
                    f.fp_reason = f"Info noise: matches noise pattern '{pattern}'"
                    stats["info_noise"] += 1
                    break

        return findings

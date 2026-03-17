"""Phase 3 — Correlation & Enrichment.

Orchestrates cross-tool correlation, threat intelligence enrichment,
false-positive reduction, and business impact scoring.

This phase runs after all Phase 2 scans complete and before finalization.
It transforms raw tool output into correlated, enriched, and prioritized
findings that form the basis for the report.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Optional

import structlog

from scanner.ai_strategy import plan_phase3_prioritization
from scanner.correlation.business_impact import calculate_business_impact, calculate_order_impact
from scanner.correlation.correlator import CrossToolCorrelator, CorrelatedFinding, extract_findings
from scanner.correlation.fp_filter import FalsePositiveFilter
from scanner.correlation.threat_intel import (
    CISAKEVLoader,
    EPSSClient,
    ExploitDBClient,
    NVDClient,
)

log = structlog.get_logger()


def _collect_cve_ids(findings: list[CorrelatedFinding]) -> list[str]:
    """Extract unique CVE IDs from correlated findings."""
    cves: set[str] = set()
    for f in findings:
        if f.primary.cve_id:
            cves.add(f.primary.cve_id)
        for cf in f.corroborating:
            if cf.cve_id:
                cves.add(cf.cve_id)
    return sorted(cves)


def _build_finding_summary(findings: list[CorrelatedFinding]) -> list[dict[str, Any]]:
    """Build condensed finding summary for AI Phase-3 input."""
    summary: list[dict[str, Any]] = []
    for f in findings:
        entry = {
            "tool": f.primary.tool,
            "title": f.primary.title[:100],
            "severity": f.primary.severity,
            "cve": f.primary.cve_id,
            "confidence": round(f.confidence, 2),
            "host": f.primary.host_ip,
            "port": f.primary.port,
        }
        if f.corroborating:
            entry["also_found_by"] = [c.tool for c in f.corroborating]
        summary.append(entry)
    return summary


def run_phase3(
    phase2_results: list[dict[str, Any]],
    tech_profiles: list[dict[str, Any]],
    scan_dir: str,
    order_id: str,
    config: dict[str, Any],
    progress_callback: Callable[[str, str, str], None],
    phase0a_results: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Orchestrate Phase 3: Correlation, Enrichment, FP-Filter, Scoring.

    Args:
        phase2_results: List of Phase 2 result dicts (one per host).
        tech_profiles: List of tech profiles from Phase 1.
        scan_dir: Base scan directory.
        order_id: Order UUID.
        config: Package configuration.
        progress_callback: Progress reporter.
        phase0a_results: Passive intel results (for Shodan cross-ref).

    Returns:
        Phase 3 results dict with correlated findings, enrichment, and scores.
    """
    phase3_tools = config.get("phase3_tools", [])
    package = config.get("package", "perimeter")
    domain = config.get("domain", "")

    log.info("phase3_start", order_id=order_id, tools=phase3_tools)

    # ── Step 1: Extract findings from Phase 2 results ────────
    progress_callback(order_id, "correlation", "extracting")
    all_findings = extract_findings(phase2_results)

    if not all_findings:
        log.info("phase3_no_findings", order_id=order_id)
        return {
            "correlated_findings": [],
            "enrichment": {},
            "business_impact_score": 0.0,
            "phase3_summary": "No findings to correlate.",
        }

    # ── Step 2: Determine WAF and CMS context ───────────────
    has_waf = any(p.get("waf") for p in tech_profiles if not p.get("skipped"))
    detected_cms = None
    for p in tech_profiles:
        if p.get("cms") and not p.get("skipped"):
            detected_cms = p["cms"]
            break

    # Build Shodan services map from Phase 0a
    shodan_services: dict[str, dict[str, str]] = {}
    if phase0a_results:
        for ip, host_data in phase0a_results.get("shodan_hosts", {}).items():
            if isinstance(host_data, dict):
                shodan_services[ip] = host_data.get("services", {})

    # ── Step 3: Cross-Tool Correlation ───────────────────────
    progress_callback(order_id, "correlation", "correlating")

    correlator = CrossToolCorrelator(
        tech_profiles=tech_profiles,
        has_waf=has_waf,
        shodan_services=shodan_services,
    )
    correlated = correlator.correlate(all_findings)

    # ── Step 4: AI Phase-3 Prioritization (Sonnet) ───────────
    ai_prioritization: dict[str, Any] = {}
    if len(correlated) > 5:  # Only worth calling AI for non-trivial finding sets
        progress_callback(order_id, "correlation", "ai_prioritization")
        finding_summary = _build_finding_summary(correlated)
        ai_prioritization = plan_phase3_prioritization(
            finding_summary, tech_profiles, has_waf,
        )

        # Apply AI FP suggestions to correlated findings
        ai_fps = {fp.get("finding_ref", ""): fp.get("reason", "")
                  for fp in ai_prioritization.get("potential_false_positives", [])}
        for cf in correlated:
            ref = f"{cf.primary.tool}:{cf.primary.title}"
            cve_ref = cf.primary.cve_id or ""
            if ref in ai_fps or cve_ref in ai_fps:
                reason = ai_fps.get(ref) or ai_fps.get(cve_ref, "")
                if not cf.is_false_positive:  # Don't override programmatic FP
                    cf.is_false_positive = True
                    cf.fp_reason = f"AI: {reason}"

    # ── Step 5: False-Positive Filter ────────────────────────
    if "fp_filter" in phase3_tools:
        progress_callback(order_id, "correlation", "fp_filter")
        fp_filter = FalsePositiveFilter(
            tech_profiles=tech_profiles,
            has_waf=has_waf,
            detected_cms=detected_cms,
        )
        correlated = fp_filter.filter(correlated)

    # ── Step 6: Threat-Intel Enrichment ──────────────────────
    cve_ids = _collect_cve_ids(correlated)
    enrichment_data: dict[str, dict[str, Any]] = {}

    # NVD enrichment
    if "nvd" in phase3_tools and cve_ids:
        progress_callback(order_id, "correlation", "nvd_enrichment")
        nvd = NVDClient()
        # WebCheck: max 5 lookups (only CRITICAL). Perimeter+: all CVEs.
        max_lookups = 5 if package == "webcheck" else 50
        nvd_data = nvd.lookup_batch(cve_ids, max_lookups=max_lookups)
        for cve_id, data in nvd_data.items():
            enrichment_data.setdefault(cve_id, {})["nvd"] = data

    # EPSS enrichment
    if "epss" in phase3_tools and cve_ids:
        progress_callback(order_id, "correlation", "epss_enrichment")
        epss = EPSSClient()
        epss_data = epss.lookup_batch(cve_ids)
        for cve_id, data in epss_data.items():
            enrichment_data.setdefault(cve_id, {})["epss"] = data

    # CISA KEV
    if "cisa_kev" in phase3_tools and cve_ids:
        progress_callback(order_id, "correlation", "cisa_kev_check")
        kev = CISAKEVLoader()
        kev_data = kev.check_batch(cve_ids)
        for cve_id, data in kev_data.items():
            enrichment_data.setdefault(cve_id, {})["cisa_kev"] = data

    # ExploitDB
    if "exploitdb" in phase3_tools and cve_ids:
        progress_callback(order_id, "correlation", "exploitdb_check")
        edb = ExploitDBClient()
        if edb.available:
            edb_data = edb.search_batch(cve_ids)
            for cve_id, data in edb_data.items():
                enrichment_data.setdefault(cve_id, {})["exploitdb"] = data

    # Apply enrichment to correlated findings
    for cf in correlated:
        cve_id = cf.primary.cve_id
        if cve_id and cve_id in enrichment_data:
            cf.enrichment = enrichment_data[cve_id]

            # CISA KEV → auto-CRITICAL
            if "cisa_kev" in cf.enrichment:
                cf.primary.severity = "critical"
                cf.confidence = max(cf.confidence, 0.95)

            # EPSS > 0.5 → boost priority
            epss_info = cf.enrichment.get("epss", {})
            if isinstance(epss_info, dict) and epss_info.get("epss", 0) > 0.5:
                if cf.primary.severity in ("medium", "low"):
                    cf.primary.severity = "high"

            # NVD CVSS overrides tool CVSS
            nvd_info = cf.enrichment.get("nvd", {})
            if nvd_info and nvd_info.get("cvss_score"):
                cf.enrichment["authoritative_cvss"] = nvd_info["cvss_score"]

    # ── Step 7: Business-Impact Scoring ──────────────────────
    order_impact_score = 0.0
    if "business_impact" in phase3_tools:
        progress_callback(order_id, "correlation", "business_impact")
        for cf in correlated:
            if not cf.is_false_positive:
                cf.enrichment["business_impact"] = calculate_business_impact(
                    cf, package, domain,
                )
        order_impact_score = calculate_order_impact(correlated, package, domain)

    # ── Step 8: Save results to disk ─────────────────────────
    phase3_dir = os.path.join(scan_dir, "phase3")
    os.makedirs(phase3_dir, exist_ok=True)

    # Save correlated findings
    findings_data = [cf.to_dict() for cf in correlated]
    with open(os.path.join(phase3_dir, "correlated_findings.json"), "w") as f:
        json.dump(findings_data, f, indent=2, ensure_ascii=False, default=str)

    # Save enrichment
    with open(os.path.join(phase3_dir, "enrichment.json"), "w") as f:
        json.dump(enrichment_data, f, indent=2, ensure_ascii=False, default=str)

    # Save AI prioritization
    if ai_prioritization:
        with open(os.path.join(phase3_dir, "ai_prioritization.json"), "w") as f:
            json.dump(ai_prioritization, f, indent=2, ensure_ascii=False)

    # Build summary
    non_fp = [cf for cf in correlated if not cf.is_false_positive]
    severity_counts: dict[str, int] = {}
    for cf in non_fp:
        sev = cf.primary.severity
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    phase3_result = {
        "correlated_findings": findings_data,
        "enrichment": enrichment_data,
        "ai_prioritization": ai_prioritization,
        "business_impact_score": order_impact_score,
        "phase3_summary": {
            "total_findings": len(correlated),
            "false_positives": sum(1 for cf in correlated if cf.is_false_positive),
            "valid_findings": len(non_fp),
            "severity_counts": severity_counts,
            "cves_enriched": len(enrichment_data),
            "cisa_kev_matches": sum(1 for d in enrichment_data.values()
                                    if "cisa_kev" in d),
        },
    }

    log.info("phase3_complete", order_id=order_id,
             total=len(correlated),
             valid=len(non_fp),
             fps=phase3_result["phase3_summary"]["false_positives"],
             impact_score=order_impact_score,
             cves_enriched=len(enrichment_data))

    return phase3_result

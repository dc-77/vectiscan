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
from scanner.progress import publish_event

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
            "phase3_summary": {
                "total_findings": 0,
                "false_positives": 0,
                "valid_findings": 0,
                "severity_counts": {},
                "cves_enriched": 0,
                "cisa_kev_matches": 0,
                "fp_details": [],
                "fp_by_reason": {},
                "message": "No findings to correlate.",
            },
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
    publish_event(order_id, {"type": "tool_starting", "tool": "correlator", "host": ""})
    progress_callback(order_id, "correlation", "correlating")

    correlator = CrossToolCorrelator(
        tech_profiles=tech_profiles,
        has_waf=has_waf,
        shodan_services=shodan_services,
    )
    correlated = correlator.correlate(all_findings)

    # ── Step 4: AI Phase-3 Confidence Boost (Sonnet) ─────────
    # Hinweis (Q2/2026 Determinismus): KI #4 ist auf reinen Confidence-Boost
    # reduziert. Sie setzt KEINE FP-Marker mehr (das macht fp_filter.py) und
    # passt KEINE Severities an (das macht severity_policy.py im Reporter).
    ai_prioritization: dict[str, Any] = {}
    if len(correlated) > 5:  # Only worth calling AI for non-trivial finding sets
        progress_callback(order_id, "correlation", "ai_prioritization")
        finding_summary = _build_finding_summary(correlated)
        ai_prioritization = plan_phase3_prioritization(
            finding_summary, tech_profiles, has_waf, order_id=order_id,
        )

        # Apply confidence scores to correlated findings (KEIN FP-Marker mehr).
        confidence_lookup: dict[str, dict[str, Any]] = {}
        for entry in ai_prioritization.get("confidence_scores", []):
            ref = entry.get("finding_ref", "")
            if ref:
                confidence_lookup[ref] = entry

        for cf in correlated:
            ref = f"{cf.primary.tool}:{cf.primary.title}"
            cve_ref = cf.primary.cve_id or ""
            entry = confidence_lookup.get(ref) or confidence_lookup.get(cve_ref)
            if not entry:
                continue
            new_conf = entry.get("confidence")
            if isinstance(new_conf, (int, float)):
                # Boost only — never reduce confidence below current value
                cf.confidence = max(cf.confidence or 0.0, float(new_conf))
            corroboration = entry.get("corroboration") or []
            if corroboration:
                cf.enrichment.setdefault("ai_corroboration", corroboration)

    # ── Step 5: False-Positive Filter ────────────────────────
    if "fp_filter" in phase3_tools:
        publish_event(order_id, {"type": "tool_starting", "tool": "fp_filter", "host": ""})
        progress_callback(order_id, "correlation", "fp_filter")
        fp_filter = FalsePositiveFilter(
            tech_profiles=tech_profiles,
            has_waf=has_waf,
            detected_cms=detected_cms,
        )
        correlated = fp_filter.filter(correlated)

    # ── Step 6: Threat-Intel Enrichment (parallel) ──────────
    cve_ids = _collect_cve_ids(correlated)
    enrichment_data: dict[str, dict[str, Any]] = {}

    # M2 (2026-05-01): Daily-Snapshot anlegen / abrufen. Wir lesen erst aus
    # dem Snapshot; nur fuer fehlende CVEs werden Live-Lookups gemacht und
    # die Ergebnisse zurueck in den Snapshot gemerged. Folge-Scans im selben
    # Tag treffen den Snapshot.
    from scanner.threat_intel_snapshot import (
        attach_snapshot_to_order,
        get_or_create_today_snapshot_id,
        get_snapshot_data,
        merge_into_snapshot,
    )
    snapshot_id = get_or_create_today_snapshot_id()
    if snapshot_id and order_id:
        attach_snapshot_to_order(order_id, snapshot_id)
    snap = get_snapshot_data(snapshot_id) if snapshot_id else {"nvd": {}, "kev": {}, "epss": {}}

    if cve_ids:
        from concurrent.futures import ThreadPoolExecutor

        publish_event(order_id, {"type": "tool_starting", "tool": "nvd", "host": ""})
        progress_callback(order_id, "correlation", "enrichment")
        max_lookups = 5 if package == "webcheck" else 50

        # CVEs die noch nicht im Snapshot sind
        missing_nvd = [c for c in cve_ids if c not in (snap.get("nvd") or {})]
        missing_epss = [c for c in cve_ids if c not in (snap.get("epss") or {})]
        missing_kev = [c for c in cve_ids if c not in (snap.get("kev") or {})]

        def _enrich_nvd() -> dict[str, Any]:
            if "nvd" not in phase3_tools or not missing_nvd:
                return {}
            return NVDClient().lookup_batch(missing_nvd, max_lookups=max_lookups)

        def _enrich_epss() -> dict[str, Any]:
            if "epss" not in phase3_tools or not missing_epss:
                return {}
            return EPSSClient().lookup_batch(missing_epss)

        def _enrich_kev() -> dict[str, Any]:
            if "cisa_kev" not in phase3_tools or not missing_kev:
                return {}
            return CISAKEVLoader().check_batch(missing_kev)

        def _enrich_exploitdb() -> dict[str, Any]:
            if "exploitdb" not in phase3_tools:
                return {}
            edb = ExploitDBClient()
            return edb.search_batch(cve_ids) if edb.available else {}

        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="enrich") as pool:
            nvd_future = pool.submit(_enrich_nvd)
            epss_future = pool.submit(_enrich_epss)
            kev_future = pool.submit(_enrich_kev)
            edb_future = pool.submit(_enrich_exploitdb)

            # Collect results with individual error handling
            nvd_data: dict[str, Any] = {}
            epss_data: dict[str, Any] = {}
            kev_data: dict[str, Any] = {}
            edb_data: dict[str, Any] = {}

            try:
                nvd_data = nvd_future.result(timeout=120)
            except Exception as e:
                log.error("nvd_enrichment_failed", error=str(e))
            try:
                epss_data = epss_future.result(timeout=30)
            except Exception as e:
                log.error("epss_enrichment_failed", error=str(e))
            try:
                kev_data = kev_future.result(timeout=30)
            except Exception as e:
                log.error("kev_enrichment_failed", error=str(e))
            try:
                edb_data = edb_future.result(timeout=60)
            except Exception as e:
                log.error("exploitdb_enrichment_failed", error=str(e))

        # Frische Daten in den Snapshot mergen (lazy-fill)
        if snapshot_id and (nvd_data or kev_data or epss_data):
            merge_into_snapshot(
                snapshot_id,
                nvd_delta=nvd_data, kev_delta=kev_data, epss_delta=epss_data,
            )
            log.info("snapshot_merged",
                     snapshot_id=snapshot_id,
                     nvd_added=len(nvd_data), kev_added=len(kev_data), epss_added=len(epss_data))

        # Merge: Snapshot-Daten + frische Live-Lookups
        full_nvd = {**(snap.get("nvd") or {}), **nvd_data}
        full_epss = {**(snap.get("epss") or {}), **epss_data}
        full_kev = {**(snap.get("kev") or {}), **kev_data}

        for cve_id in cve_ids:
            entry: dict[str, Any] = {}
            if cve_id in full_nvd:
                entry["nvd"] = full_nvd[cve_id]
            if cve_id in full_epss:
                entry["epss"] = full_epss[cve_id]
            if cve_id in full_kev:
                entry["cisa_kev"] = full_kev[cve_id]
            if cve_id in edb_data:
                entry["exploitdb"] = edb_data[cve_id]
            if entry:
                enrichment_data[cve_id] = entry

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
            if isinstance(nvd_info, dict) and nvd_info.get("cvss_score"):
                cf.enrichment["authoritative_cvss"] = nvd_info["cvss_score"]

    # ── Step 7: Business-Impact Scoring ──────────────────────
    order_impact_score = 0.0
    if "business_impact" in phase3_tools:
        publish_event(order_id, {"type": "tool_starting", "tool": "business_impact", "host": ""})
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
    fp_list = [cf for cf in correlated if cf.is_false_positive]
    severity_counts: dict[str, int] = {}
    for cf in non_fp:
        sev = cf.primary.severity
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Detailed FP report: which findings were filtered and why
    fp_details: list[dict[str, str]] = []
    for cf in fp_list:
        fp_details.append({
            "tool": cf.primary.tool,
            "title": cf.primary.title[:100],
            "severity": cf.primary.severity,
            "reason": cf.fp_reason,
            "host": cf.primary.host_ip,
            "cve": cf.primary.cve_id or "",
        })

    # Group FP reasons for summary
    fp_by_reason: dict[str, int] = {}
    for fp in fp_details:
        # Extract the rule category from the reason
        reason = fp["reason"]
        if reason.startswith("AI:"):
            category = "AI-Priorisierung"
        elif "WAF" in reason:
            category = "WAF-Filter"
        elif "Version mismatch" in reason:
            category = "Version-Mismatch"
        elif "CMS mismatch" in reason:
            category = "CMS-Mismatch"
        elif "SSL dedup" in reason:
            category = "SSL-Dedup"
        elif "Header dedup" in reason:
            category = "Header-Dedup"
        elif "Info noise" in reason:
            category = "Info-Noise"
        else:
            category = "Sonstige"
        fp_by_reason[category] = fp_by_reason.get(category, 0) + 1

    phase3_result = {
        "correlated_findings": findings_data,
        "enrichment": enrichment_data,
        "ai_prioritization": ai_prioritization,
        "business_impact_score": order_impact_score,
        "phase3_summary": {
            "total_findings": len(correlated),
            "false_positives": len(fp_list),
            "valid_findings": len(non_fp),
            "severity_counts": severity_counts,
            "cves_enriched": len(enrichment_data),
            "cisa_kev_matches": sum(1 for d in enrichment_data.values()
                                    if "cisa_kev" in d),
            "fp_details": fp_details,
            "fp_by_reason": fp_by_reason,
        },
    }

    log.info("phase3_complete", order_id=order_id,
             total=len(correlated),
             valid=len(non_fp),
             fps=phase3_result["phase3_summary"]["false_positives"],
             impact_score=order_impact_score,
             cves_enriched=len(enrichment_data))

    return phase3_result

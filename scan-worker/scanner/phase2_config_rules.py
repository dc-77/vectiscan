"""Deterministische Rule-Engine fuer Phase-2-Config (vor KI #3).

Hintergrund: KI #3 (`plan_phase2_config`) liefert auch bei klaren Faellen
variable Outputs (zap_threads mal 5, mal 8 bei identischem Tech-Profile).
Bei wiederholten Scans -> Determinismus-Drift.

Loesung: Wenn der Tech-Profile + WAF + Package eindeutig auf einen
Standard-Fall passt -> deterministische Config zurueckgeben, KEIN KI-Call.
KI bleibt nur fuer Edge-Cases.

Spart ~$0.024/Order bei 3 Hosts (3x Haiku-Call vermieden).
"""

from __future__ import annotations

from typing import Any, Optional

# Default-Sets pro Profil
_CATEGORIES_FULL = ["sqli", "xss", "lfi", "ssrf", "cmdi", "path_traversal"]
_CATEGORIES_WAF_SAFE = ["sqli", "xss", "lfi"]
_CATEGORIES_API = ["sqli", "ssrf", "cmdi", "auth_bypass"]


def try_rule_based_config(
    tech_profile: dict[str, Any],
    package: str,
    domain: str = "",
) -> Optional[dict[str, Any]]:
    """Liefert Phase-2-Config ohne KI wenn Tech-Profile eindeutig matcht.

    Returns:
        dict mit Phase-2-Config (gleiche Felder wie KI-Output) ODER None
        wenn kein Match → KI-Fallback in plan_phase2_config notwendig.
    """
    cms = (tech_profile.get("cms") or "").lower()
    waf = (tech_profile.get("waf") or "").lower()
    server = (tech_profile.get("server") or "").lower()
    has_ssl = bool(tech_profile.get("has_ssl"))
    is_spa = bool(tech_profile.get("is_spa"))
    open_ports = set(tech_profile.get("open_ports") or [])
    fqdns = tech_profile.get("fqdns") or []
    primary_fqdn = (fqdns[0] if fqdns else "").lower()
    package_lc = (package or "").lower()
    is_webcheck = package_lc in ("webcheck", "basic")

    # Reine Mailserver (nur Mail-Ports, kein Web)
    mail_ports = {25, 465, 587, 993, 995}
    if open_ports and open_ports.issubset(mail_ports | {22}) and not has_ssl:
        return _config(
            policy="passive-only",
            spider_depth=0,
            ajax=False,
            cats=[],
            rate=20, threads=2,
            skip_tools=["zap_active", "zap_spider", "zap_ajax_spider",
                        "feroxbuster", "ffuf", "wpscan", "nikto"],
            reason="rule:mail-server-only",
        )

    # WordPress + kein WAF + has_ssl  → Standard-Scan
    if cms == "wordpress" and not waf and has_ssl:
        return _config(
            policy="standard",
            spider_depth=8,
            ajax=False,
            cats=_CATEGORIES_FULL,
            rate=80, threads=10,
            skip_tools=[],
            reason="rule:wordpress-standard",
        )

    # CMS unbekannt + Cloudflare-WAF (oder andere WAF) → waf-safe
    if waf and (
        "cloudflare" in waf or "akamai" in waf or "imperva" in waf
        or "fortinet" in waf or "modsecurity" in waf
    ):
        return _config(
            policy="waf-safe",
            spider_depth=5,
            ajax=False,
            cats=_CATEGORIES_WAF_SAFE,
            rate=30, threads=3,
            skip_tools=["wpscan"] if cms != "wordpress" else [],
            reason=f"rule:waf-{waf.split()[0]}",
        )

    # SPA (Next.js, React, Vue, Angular) → AJAX-Spider an
    if is_spa or any(t in (server + " " + cms) for t in ("next.js", "nuxt", "react", "vue", "angular")):
        return _config(
            policy="standard",
            spider_depth=6,
            ajax=True,
            cats=_CATEGORIES_FULL,
            rate=60, threads=5,
            skip_tools=["wpscan"],
            reason="rule:spa-ajax",
        )

    # Reine API-Hosts (typisch /api/ in primary_fqdn oder kein has_web)
    if (primary_fqdn.startswith("api.") or "graphql" in primary_fqdn) and not cms:
        return _config(
            policy="standard",
            spider_depth=4,
            ajax=False,
            cats=_CATEGORIES_API,
            rate=50, threads=5,
            skip_tools=["feroxbuster", "wpscan"],
            reason="rule:api-host",
        )

    # WebCheck-Paket auf normaler Site → konservativ + schnell
    if is_webcheck and has_ssl and not cms:
        return _config(
            policy="standard",
            spider_depth=4,
            ajax=False,
            cats=_CATEGORIES_WAF_SAFE,
            rate=60, threads=5,
            skip_tools=["wpscan", "feroxbuster"],
            reason="rule:webcheck-quick",
        )

    # Generic CMS (Drupal, TYPO3, Joomla) ohne WAF
    if cms in {"drupal", "typo3", "joomla", "shopware", "magento"} and not waf:
        return _config(
            policy="standard",
            spider_depth=7,
            ajax=False,
            cats=_CATEGORIES_FULL,
            rate=80, threads=8,
            skip_tools=["wpscan"],
            reason=f"rule:{cms}-standard",
        )

    # Kein deterministischer Match -> KI muss entscheiden
    return None


def _config(*, policy: str, spider_depth: int, ajax: bool, cats: list[str],
            rate: int, threads: int, skip_tools: list[str], reason: str,
            ) -> dict[str, Any]:
    """Baut das Standard-Config-Dict im KI-Output-Format."""
    return {
        "zap_scan_policy": policy,
        "zap_spider_max_depth": spider_depth,
        "zap_ajax_spider_enabled": ajax,
        "zap_active_categories": cats,
        "zap_rate_req_per_sec": rate,
        "zap_threads": threads,
        "zap_spider_delay_ms": 0,
        "zap_extra_urls": [],
        "skip_tools": skip_tools,
        "reasoning": f"[RULE-BASED] {reason}",
        "_rule_based": True,  # marker fuer Logging/Debug
    }

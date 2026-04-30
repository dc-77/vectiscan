"""AI-powered scan strategy — 4 decision points.

1. Host Strategy (Haiku): after Phase 0, decide scan/skip per host
2. Phase-2 Config (Haiku): after Phase 1, configure tools per host
3. Phase-3 Prioritization (Sonnet): after Phase 2, cross-tool correlation reasoning
4. Report QA (programmatic + Haiku): after report generation (Phase V)
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import structlog

from scanner.ai_cache import (
    AI_PRICING,
    CacheStats,
    cached_call,
    extract_text,
)

log = structlog.get_logger()

HAIKU_MODEL = "claude-haiku-4-5-20251001"
SONNET_MODEL = "claude-sonnet-4-6"

# Cache-TTLs pro Namespace (Spec 03-ai-determinism.md §5)
CACHE_TTL_HOST_STRATEGY = 7 * 24 * 3600     # 7 Tage
CACHE_TTL_TECH_ANALYSIS = 30 * 24 * 3600    # 30 Tage (CMS-Detection ist stabil)
CACHE_TTL_PHASE2_CONFIG = 7 * 24 * 3600     # 7 Tage
CACHE_TTL_PHASE3 = 24 * 3600                # 1 Tag (Findings-Liste aendert sich oft)


def _save_ai_debug(
    order_id: str,
    host_ip: str | None,
    phase: int,
    tool_name: str,
    system_prompt: str,
    user_prompt: str,
    raw_response: str,
    parsed: dict[str, Any],
    cost: dict[str, Any] | None = None,
) -> None:
    """Save full Claude prompt+response for debug transparency.

    Stored as a separate scan_result with tool_name '{tool_name}_debug'.
    """
    from scanner.tools import _save_result
    debug = {
        "system_prompt": system_prompt,
        "user_prompt": user_prompt[:10000],  # Cap user prompt (can be very long)
        "raw_response": raw_response,
    }
    if cost:
        debug["cost"] = cost
    _save_result(
        order_id=order_id, host_ip=host_ip, phase=phase,
        tool_name=f"{tool_name}_debug",
        raw_output=json.dumps(debug, indent=2, ensure_ascii=False)[:50000],
        exit_code=0, duration_ms=0,
    )


# ---------------------------------------------------------------------------
# Haiku client
# ---------------------------------------------------------------------------

def _strip_markdown_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
    if text.endswith("```"):
        text = text.rsplit("```", 1)[0]
    return text.strip()


def _build_cost_dict(model: str, stats: CacheStats) -> dict[str, Any]:
    return {
        "model": model,
        "input_tokens": stats.input_tokens,
        "output_tokens": stats.output_tokens,
        "total_cost_usd": round(stats.cost_estimated_usd, 4),
        "cache_hit": stats.hit,
        "cache_age_seconds": stats.age_seconds,
        "cache_key": stats.cache_key_short,
    }


def _call_haiku(system_prompt: str, user_prompt: str,
                cache_namespace: str = "haiku_default",
                cache_ttl_seconds: int = 24 * 3600) -> dict[str, Any]:
    """Cached Haiku-Call mit temperature=0.

    On failure, returns {"_error": "reason"} so callers can include the
    specific error in fallback reasoning shown to the user.

    Caller-Vertrag (unveraendert):
      - parsed["_raw"]  : roher Antwort-Text (auch bei JSON-Parse-Fehler)
      - parsed["_cost"] : {model, input_tokens, output_tokens, total_cost_usd, cache_hit, ...}
    """
    raw = ""
    start = time.monotonic()
    response_dict, stats = cached_call(
        model=HAIKU_MODEL,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
        temperature=0.0,
        max_tokens=8192,
        cache_ttl_seconds=cache_ttl_seconds,
        cache_namespace=cache_namespace,
    )
    duration_ms = int((time.monotonic() - start) * 1000)

    if "_error" in response_dict:
        return {"_error": response_dict["_error"], "_raw": ""}

    raw = extract_text(response_dict)
    log.info("haiku_response",
             namespace=cache_namespace,
             cache_hit=stats.hit,
             duration_ms=duration_ms,
             tokens=stats.output_tokens)

    text = _strip_markdown_fences(raw)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        log.error("haiku_json_parse_error",
                  namespace=cache_namespace, error=str(e), raw=raw[:500])
        return {"_error": f"JSON-Parse-Fehler: {e}", "_raw": raw}

    parsed["_raw"] = raw
    parsed["_cost"] = _build_cost_dict(HAIKU_MODEL, stats)
    return parsed


# ---------------------------------------------------------------------------
# Host Strategy (after Phase 0)
# ---------------------------------------------------------------------------

HOST_STRATEGY_SYSTEM = """Du bist ein Security-Scanner-Orchestrator. Du entscheidest, welche Hosts gescannt werden und mit welcher Priorität.

WICHTIG ZU FQDNs:
- Jeder Host hat eine Liste von FQDNs die auf dieselbe IP zeigen
- Die ERSTE FQDN in der Liste ist die relevanteste (Basisdomain vor www vor Subdomains)
- Wenn ein Host sowohl die Basisdomain als auch Mail-FQDNs enthält, ist er IMMER ein Web-Host
- Beurteile den Host nach seiner wichtigsten FQDN, nicht nach Mail-Subdomains

WEB-PROBE DATEN:
- Jeder Host kann ein "web_probe" Feld haben mit has_web, status, final_url, title
- has_web=true: HTTP-Content vorhanden → Web-Scan (alle Tools)
- has_web=false: Kein HTTP-Content → Port-Scan (nmap + testssl reichen)
- final_url zeigt wohin Redirects führen → die relevante Scan-URL

PASSIVE INTELLIGENCE (wenn verfügbar):
- Jeder Host kann ein "passive_intel" Feld haben mit Daten aus Shodan, AbuseIPDB, WHOIS:
  - shodan_ports: Bereits bekannte offene Ports pro IP
  - shodan_services: Service-Versionen (z.B. {"443": "nginx 1.18", "22": "OpenSSH 7.9"})
  - abuseipdb_score: IP-Reputation (0-100, höher = verdächtiger)
  - is_tor: Ob die IP ein Tor-Exit-Node ist
  - dnssec_signed: Ob die Domain DNSSEC-signiert ist
  - whois_expiration: Domain-Ablaufdatum

ERWEITERTE REGELN (Passive Intel):
- Hosts mit veralteten Service-Versionen aus Shodan (alte OpenSSH, alte nginx) → Priorität 1
- Hosts mit exponierten Management-Ports (22, 3389, 5900, 8080, 8443) aus Shodan → Priorität 1
- Hosts mit hohem AbuseIPDB-Score (>50) → Priorität 1 (mögliche Kompromittierung)
- Hosts mit nur Port 80/443 und niedrigem AbuseIPDB-Score → Priorität 2
- Mailserver mit fehlender SPF/DMARC → scannen (nicht skippen!)

STANDARD-REGELN:
- Basisdomain und www-Subdomain: IMMER scannen (action: "scan"), höchste Priorität
- Webserver mit interaktivem Content (Apps, APIs, CMS, Shops): scan (hohe Priorität)
- Mailserver (MX, SMTP, IMAP): scan mit NIEDRIGERER Priorität — NICHT skippen!
- Autodiscover-Hosts (nur Exchange/Outlook-Konfiguration): skip
- Parking-Pages, Redirect auf externe Domain: skip
- CDN-Edge-Nodes (nur CDN-IP, kein eigener Content): skip (außer bei has_web=true mit eigenem Content)
- Wenn unklar: lieber scannen als überspringen

Jeder Host braucht eine kurze Begründung (1 Satz).
Priority: 1 = höchste Priorität, aufsteigend.

Antworte NUR mit validem JSON, kein anderer Text."""

HOST_STRATEGY_SCHEMA = """{
  "hosts": [
    {
      "ip": "...",
      "action": "scan|skip",
      "priority": 1,
      "reasoning": "...",
      "scan_hints": {
        "shodan_ports": [21, 22, 80, 443],
        "focus_areas": ["web_vulns", "ssl", "ftp_security"]
      }
    }
  ],
  "strategy_notes": "Kurze Zusammenfassung der Strategie",
  "passive_intel_summary": "Was die Passive Intelligence ergeben hat"
}"""


def plan_host_strategy(
    host_inventory: dict[str, Any],
    domain: str,
    package: str,
    order_id: str = "",
) -> dict[str, Any]:
    """Use Haiku to decide which hosts to scan and in what order."""
    hosts = host_inventory.get("hosts", [])
    if not hosts:
        return {"hosts": [], "strategy_notes": "Keine Hosts gefunden"}

    dns_findings = host_inventory.get("dns_findings", {})

    user_prompt = f"""Domain: {domain}
Paket: {package}

Gefundene Hosts ({len(hosts)}):
{json.dumps(hosts, indent=2, ensure_ascii=False)}

DNS-Findings:
{json.dumps(dns_findings, indent=2, ensure_ascii=False)}

Entscheide für jeden Host: scan oder skip?
Antwort im Format:
{HOST_STRATEGY_SCHEMA}"""

    result = _call_haiku(
        HOST_STRATEGY_SYSTEM, user_prompt,
        cache_namespace="ki1_host_strategy",
        cache_ttl_seconds=CACHE_TTL_HOST_STRATEGY,
    )

    # Save full AI debug (system prompt + user prompt + raw response)
    cost = result.get("_cost")
    if order_id:
        _save_ai_debug(order_id, None, 0, "ai_host_strategy",
                        HOST_STRATEGY_SYSTEM, user_prompt,
                        result.get("_raw", ""), result, cost=cost)

    error_detail = result.get("_error", "")
    if not result or "hosts" not in result:
        # Fallback: scan all hosts in original order
        reason = error_detail or "Ungültige KI-Antwort"
        log.warning("ai_host_strategy_fallback", reason=reason)
        return {
            "hosts": [
                {"ip": h["ip"], "action": "scan", "priority": i + 1,
                 "reasoning": f"Fallback — {reason}"}
                for i, h in enumerate(hosts)
            ],
            "strategy_notes": f"Fallback: alle Hosts scannen ({reason})"
        }

    log.info("ai_host_strategy_complete",
             scan=sum(1 for h in result["hosts"] if h.get("action") == "scan"),
             skip=sum(1 for h in result["hosts"] if h.get("action") == "skip"))

    # Strip internal keys before return
    result.pop("_raw", None)
    result.pop("_cost", None)
    return result


# ---------------------------------------------------------------------------
# Tech Analysis (after Phase 1, correct CMS detection)
# ---------------------------------------------------------------------------

TECH_ANALYSIS_SYSTEM = """Du bist ein Web-Technologie-Analyst. Du bestimmst die korrekte Technologie für jeden Host basierend auf Redirect-Verhalten, HTTP-Headern und Scan-Ergebnissen.

REGELN:
- Wenn eine FQDN auf eine ANDERE Domain redirected → die FQDN nutzt NICHT das CMS dieser anderen Domain
- Wenn /wp-login.php existiert aber Body "nicht gefunden", "not found" oder "404" enthält → KEIN WordPress
- Wenn /wp-login.php auf eine andere Domain redirected → KEIN WordPress auf DIESER Domain
- Page Title "Outlook Web App" oder "OWA" → Microsoft Exchange, KEIN WordPress/CMS
- Page Title mit "TYPO3" oder "Neos" → TYPO3
- meta generator Tag hat Vorrang vor Pfad-Probes
- IIS Server + .aspx/.asmx Pfade → Microsoft-Stack, KEIN PHP-CMS
- Wenn CMS-Fingerprinter WordPress mit hoher Konfidenz (>0.8) meldet UND /wp-login.php tatsächlich WordPress-Login zeigt → WordPress bestätigt
- Wenn CMS-Fingerprinter WordPress meldet ABER /wp-login.php zeigt Fehlerseite → WordPress NICHT bestätigt, CMS auf null setzen

WICHTIG:
- Nur CMS melden wenn du sicher bist. Im Zweifel: cms=null
- technology_stack ist eine Liste aller erkannten Technologien (Server, Sprache, Framework)
- is_spa=true nur wenn React, Vue, Angular, Next.js, Nuxt oder Shopware 6 erkannt

Antworte NUR mit validem JSON, kein anderer Text."""

TECH_ANALYSIS_SCHEMA = """{
  "hosts": {
    "<ip>": {
      "cms": "WordPress|TYPO3|Shopware|Joomla|Drupal|Exchange|null",
      "cms_version": "6.8|null",
      "cms_confidence": 0.95,
      "technology_stack": ["nginx", "PHP 8.2", "WordPress"],
      "is_spa": false,
      "reasoning": "Kurze Begründung"
    }
  }
}"""


def plan_tech_analysis(
    tech_profiles: list[dict[str, Any]],
    redirect_data: dict[str, Any],
    order_id: str = "",
) -> dict[str, Any]:
    """Use Haiku to correct CMS detection using Playwright redirect data.

    Args:
        tech_profiles: Phase 1 tech profiles (with potentially wrong CMS)
        redirect_data: Playwright redirect probe results per FQDN
        order_id: For debug logging

    Returns:
        Dict with corrected CMS per host IP.
    """
    if not tech_profiles:
        return {}

    # Build condensed summary of tech profiles
    tech_profiles_summary = []
    for tp in tech_profiles:
        tech_profiles_summary.append({
            "ip": tp.get("ip", ""),
            "fqdns": tp.get("fqdns", []),
            "cms": tp.get("cms"),
            "cms_confidence": tp.get("cms_confidence"),
            "server": tp.get("server"),
            "open_ports": tp.get("open_ports", []),
        })

    user_prompt = f"""Phase-1 Tech-Profiles (CMS-Fingerprinter-Vorschlag, kann falsch sein):
{json.dumps(tech_profiles_summary, indent=2, ensure_ascii=False)}

Playwright Redirect-Analyse:
{json.dumps(redirect_data, indent=2, ensure_ascii=False)}

Korrigiere die CMS-Erkennung für jeden Host.
Antwort im Format:
{TECH_ANALYSIS_SCHEMA}"""

    result = _call_haiku(
        TECH_ANALYSIS_SYSTEM, user_prompt,
        cache_namespace="ki2_tech_analysis",
        cache_ttl_seconds=CACHE_TTL_TECH_ANALYSIS,
    )

    # Save full AI debug
    cost = result.get("_cost")
    if order_id:
        _save_ai_debug(order_id, None, 1, "ai_tech_analysis",
                        TECH_ANALYSIS_SYSTEM, user_prompt,
                        result.get("_raw", ""), result, cost=cost)

    error_detail = result.get("_error", "")
    if not result or "hosts" not in result:
        reason = error_detail or "Ungültige KI-Antwort"
        log.warning("ai_tech_analysis_fallback", reason=reason)
        return {}

    log.info("ai_tech_analysis_complete",
             hosts=len(result.get("hosts", {})))

    # Strip internal keys before return
    result.pop("_raw", None)
    result.pop("_cost", None)
    return result


# ---------------------------------------------------------------------------
# Phase 2 Config (after Phase 1, per host)
# ---------------------------------------------------------------------------

PHASE2_CONFIG_SYSTEM = """Du bist ein Security-Scanner-Orchestrator. Du konfigurierst Phase-2-Scan-Tools optimal basierend auf dem erkannten Tech-Stack eines Hosts.

ZAP-KONFIGURATION (OWASP ZAP Daemon):
- zap_scan_policy: "passive-only"|"waf-safe"|"standard"|"aggressive" (Default: "standard")
  - "passive-only": Kein Active Scan (WebCheck-Default, wird automatisch gesetzt)
  - "waf-safe": Reduzierte Intensität, langsamer — für Hosts hinter WAF
  - "standard": Gute Balance zwischen Coverage und Laufzeit (Default)
  - "aggressive": Alle Scan-Rules, hohe Intensität — nur bei verdächtigen Hosts
- zap_spider_max_depth: 3–7 (Default: 5). SPAs/JS-Heavy Apps: 6-7. Statische Seiten: 3.
- zap_ajax_spider_enabled: true für SPA-Frameworks (React, Vue, Angular, Next.js, Nuxt, Shopware 6), false sonst
- zap_active_categories: Aktivierte Active-Scan-Kategorien:
  - "sqli" — SQL Injection
  - "xss" — Cross-Site Scripting (reflected + stored)
  - "lfi" — Local File Inclusion / Path Traversal
  - "rfi" — Remote File Inclusion
  - "ssrf" — Server-Side Request Forgery
  - "cmdi" — Command Injection
  - "xxe" — XML External Entity
  - "crlf" — CRLF Injection
  Bei PHP-Servern: sqli, xss, lfi, rfi, cmdi
  Bei Java/Spring/Tomcat: sqli, xss, lfi, xxe, cmdi
  Bei Node.js/Express: xss, ssrf, cmdi, crlf
  Bei statischen Seiten: nur xss
- zap_rate_req_per_sec: 15–80 (Default: 80). Bei WAF: 15. Ohne WAF: 80.
- zap_threads: 2–5 (Default: 5). Bei WAF: 2. Ohne WAF: 5.
- zap_spider_delay_ms: 0–800 (Default: 0). Bei WAF: 800. Ohne WAF: 0.
- zap_extra_urls: [] — Zusätzliche URLs für offene Non-Standard-Ports (z.B. 8080, 8443, 9090)

WAF-SIGNAL → ZAP-DEFAULTS:
WAF erkannt (Cloudflare, Akamai, Sucuri, Imperva, F5 etc.):
→ zap_scan_policy: "waf-safe", zap_rate_req_per_sec: 15, zap_threads: 2, zap_spider_delay_ms: 800
Keine WAF:
→ zap_scan_policy: "standard" oder "aggressive", zap_rate_req_per_sec: 80, zap_threads: 5, zap_spider_delay_ms: 0

TOOLS DIE ÜBERSPRUNGEN WERDEN KÖNNEN:
feroxbuster, zap_ajax_spider

WANN feroxbuster ÜBERSPRINGEN:
- Große Webshops/CMS mit vielen Produktseiten (Shopware, Magento, WooCommerce mit >1000 Seiten) — ZAP Spider findet bereits umfangreiche URLs
- Hosts hinter aggressiver WAF (Cloudflare etc.) — feroxbuster erzeugt viele 403er ohne Mehrwert
- Reine API-Hosts ohne Web-Frontend

WICHTIG FÜR skip_tools:
- Für die Basisdomain und www-Subdomain: skip_tools MUSS IMMER leer sein []
- Für Hosts mit Web-Content (has_web=true) und kleinen/mittleren Seiten: skip_tools leer lassen
- skip_tools nur für reine API-Hosts, reine Mailserver, minimale Services, oder große Webshops (nur feroxbuster)
- Im Zweifel: skip_tools leer lassen — lieber ein Tool zu viel als wichtige Findings verpassen

REGELN:
- Bei WAF vorhanden: ZAP auf waf-safe setzen
- zap_ajax_spider_enabled=true nur wenn SPA/JS-Framework erkannt
- Bei WordPress: wpscan wird automatisch aktiviert

Antworte NUR mit validem JSON, kein anderer Text."""

PHASE2_CONFIG_SCHEMA = """{
  "zap_scan_policy": "standard",
  "zap_spider_max_depth": 5,
  "zap_ajax_spider_enabled": true,
  "zap_active_categories": ["sqli", "xss", "lfi", "ssrf"],
  "zap_rate_req_per_sec": 80,
  "zap_threads": 5,
  "zap_spider_delay_ms": 0,
  "zap_extra_urls": [],
  "skip_tools": [],
  "reasoning": "Kurze Begründung der Konfiguration"
}"""


def plan_phase2_config(
    tech_profile: dict[str, Any],
    host_inventory: dict[str, Any],
    package: str,
    order_id: str = "",
) -> dict[str, Any]:
    """Use Haiku to configure Phase 2 tools based on discovered tech stack."""

    # Build enriched input: tech profile + CMS details + Shodan services
    enriched_profile = {**tech_profile}

    # Include CMS fingerprinting details if available
    cms_details = tech_profile.get("cms_details", {})
    if cms_details:
        enriched_profile["cms_fingerprint"] = cms_details

    # Include Shodan service versions from host inventory (if available)
    ip = tech_profile.get("ip", "")
    hosts = host_inventory.get("hosts", [])
    for h in hosts:
        if h.get("ip") == ip:
            passive_intel = h.get("passive_intel", {})
            if passive_intel:
                enriched_profile["shodan_services"] = passive_intel.get("shodan_services", {})
                enriched_profile["abuseipdb_score"] = passive_intel.get("abuseipdb_score")
            break

    user_prompt = f"""Host Tech-Profile:
{json.dumps(enriched_profile, indent=2, ensure_ascii=False)}

Paket: {package}
Domain: {host_inventory.get("domain", "unknown")}

Konfiguriere die Phase-2-Tools optimal für diesen Host.
Antwort im Format:
{PHASE2_CONFIG_SCHEMA}"""

    result = _call_haiku(
        PHASE2_CONFIG_SYSTEM, user_prompt,
        cache_namespace="ki3_phase2_config",
        cache_ttl_seconds=CACHE_TTL_PHASE2_CONFIG,
    )

    # Save full AI debug
    cost = result.get("_cost")
    if order_id:
        _save_ai_debug(order_id, ip, 1, "ai_phase2_config",
                        PHASE2_CONFIG_SYSTEM, user_prompt,
                        result.get("_raw", ""), result, cost=cost)

    error_detail = result.get("_error", "")
    if not result or "zap_scan_policy" not in result:
        # Fallback: default config
        reason = error_detail or "Ungültige KI-Antwort"
        log.warning("ai_phase2_config_fallback", ip=tech_profile.get("ip"), reason=reason)
        return {
            "zap_scan_policy": "standard",
            "zap_spider_max_depth": 5,
            "zap_ajax_spider_enabled": False,
            "zap_active_categories": ["sqli", "xss", "lfi", "ssrf", "cmdi"],
            "zap_rate_req_per_sec": 80,
            "zap_threads": 5,
            "zap_spider_delay_ms": 0,
            "zap_extra_urls": [],
            "skip_tools": [],
            "reasoning": f"Fallback — {reason}",
        }

    log.info("ai_phase2_config_complete",
             ip=tech_profile.get("ip"),
             zap_policy=result.get("zap_scan_policy"),
             zap_ajax=result.get("zap_ajax_spider_enabled"),
             zap_categories=result.get("zap_active_categories"),
             skip_tools=result.get("skip_tools"))

    # Strip internal keys before return
    result.pop("_raw", None)
    result.pop("_cost", None)
    return result


# ---------------------------------------------------------------------------
# Sonnet client (for Phase 3 cross-tool reasoning)
# ---------------------------------------------------------------------------

def _call_sonnet(system_prompt: str, user_prompt: str, max_tokens: int = 16384,
                 cache_namespace: str = "sonnet_default",
                 cache_ttl_seconds: int = 24 * 3600) -> dict[str, Any]:
    """Cached Sonnet-Call mit temperature=0.

    Used for Phase 3 cross-tool correlation where Haiku's reasoning
    capability is insufficient.
    """
    raw = ""
    start = time.monotonic()
    response_dict, stats = cached_call(
        model=SONNET_MODEL,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
        temperature=0.0,
        max_tokens=max_tokens,
        cache_ttl_seconds=cache_ttl_seconds,
        cache_namespace=cache_namespace,
    )
    duration_ms = int((time.monotonic() - start) * 1000)

    if "_error" in response_dict:
        return {"_error": response_dict["_error"], "_raw": ""}

    raw = extract_text(response_dict)
    log.info("sonnet_response",
             namespace=cache_namespace,
             cache_hit=stats.hit,
             duration_ms=duration_ms,
             tokens=stats.output_tokens)

    text = _strip_markdown_fences(raw)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        log.error("sonnet_json_parse_error",
                  namespace=cache_namespace, error=str(e), raw=raw[:500])
        return {"_error": f"JSON-Parse-Fehler: {e}", "_raw": raw}

    parsed["_raw"] = raw
    parsed["_cost"] = _build_cost_dict(SONNET_MODEL, stats)
    return parsed


# ---------------------------------------------------------------------------
# Phase 3 Prioritization (after Phase 2, uses Sonnet)
# ---------------------------------------------------------------------------

PHASE3_SYSTEM = """Du bist ein Senior-Pentester. Du analysierst aggregierte Findings aus mehreren Security-Scanning-Tools.

DEINE EINZIGE AUFGABE:
Pro Finding einen Confidence-Score (0.0–1.0) und eine Liste der bestaetigenden Tools/Signale vergeben.

CONFIDENCE-REGELN:
- Gleiche CVE aus mehreren Tools  → 0.90 – 1.00
- ZAP-Finding + passende Service-Version aus nmap  → 0.85 – 0.95
- testssl + ZAP fuer gleiche TLS-Schwaeche  → 0.85 – 0.95
- wpscan + ZAP fuer gleiche WordPress-Schwaeche  → 0.85 – 0.95
- Nur ein Tool, kein zusaetzlicher Kontext  → 0.40 – 0.60
- Tool-Disagreement (z.B. ZAP meldet WordPress, Tech-Profile zeigt Shopware)  → 0.20 – 0.40

VERBOTEN (macht andere Stellen):
- KEINE False-Positive-Markierung — das macht der deterministische FP-Filter (fp_filter.py).
- KEINE Severity-Anpassung — das macht die Severity-Policy (severity_policy.py).
- KEINE Finding-Auswahl / Priorisierung — das macht selection.py.

Antworte NUR mit validem JSON, kein anderer Text."""

PHASE3_SCHEMA = """{
  "confidence_scores": [
    {
      "finding_ref": "tool:title  ODER  CVE-ID",
      "confidence": 0.95,
      "corroboration": ["nmap_version_match", "shodan_confirmed"],
      "reason": "Kurze Begruendung warum dieser Score"
    }
  ],
  "strategy_notes": "Kurze Zusammenfassung der Cross-Tool-Korrelation"
}"""


def plan_phase3_prioritization(
    finding_summary: list[dict[str, Any]],
    tech_profiles: list[dict[str, Any]],
    has_waf: bool = False,
    order_id: str = "",
) -> dict[str, Any]:
    """Use Sonnet to prioritize and correlate Phase 2 findings.

    Args:
        finding_summary: Condensed list of findings from all tools.
        tech_profiles: Tech profiles from Phase 1 (for version cross-checking).
        has_waf: Whether any host has a WAF detected.

    Returns:
        Prioritized finding list with confidence scores.
    """
    # Truncate finding summary to avoid excessive token usage
    summary_truncated = finding_summary[:100]

    user_prompt = f"""Phase-2 Scan-Ergebnisse ({len(finding_summary)} Findings, zeige die ersten {len(summary_truncated)}):

{json.dumps(summary_truncated, indent=2, ensure_ascii=False)}

Tech-Profiles der gescannten Hosts:
{json.dumps(tech_profiles, indent=2, ensure_ascii=False)}

WAF erkannt: {"Ja" if has_waf else "Nein"}

Vergib pro Finding einen Confidence-Score und liste die bestaetigenden Tools/Signale.
Antwort im Format:
{PHASE3_SCHEMA}"""

    result = _call_sonnet(
        PHASE3_SYSTEM, user_prompt,
        cache_namespace="ki4_phase3",
        cache_ttl_seconds=CACHE_TTL_PHASE3,
    )

    # Save full AI debug
    cost = result.get("_cost")
    if order_id:
        _save_ai_debug(order_id, None, 3, "ai_phase3_prioritization",
                        PHASE3_SYSTEM, user_prompt,
                        result.get("_raw", ""), result, cost=cost)

    error_detail = result.get("_error", "")
    if not result or "confidence_scores" not in result:
        reason = error_detail or "Ungültige KI-Antwort"
        log.warning("ai_phase3_fallback", reason=reason)
        return {
            "confidence_scores": [],
            "strategy_notes": f"Fallback: programmatische Korrelation ({reason})",
        }

    n = len(result.get("confidence_scores", []))
    log.info("ai_phase3_complete", confidence_scores=n)

    # Strip internal keys before return
    result.pop("_raw", None)
    result.pop("_cost", None)
    return result

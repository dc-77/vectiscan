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

log = structlog.get_logger()

HAIKU_MODEL = "claude-haiku-4-5-20251001"
SONNET_MODEL = "claude-sonnet-4-6"

AI_PRICING: dict[str, dict[str, float]] = {
    "claude-haiku-4-5-20251001": {"input": 1.0, "output": 5.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-opus-4-6": {"input": 15.0, "output": 75.0},
}


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

def _call_haiku(system_prompt: str, user_prompt: str) -> dict[str, Any]:
    """Call Claude Haiku and return parsed JSON response.

    On failure, returns {"_error": "reason"} so callers can include the
    specific error in fallback reasoning shown to the user.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        log.warning("ai_strategy_no_api_key", msg="ANTHROPIC_API_KEY not set, skipping AI strategy")
        return {"_error": "ANTHROPIC_API_KEY nicht gesetzt"}

    raw = ""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)

        start = time.monotonic()
        response = client.messages.create(
            model=HAIKU_MODEL,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        duration_ms = int((time.monotonic() - start) * 1000)

        raw = response.content[0].text
        log.info("haiku_response", duration_ms=duration_ms, tokens=response.usage.output_tokens)

        # Cost tracking
        prices = AI_PRICING.get(HAIKU_MODEL, {"input": 1.0, "output": 5.0})
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        cost = round((input_tokens / 1_000_000) * prices["input"] + (output_tokens / 1_000_000) * prices["output"], 4)

        # Strip markdown code fences if present
        text = raw.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        parsed = json.loads(text)
        parsed["_raw"] = raw  # Preserve raw response for debug transparency
        parsed["_cost"] = {
            "model": HAIKU_MODEL,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_cost_usd": cost,
        }
        return parsed

    except json.JSONDecodeError as e:
        log.error("haiku_json_parse_error", error=str(e), raw=raw[:500])
        return {"_error": f"JSON-Parse-Fehler: {e}", "_raw": raw}
    except Exception as e:
        log.error("haiku_call_error", error=str(e))
        return {"_error": f"API-Fehler: {e}", "_raw": raw}


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

    result = _call_haiku(HOST_STRATEGY_SYSTEM, user_prompt)

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

    result = _call_haiku(TECH_ANALYSIS_SYSTEM, user_prompt)

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

NUCLEI-KONFIGURATION:
Der Tag "default-login" wird automatisch hinzugefügt. Verwende tech-spezifische Tags für CVE-Erkennung (z.B. "wordpress", "nginx", "apache").
WICHTIG: Verwende NICHT den Tag "cve" — er matcht 3000+ Templates und verursacht Timeouts.

VERFÜGBARE NUCLEI-TAGS (wichtigste):
wordpress, apache, nginx, iis, php, java, python, nodejs, rails, laravel, django, spring, tomcat, jboss, weblogic, coldfusion, drupal, joomla, magento, shopify, shopware, prestashop, struts, network, ssl, dns, tech, token, sqli, xss, lfi, rfi, ssrf, redirect, upload

CMS-SPEZIFISCHE NUCLEI-TAG-EMPFEHLUNGEN:
- WordPress     → nuclei_tags: ["wordpress", "wp-plugin", "wp-theme"]
- Shopware 5/6  → nuclei_tags: ["shopware", "php"]
- TYPO3         → nuclei_tags: ["typo3", "php"]
- Joomla        → nuclei_tags: ["joomla", "php"]
- Drupal        → nuclei_tags: ["drupal", "php"]
- Contao        → nuclei_tags: ["php"]
- Magento       → nuclei_tags: ["magento", "php", "token"]
- Strapi        → nuclei_tags: ["nodejs", "api"]
- Ghost         → nuclei_tags: ["nodejs"]
Wenn kein CMS erkannt: → Standard-Tags basierend auf Tech-Stack (Apache/nginx/PHP/Node)
Wenn WordPress erkannt: → wpscan wird automatisch aktiviert

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
gowitness, zap_ajax_spider

WICHTIG FÜR skip_tools:
- Für die Basisdomain und www-Subdomain: skip_tools MUSS IMMER leer sein []
- Für Hosts mit Web-Content (has_web=true): skip_tools MUSS leer sein []
- skip_tools nur für reine API-Hosts (kein HTML), reine Mailserver, oder minimale Services
- Im Zweifel: skip_tools leer lassen — lieber ein Tool zu viel als wichtige Findings verpassen

REGELN:
- Nuclei-Tags sollten zur erkannten Technologie passen
- Bei WordPress: "wordpress" Tag
- Bei Shopware: "shopware" Tag
- Bei API-Hosts: token Tags für nuclei
- Bei WAF vorhanden: "dos" und "fuzz" für nuclei ausschließen, ZAP auf waf-safe setzen
- zap_ajax_spider_enabled=true nur wenn SPA/JS-Framework erkannt

WICHTIG FÜR NUCLEI-TAGS (Performance):
- Verwende NIEMALS den Tag "cve" allein — das matcht 3000+ Templates und dauert zu lange
- Stattdessen: technologie-spezifische Tags wie "apache", "nginx", "wordpress", "shopware"
- Kombiniere maximal 5-7 Tags für optimale Laufzeit
- Der Tag "default-login" wird automatisch ergänzt
- Gute Kombination: ["tech-spezifisch", "ssl", "token"]
- Schlechte Kombination: ["cve", "network", "dns"] — viel zu breit, Timeout garantiert

Antworte NUR mit validem JSON, kein anderer Text."""

PHASE2_CONFIG_SCHEMA = """{
  "nuclei_tags": ["tag1", "tag2"],
  "nuclei_exclude_tags": ["dos", "fuzz"],
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

    result = _call_haiku(PHASE2_CONFIG_SYSTEM, user_prompt)

    # Save full AI debug
    cost = result.get("_cost")
    if order_id:
        _save_ai_debug(order_id, ip, 1, "ai_phase2_config",
                        PHASE2_CONFIG_SYSTEM, user_prompt,
                        result.get("_raw", ""), result, cost=cost)

    error_detail = result.get("_error", "")
    if not result or "nuclei_tags" not in result:
        # Fallback: default config (all tools, all templates)
        reason = error_detail or "Ungültige KI-Antwort"
        log.warning("ai_phase2_config_fallback", ip=tech_profile.get("ip"), reason=reason)
        return {
            "nuclei_tags": [],
            "nuclei_exclude_tags": ["dos", "fuzz"],
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
             nuclei_tags=result.get("nuclei_tags"),
             zap_policy=result.get("zap_scan_policy"),
             zap_ajax=result.get("zap_ajax_spider_enabled"),
             zap_categories=result.get("zap_active_categories"))

    # Strip internal keys before return
    result.pop("_raw", None)
    result.pop("_cost", None)
    return result


# ---------------------------------------------------------------------------
# Sonnet client (for Phase 3 cross-tool reasoning)
# ---------------------------------------------------------------------------

def _call_sonnet(system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> dict[str, Any]:
    """Call Claude Sonnet for complex reasoning tasks.

    Used for Phase 3 cross-tool correlation where Haiku's reasoning
    capability is insufficient.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        log.warning("ai_sonnet_no_api_key")
        return {"_error": "ANTHROPIC_API_KEY nicht gesetzt"}

    raw = ""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)

        start = time.monotonic()
        response = client.messages.create(
            model=SONNET_MODEL,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        duration_ms = int((time.monotonic() - start) * 1000)

        raw = response.content[0].text
        log.info("sonnet_response", duration_ms=duration_ms,
                 tokens=response.usage.output_tokens)

        # Cost tracking
        prices = AI_PRICING.get(SONNET_MODEL, {"input": 3.0, "output": 15.0})
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        cost = round((input_tokens / 1_000_000) * prices["input"] + (output_tokens / 1_000_000) * prices["output"], 4)

        # Strip markdown code fences if present
        text = raw.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        parsed = json.loads(text)
        parsed["_raw"] = raw
        parsed["_cost"] = {
            "model": SONNET_MODEL,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_cost_usd": cost,
        }
        return parsed

    except json.JSONDecodeError as e:
        log.error("sonnet_json_parse_error", error=str(e), raw=raw[:500])
        return {"_error": f"JSON-Parse-Fehler: {e}", "_raw": raw}
    except Exception as e:
        log.error("sonnet_call_error", error=str(e))
        return {"_error": f"API-Fehler: {e}", "_raw": raw}


# ---------------------------------------------------------------------------
# Phase 3 Prioritization (after Phase 2, uses Sonnet)
# ---------------------------------------------------------------------------

PHASE3_SYSTEM = """Du bist ein Senior-Pentester der Findings aus verschiedenen Security-Scanning-Tools analysiert.

AUFGABE:
Analysiere die aggregierten Findings und entscheide:
1. Welche Findings haben hohe Konfidenz? (von mehreren Tools bestätigt, Version passt)
2. Welche Findings haben niedrige Konfidenz? (nur ein Tool, kein Kontext)
3. Welche Findings sind wahrscheinlich False Positives? (Version-Mismatch, WAF-Artefakt, CMS-Mismatch)

KONFIDENZ-REGELN:
- Gleiche CVE aus mehreren Tools → hohe Konfidenz
- nuclei-Finding + passende Service-Version aus nmap → hohe Konfidenz
- nikto-only Finding hinter WAF → niedrige Konfidenz
- nuclei-Finding für falsche Technologie (z.B. WordPress-Template auf Shopware-Site) → False Positive
- testssl-Finding + nuclei-SSL-Finding → merge zu einem Finding

PRIORISIERUNG:
- Findings mit CVSS ≥ 9.0 → immer "high" Priorität
- Findings mit aktiven Exploits → immer "high" Priorität
- Informational-Findings ohne Sicherheitswert → "low" Priorität

Antworte NUR mit validem JSON, kein anderer Text."""

PHASE3_SCHEMA = """{
  "high_confidence_findings": [
    {
      "finding_ref": "tool:title or CVE-ID",
      "confidence": 0.95,
      "corroboration": ["tool1_match", "version_confirmed"],
      "enrich_priority": "high"
    }
  ],
  "low_confidence_findings": [
    {
      "finding_ref": "tool:title or CVE-ID",
      "confidence": 0.3,
      "reason": "Nur ein Tool, keine Bestätigung",
      "enrich_priority": "low"
    }
  ],
  "potential_false_positives": [
    {
      "finding_ref": "tool:title or CVE-ID",
      "reason": "Version-Mismatch: Finding für nginx 1.18, aber nmap erkennt 1.24"
    }
  ],
  "strategy_notes": "Zusammenfassung der Korrelationsanalyse"
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

Analysiere die Findings: Welche sind echt, welche sind False Positives?
Antwort im Format:
{PHASE3_SCHEMA}"""

    result = _call_sonnet(PHASE3_SYSTEM, user_prompt)

    # Save full AI debug
    cost = result.get("_cost")
    if order_id:
        _save_ai_debug(order_id, None, 3, "ai_phase3_prioritization",
                        PHASE3_SYSTEM, user_prompt,
                        result.get("_raw", ""), result, cost=cost)

    error_detail = result.get("_error", "")
    if not result or "high_confidence_findings" not in result:
        reason = error_detail or "Ungültige KI-Antwort"
        log.warning("ai_phase3_fallback", reason=reason)
        return {
            "high_confidence_findings": [],
            "low_confidence_findings": [],
            "potential_false_positives": [],
            "strategy_notes": f"Fallback: programmatische Korrelation ({reason})",
        }

    high = len(result.get("high_confidence_findings", []))
    low = len(result.get("low_confidence_findings", []))
    fp = len(result.get("potential_false_positives", []))
    log.info("ai_phase3_complete", high=high, low=low, fp=fp)

    # Strip internal keys before return
    result.pop("_raw", None)
    result.pop("_cost", None)
    return result

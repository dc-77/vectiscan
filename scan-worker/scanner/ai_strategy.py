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
            max_tokens=2048,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        duration_ms = int((time.monotonic() - start) * 1000)

        raw = response.content[0].text
        log.info("haiku_response", duration_ms=duration_ms, tokens=response.usage.output_tokens)

        # Strip markdown code fences if present
        text = raw.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        return json.loads(text)

    except json.JSONDecodeError as e:
        log.error("haiku_json_parse_error", error=str(e), raw=raw[:500])
        return {"_error": f"JSON-Parse-Fehler: {e}"}
    except Exception as e:
        log.error("haiku_call_error", error=str(e))
        return {"_error": f"API-Fehler: {e}"}


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

    return result


# ---------------------------------------------------------------------------
# Phase 2 Config (after Phase 1, per host)
# ---------------------------------------------------------------------------

PHASE2_CONFIG_SYSTEM = """Du bist ein Security-Scanner-Orchestrator. Du konfigurierst Phase-2-Scan-Tools optimal basierend auf dem erkannten Tech-Stack eines Hosts.

NUCLEI-KONFIGURATION:
Die Tags "cve" und "default-login" werden automatisch hinzugefügt — du gibst nur die tech-spezifischen Tags an.
Misconfig und Exposure werden von OWASP ZAP abgedeckt — nur bei Bedarf als nuclei-Tag.

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
- zap_forced_browse_enabled: true (Default). false bei WAF (wird geblockt).
- zap_forced_browse_wordlist: "common"|"wordpress"|"api-rest"|"java-spring" (Default: "common")
  - "wordpress": wp-admin, plugins, uploads
  - "api-rest": swagger, graphql, /api/v1, actuator
  - "java-spring": actuator, /api/v1, /manage
  - "common": generische Pfade
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
→ zap_scan_policy: "waf-safe", zap_rate_req_per_sec: 15, zap_threads: 2, zap_spider_delay_ms: 800, zap_forced_browse_enabled: false
Keine WAF:
→ zap_scan_policy: "standard" oder "aggressive", zap_rate_req_per_sec: 80, zap_threads: 5, zap_spider_delay_ms: 0, zap_forced_browse_enabled: true

TOOLS DIE ÜBERSPRUNGEN WERDEN KÖNNEN:
gowitness, zap_ajax_spider, zap_forced_browse

WICHTIG FÜR skip_tools:
- Für die Basisdomain und www-Subdomain: skip_tools MUSS IMMER leer sein []
- Für Hosts mit Web-Content (has_web=true): skip_tools MUSS leer sein []
- skip_tools nur für reine API-Hosts (kein HTML), reine Mailserver, oder minimale Services
- Im Zweifel: skip_tools leer lassen — lieber ein Tool zu viel als wichtige Findings verpassen

REGELN:
- Nuclei-Tags sollten zur erkannten Technologie passen
- Bei WordPress: "wordpress" Tag + wordpress Wordlist für ZAP Forced Browse
- Bei Shopware: "shopware" Tag
- Bei API-Hosts: api-rest Wordlist für ZAP Forced Browse, token Tags für nuclei
- Bei WAF vorhanden: "dos" und "fuzz" für nuclei ausschließen, ZAP auf waf-safe setzen
- zap_ajax_spider_enabled=true nur wenn SPA/JS-Framework erkannt

WICHTIG FÜR NUCLEI-TAGS (Performance):
- Verwende NIEMALS den Tag "cve" allein — das matcht 3000+ Templates und dauert zu lange
- Stattdessen: technologie-spezifische Tags wie "apache", "nginx", "wordpress", "shopware"
- Kombiniere maximal 5-7 Tags für optimale Laufzeit
- Die Tags "cve" und "default-login" werden automatisch ergänzt
- Gute Kombination: ["tech-spezifisch", "ssl", "token"]
- Schlechte Kombination: ["cve", "network", "dns"] — viel zu breit, Timeout garantiert

Antworte NUR mit validem JSON, kein anderer Text."""

PHASE2_CONFIG_SCHEMA = """{
  "nuclei_tags": ["tag1", "tag2"],
  "nuclei_exclude_tags": ["dos", "fuzz", "misconfig", "exposure"],
  "zap_scan_policy": "standard",
  "zap_spider_max_depth": 5,
  "zap_ajax_spider_enabled": true,
  "zap_forced_browse_enabled": true,
  "zap_forced_browse_wordlist": "common",
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

    error_detail = result.get("_error", "")
    if not result or "nuclei_tags" not in result:
        # Fallback: default config (all tools, all templates)
        reason = error_detail or "Ungültige KI-Antwort"
        log.warning("ai_phase2_config_fallback", ip=tech_profile.get("ip"), reason=reason)
        return {
            "nuclei_tags": [],
            "nuclei_exclude_tags": ["dos", "fuzz", "misconfig", "exposure"],
            "zap_scan_policy": "standard",
            "zap_spider_max_depth": 5,
            "zap_ajax_spider_enabled": False,
            "zap_forced_browse_enabled": True,
            "zap_forced_browse_wordlist": "common",
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

        # Strip markdown code fences if present
        text = raw.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()

        return json.loads(text)

    except json.JSONDecodeError as e:
        log.error("sonnet_json_parse_error", error=str(e), raw=raw[:500])
        return {"_error": f"JSON-Parse-Fehler: {e}"}
    except Exception as e:
        log.error("sonnet_call_error", error=str(e))
        return {"_error": f"API-Fehler: {e}"}


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

    return result

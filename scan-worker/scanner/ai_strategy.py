"""AI-powered scan strategy — uses Haiku for host prioritization and tool configuration."""

from __future__ import annotations

import json
import os
import time
from typing import Any

import structlog

log = structlog.get_logger()

HAIKU_MODEL = "claude-haiku-4-5-20251001"

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

HOST_STRATEGY_SYSTEM = """Du bist ein Security-Scanner-Orchestrator. Du entscheidest, welche Hosts gescannt werden.

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

REGELN:
- Basisdomain und www-Subdomain: IMMER scannen (action: "scan"), höchste Priorität
- Webserver mit interaktivem Content (Apps, APIs, CMS, Shops): scan (hohe Priorität)
- Mailserver (MX, SMTP, IMAP): scan mit NIEDRIGERER Priorität — NICHT skippen!
  → Mailserver haben eigene Schwachstellen: offene Relays, veraltetes TLS,
    SMTP-Auth-Brute-Force, exponierte IMAP/POP3-Ports
  → Bei reinen Mailservern reichen testssl + nmap, kein Nuclei/Gobuster nötig
- Autodiscover-Hosts (nur Exchange/Outlook-Konfiguration): skip (einzige Ausnahme)
- Parking-Pages, Redirect auf externe Domain: skip
- CDN-Edge-Nodes (nur CDN-IP, kein eigener Content): skip
- Wenn unklar: lieber scannen als überspringen

Jeder Host braucht eine kurze Begründung (1 Satz).
Priority: 1 = höchste Priorität, aufsteigend.

Antworte NUR mit validem JSON, kein anderer Text."""

HOST_STRATEGY_SCHEMA = """{
  "hosts": [
    {"ip": "...", "action": "scan|skip", "priority": 1, "reasoning": "..."}
  ],
  "strategy_notes": "Kurze Zusammenfassung der Strategie"
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

VERFÜGBARE NUCLEI-TAGS (wichtigste):
wordpress, apache, nginx, iis, php, java, python, nodejs, rails, laravel, django, spring, tomcat, jboss, weblogic, coldfusion, drupal, joomla, magento, shopify, shopware, prestashop, struts, exposure, network, ssl, dns, cve, default-login, misconfig, tech, token, sqli, xss, lfi, rfi, ssrf, redirect, upload

NIKTO-TUNING-KATEGORIEN:
1=Interesting File, 2=Misconfiguration, 3=Information Disclosure, 4=Injection (XSS/Script), 5=Remote File Retrieval, 6=Denial of Service, 7=Remote File Retrieval (Server Wide), 8=Command Execution, 9=SQL Injection, 0=File Upload

GOBUSTER-WORDLISTS:
- "common" — Generische Pfade (Standard)
- "wordpress" — WordPress-spezifische Pfade (wp-admin, plugins, uploads)
- "api" — API-Endpunkte (swagger, graphql, /api/v1, actuator)
- "cms" — CMS-Admin-Panels und typische CMS-Pfade

TOOLS DIE ÜBERSPRUNGEN WERDEN KÖNNEN:
katana (Crawler — unnötig bei einfachen Seiten oder bekanntem CMS)
gowitness (Screenshot — unnötig bei reinen API-Hosts)

REGELN:
- Nuclei-Tags sollten zur erkannten Technologie passen
- Immer "exposure" und "misconfig" als Tags einschließen
- Bei WordPress: "wordpress" Tag UND wordpress Wordlist
- Bei Shopware: "shopware" Tag UND cms Wordlist
- Bei API-Hosts: "api" Wordlist, exposure + token Tags
- Bei WAF vorhanden: "dos" und "fuzz" ausschließen (werden geblockt)
- nikto_tuning auf relevante Kategorien beschränken

WICHTIG FÜR NUCLEI-TAGS (Performance):
- Verwende NIEMALS den Tag "cve" allein — das matcht 3000+ Templates und dauert zu lange
- Stattdessen: technologie-spezifische Tags wie "apache", "nginx", "wordpress", "shopware"
- Kombiniere maximal 5-7 Tags für optimale Laufzeit
- Die Tags "exposure" und "misconfig" sind effizient (wenige Templates, hoher Ertrag)
- Gute Kombination: ["exposure", "misconfig", "tech-spezifisch", "ssl", "default-login"]
- Schlechte Kombination: ["cve", "network", "dns"] — viel zu breit, Timeout garantiert

Antworte NUR mit validem JSON, kein anderer Text."""

PHASE2_CONFIG_SCHEMA = """{
  "nuclei_tags": ["tag1", "tag2"],
  "nuclei_exclude_tags": ["dos", "fuzz"],
  "nikto_tuning": "1,2,3,4",
  "gobuster_wordlist": "common|wordpress|api|cms",
  "skip_tools": [],
  "reasoning": "Kurze Begründung der Konfiguration"
}"""


def plan_phase2_config(
    tech_profile: dict[str, Any],
    host_inventory: dict[str, Any],
    package: str,
) -> dict[str, Any]:
    """Use Haiku to configure Phase 2 tools based on discovered tech stack."""
    user_prompt = f"""Host Tech-Profile:
{json.dumps(tech_profile, indent=2, ensure_ascii=False)}

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
            "nuclei_exclude_tags": [],
            "nikto_tuning": "1234567890",
            "gobuster_wordlist": "common",
            "skip_tools": [],
            "reasoning": f"Fallback — {reason}"
        }

    log.info("ai_phase2_config_complete",
             ip=tech_profile.get("ip"),
             nuclei_tags=result.get("nuclei_tags"),
             wordlist=result.get("gobuster_wordlist"))

    return result

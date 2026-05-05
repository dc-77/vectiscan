"""KI-Fallback-Mapper fuer finding_types die nicht durch Regex-Patterns
gemappt werden (B2).

Wenn `finding_type_mapper.map_finding_type()` `None` zurueckgibt → Haiku
wird mit Liste der ~50 verfuegbaren finding_types befragt: "Welcher
finding_type passt am besten zu diesem Title+Description?".

Cache: namespace `reporter_v1_finding_type_fallback`, content_hash ueber
normalisierten title + cwe + erste 200 chars description, TTL 30 Tage
(Mappings sind stabil, aendern sich nur bei Pattern-Updates).

Bei API-Fehler oder unklarem KI-Output: None zurueckgeben → Caller
faellt auf SP-FALLBACK zurueck (heutiges Verhalten).
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional

log = logging.getLogger(__name__)

# Modul-Level-Imports fuer Mockability in Tests. Bei Import-Fehler werden
# die Symbole auf None gesetzt und der Mapper laeuft ohne Cache.
try:
    from reporter.ai_cache import (
        cache_key, get_cached_response, set_cached_response,
        compute_content_hash,
    )
except Exception:
    cache_key = None  # type: ignore
    get_cached_response = None  # type: ignore
    set_cached_response = None  # type: ignore
    compute_content_hash = None  # type: ignore

HAIKU_MODEL = "claude-haiku-4-5-20251001"
CACHE_NAMESPACE = "reporter_v1_finding_type_fallback"
CACHE_TTL_SECONDS = 30 * 24 * 3600  # 30 Tage

# Liste der bekannten finding_types mit Kurzbeschreibung — wird in den
# System-Prompt eingebettet, damit die KI weiss aus welchem festen
# Vokabular sie waehlen darf.
FINDING_TYPE_CATALOG: dict[str, str] = {
    "database_port_exposed":      "Datenbank-Port (3306, 5432, 1433, 27017, 6379) oeffentlich erreichbar",
    "cors_misconfiguration":      "CORS-Header zu permissiv (z.B. Access-Control-Allow-Origin: *)",
    "js_library_vulnerable":      "Veraltete JavaScript-Bibliothek mit bekannter Schwachstelle",
    "private_ip_disclosure":      "Interne RFC1918-IP-Adresse im Response sichtbar",
    "sri_missing":                "Subresource-Integrity (SRI) auf externen Skripten fehlt",
    "wordpress_plugin_vulnerability": "Bekannte Schwachstelle in WordPress-Plugin",
    "wordpress_user_enumeration": "WordPress-User-Enumeration moeglich (z.B. /wp-json/wp/v2/users)",
    "user_enumeration":           "User-Enumeration generisch (Login-Formular reagiert unterschiedlich)",
    "env_file_exposed":           ".env-Datei oeffentlich erreichbar",
    "git_directory_exposed":      ".git-Verzeichnis oeffentlich erreichbar",
    "phpinfo_exposed":            "phpinfo()-Endpoint oeffentlich erreichbar",
    "directory_listing_enabled":  "Directory-Listing aktiv",
    "error_message_with_stack":   "Stacktrace/Pfad in Fehlerseite sichtbar",
    "nginx_status_endpoint_open": "Nginx-Status-Endpoint oeffentlich",
    "server_banner_with_version": "Server-Banner mit Versionsinformation",
    "server_banner_no_version":   "Server-Banner ohne Versionsinformation",
    "cookie_no_secure":           "Cookie ohne Secure-Flag",
    "cookie_no_httponly":         "Cookie ohne HttpOnly-Flag",
    "cookie_no_samesite":         "Cookie ohne SameSite-Attribut",
    "csp_unsafe_inline":          "CSP enthaelt unsafe-inline",
    "csp_unsafe_eval":            "CSP enthaelt unsafe-eval",
    "csp_wildcard_source":        "CSP enthaelt Wildcard-Quelle (*)",
    "csp_missing":                "Content-Security-Policy fehlt",
    "hsts_preload_missing":       "HSTS-Preload-Eintrag fehlt",
    "hsts_no_includesubdomains":  "HSTS ohne includeSubDomains",
    "hsts_short_maxage":          "HSTS max-age zu kurz (<6 Monate)",
    "hsts_missing":               "HSTS-Header fehlt",
    "xcto_missing":               "X-Content-Type-Options fehlt",
    "xfo_missing":                "X-Frame-Options fehlt (Clickjacking-Schutz)",
    "referrer_policy_missing":    "Referrer-Policy fehlt",
    "permissions_policy_missing": "Permissions-Policy fehlt",
    "csrf_token_missing":         "Anti-CSRF-Token fehlt auf state-aenderndem Formular",
    "ssh_no_brute_force_protection": "SSH-Dienst ohne Brute-Force-Schutz",
    "tls_below_tr03116_minimum":  "TLS-Konfiguration unter BSI-TR-03116-Mindeststandard",
    "tls_weak_cipher_suites":     "Schwache TLS-Cipher-Suites aktiviert",
    "tls_no_pfs":                 "Kein Perfect Forward Secrecy",
    "tls_certificate_expired":    "TLS-Zertifikat abgelaufen",
    "tls_certificate_expiring_30d": "TLS-Zertifikat laeuft in <30 Tagen ab",
    "tls_self_signed":            "Selbstsigniertes TLS-Zertifikat",
    "dnssec_chain_broken":        "DNSSEC-Kette unterbrochen",
    "dnssec_missing":             "DNSSEC fehlt fuer Domain",
    "caa_missing":                "CAA-Record fehlt",
    "spf_softfail":               "SPF-Policy auf softfail (~all)",
    "spf_missing":                "SPF-Record fehlt",
    "dmarc_p_quarantine":         "DMARC-Policy auf quarantine (statt reject)",
    "dmarc_p_none":               "DMARC-Policy auf none (Reporting only, kein Enforcement)",
    "dmarc_missing":              "DMARC-Record fehlt",
    "dkim_missing":               "DKIM-Record fehlt",
    "mta_sts_missing":            "MTA-STS-Policy fehlt",
    "software_eol":               "Eingesetzte Software ist End-of-Life ohne Sicherheitsupdates",
}


def _normalize_for_cache(title: str, description: str, cwe: str | None = None) -> str:
    """Normalisierter Hash-Input — case-insensitiv, kollabierte Whitespaces."""
    import re
    parts = [title or "", (description or "")[:200], cwe or ""]
    s = " | ".join(p.strip().lower() for p in parts)
    return re.sub(r"\s+", " ", s)


def _build_system_prompt() -> str:
    types_list = "\n".join(
        f"  - {name}: {desc}" for name, desc in FINDING_TYPE_CATALOG.items()
    )
    return f"""Du bist ein Security-Findings-Klassifikator. Aufgabe:
Ordne den gegebenen Befund (Title + Description) GENAU einem der unten
gelisteten finding_types zu. Du MUSST aus dieser Liste waehlen oder
"unknown" zurueckgeben.

Verfuegbare finding_types:
{types_list}

Antworte NUR mit validem JSON:
{{"finding_type": "<einer der oben gelisteten>|unknown", "confidence": 0.0-1.0, "reason": "kurze Begruendung"}}
"""


def map_finding_type_via_ai(finding: dict[str, Any]) -> Optional[str]:
    """KI-basierter Fallback-Mapper. Returns finding_type-String oder None.

    Wird nur aufgerufen wenn Regex-Mapping kein Ergebnis lieferte.
    """
    title = (finding.get("title") or "").strip()
    description = (finding.get("description") or "").strip()
    cwe = (finding.get("cwe") or "").strip()

    if not title:
        return None

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        log.debug("ai_finding_type_fallback_no_api_key")
        return None

    cache_k: Optional[str] = None
    if cache_key and compute_content_hash:
        ch = compute_content_hash(_normalize_for_cache(title, description, cwe))
        cache_k = cache_key(
            model=HAIKU_MODEL, system="", messages=[],
            namespace=CACHE_NAMESPACE, content_hash=ch,
        )
        if get_cached_response:
            cached = get_cached_response(cache_k)
            if cached and cached.get("response_text"):
                try:
                    parsed = json.loads(cached["response_text"])
                    ft = parsed.get("finding_type")
                    if ft and ft in FINDING_TYPE_CATALOG:
                        log.info("ai_finding_type_cache_hit type=%s", ft)
                        return ft
                except Exception:
                    pass

    # Live-Call
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        system_prompt = _build_system_prompt()
        user_prompt = (
            f"TITLE: {title[:300]}\n\n"
            f"DESCRIPTION: {description[:600]}\n\n"
            f"CWE: {cwe or '—'}\n\n"
            "Welcher finding_type passt?"
        )
        start = time.monotonic()
        response = client.messages.create(
            model=HAIKU_MODEL,
            max_tokens=200,
            temperature=0.0,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
        if raw.endswith("```"):
            raw = raw.rsplit("```", 1)[0]
        parsed = json.loads(raw.strip())

        ft = parsed.get("finding_type")
        if ft == "unknown" or ft not in FINDING_TYPE_CATALOG:
            log.info("ai_finding_type_no_match title=%r duration_ms=%d",
                     title[:60], duration_ms)
            # Cache auch das Negativ-Ergebnis (verhindert wiederholte API-Calls)
            if cache_k and set_cached_response:
                try:
                    set_cached_response(
                        cache_k,
                        response_text=raw,
                        model=HAIKU_MODEL,
                        input_tokens=getattr(response.usage, "input_tokens", 0),
                        output_tokens=getattr(response.usage, "output_tokens", 0),
                        cache_ttl_seconds=CACHE_TTL_SECONDS,
                    )
                except Exception:
                    pass
            return None

        log.info("ai_finding_type_mapped type=%s confidence=%s duration_ms=%d title=%r",
                 ft, parsed.get("confidence"), duration_ms, title[:60])

        # Cache speichern
        if cache_k and set_cached_response:
            try:
                set_cached_response(
                    cache_k,
                    response_text=raw,
                    model=HAIKU_MODEL,
                    input_tokens=getattr(response.usage, "input_tokens", 0),
                    output_tokens=getattr(response.usage, "output_tokens", 0),
                    cache_ttl_seconds=CACHE_TTL_SECONDS,
                )
            except Exception as e:
                log.warning("ai_finding_type_cache_set_failed err=%s", e)

        return ft

    except Exception as e:
        log.warning("ai_finding_type_fallback_failed err=%s title=%r",
                    str(e)[:200], title[:60])
        return None

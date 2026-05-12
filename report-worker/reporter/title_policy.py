"""Deterministische Title-Templates pro policy_id.

Die KI #5 (Reporter) formuliert Titel heute frei -> derselbe Befund erscheint
in 3-4 Wording-Variationen ueber wiederholte Scans (z.B. "DMARC-Policy auf
'quarantine' statt 'reject'" vs "DMARC-Policy auf Quarantine statt Reject").

Loesung: TITLE_TEMPLATES bietet pro policy_id ein deterministisches deutsches
Template mit Platzhaltern. Die KI liefert weiterhin `title_vars: dict` (z.B.
{p_value: "quarantine"}) — der finale Title wird durch das Template gebaut.

Bei fehlendem Template: KI-Title bleibt erhalten, Flag `_title_template_missing`
fuer QA-Check + Frontend-Hinweis.

Stand 2026-05-05: ~64 Templates (deckt ~70% der haeufigsten Findings).
Smart-Fallback (A2): Vars wie cookie_name/private_ip/tech/port werden aus
evidence/description/affected/tech_profiles abgeleitet wenn KI sie nicht
explizit liefert. Sicherheitsnetz (A1): wenn der gerenderte Title `?`
enthaelt aber der KI-Original keine Luecke hat → KI-Original gewinnt.

M2 Track 2b (Mai 2026, P0-01/03/04/05):
- Service-spezifische Banner-Templates (info_disclosure_banner_ssh/http/...)
- Service-spezifische Mail-Security-Templates (mail_security_missing_spf/dkim/...)
- Erweiterte host-Fallback-Kette (affected, affected_hosts, tech_profiles, ...)
- TitleVarFallbackError + _title_degraded fuer "harte" Hosts-Luecken
- Title-Token-Linter: nackte Zahlen (z.B. "Plugin 27") werden erkannt
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


# A2 Smart-Fallback Pattern (kompiliert one-time)
_RFC1918_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)
_COOKIE_NAME_RE = re.compile(
    r"(?:Set-Cookie|cookie\s*name|cookie[:=]\s*)\s*[:\"']?\s*([A-Za-z_][A-Za-z0-9_-]{1,40})",
    re.IGNORECASE,
)
_PORT_RE = re.compile(r":(\d{1,5})\b")
_VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3}(?:[a-z]\d?)?)")
_CSP_DIRECTIVE_RE = re.compile(
    r"\b(default-src|script-src|style-src|img-src|connect-src|font-src|"
    r"frame-ancestors|base-uri|form-action|object-src|media-src|child-src|"
    r"manifest-src|worker-src|frame-src)\b"
)
_PLUGIN_NAME_RE = re.compile(
    r"(?:plugin|theme)[:\s]+['\"]?([A-Za-z0-9_-]{2,40})", re.IGNORECASE,
)
_LIBRARY_NAME_RE = re.compile(
    r"\b(jQuery|jquery|Bootstrap|bootstrap|React|react|Angular|angular|"
    r"Vue|vue|Lodash|lodash|Moment|moment|D3|d3)(?:[\s/-]?(\d+(?:\.\d+){1,3})?)?",
)


def _derive_var_from_finding(
    name: str,
    finding: dict[str, Any],
    scan_context: dict[str, Any] | None = None,
) -> str | None:
    """Versucht eine Title-Var aus Finding-Feldern abzuleiten.

    Quellen pro Var:
      cookie_name → Set-Cookie-Header in evidence ODER affected
      private_ip  → RFC1918-Match in description ODER evidence
      tech        → finding.technology, dann tech_profiles[ip].cms/server
      port        → ":<port>" in affected
      version     → letztes Versions-Match in evidence
      directive   → CSP-Directive in evidence/description
      plugin      → plugin-Name aus evidence
      library     → JS-Library-Name aus title/evidence
      days        → aus description "in N Tagen" pattern

    Returns None wenn nichts ableitbar (Caller fuellt mit "?" via _SafeDict).
    """
    text_blobs = " | ".join(filter(None, [
        finding.get("evidence") or "",
        finding.get("description") or "",
        finding.get("affected") or "",
        finding.get("title") or "",
    ]))

    if name == "cookie_name":
        m = _COOKIE_NAME_RE.search(text_blobs)
        if m:
            return m.group(1)

    if name == "private_ip":
        m = _RFC1918_RE.search(text_blobs)
        if m:
            return m.group(0)

    if name == "tech":
        # Direkt-Feld zuerst
        if finding.get("technology"):
            return str(finding["technology"])
        # tech_profiles[ip] aus scan_context
        host_ip = finding.get("host_ip")
        if host_ip and scan_context:
            tps = scan_context.get("tech_profiles") or []
            for tp in tps:
                if tp.get("ip") == host_ip:
                    return tp.get("cms") or tp.get("server") or None

    if name == "port":
        affected = finding.get("affected") or ""
        m = _PORT_RE.search(affected)
        if m:
            return m.group(1)
        if finding.get("port"):
            return str(finding["port"])

    if name == "version":
        # 1) finding.cms_version o.ae., 2) Version-Match in evidence
        for k in ("version", "cms_version"):
            if finding.get(k):
                return str(finding[k])
        m = _VERSION_RE.search(finding.get("evidence") or "")
        if m:
            return m.group(1)

    if name == "directive":
        m = _CSP_DIRECTIVE_RE.search(text_blobs)
        if m:
            return m.group(1)

    if name == "plugin":
        m = _PLUGIN_NAME_RE.search(text_blobs)
        if m:
            return m.group(1)

    if name == "library":
        m = _LIBRARY_NAME_RE.search(text_blobs)
        if m:
            ver = m.group(2)
            return f"{m.group(1)} {ver}" if ver else m.group(1)

    if name == "days":
        m = re.search(r"\b(?:in|innerhalb)\s+(\d+)\s+Tagen", text_blobs)
        if m:
            return m.group(1)

    return None

# Deterministische Title-Templates pro policy_id (deutsch).
# Platzhalter werden aus finding["title_vars"] gefuellt; fehlende Vars
# werden durch '?' ersetzt (kein KeyError).
TITLE_TEMPLATES: dict[str, str] = {
    # ── Header (SP-HDR-*) ─────────────────────────────────────────
    "SP-HDR-001": "HSTS-Header fehlt auf {host}",
    "SP-HDR-002": "HSTS-Header fehlt auf Session-Pfad {host}",
    "SP-HDR-003": "HSTS-Header ohne includeSubDomains auf {host}",
    "SP-HDR-004": "HSTS max-age unter 6 Monaten auf {host}",
    "SP-HDR-005": "X-Content-Type-Options-Header fehlt auf {host}",
    "SP-HDR-006": "X-Frame-Options-Header fehlt auf {host}",
    "SP-HDR-007": "Referrer-Policy-Header fehlt auf {host}",
    "SP-HDR-008": "Permissions-Policy-Header fehlt auf {host}",
    "SP-HDR-009": "HSTS-Preload-Eintrag fehlt fuer {host}",
    # ── CSP (SP-CSP-*) ─────────────────────────────────────────────
    # IDs muessen mit reporter/severity_policy.py:finding_type-Zuordnung
    # 1:1 uebereinstimmen — Test-Session-Drift Mai 2026: SP-CSP-002..005 waren
    # versetzt (CSP-002 zeigte "unsafe-inline" obwohl severity_policy sagt
    # csp_missing-fortgeschritten).
    "SP-CSP-001": "Content-Security-Policy fehlt auf {host}",
    "SP-CSP-002": "Wirkungslose Content-Security-Policy auf {host}",
    "SP-CSP-003": "CSP enthaelt 'unsafe-inline' auf {host}",
    "SP-CSP-004": "CSP enthaelt 'unsafe-eval' auf {host}",
    "SP-CSP-005": "CSP enthaelt Wildcard-Quelle auf {host}",
    # ── Cookies (SP-COOK-*) ────────────────────────────────────────
    "SP-COOK-001": "Cookie {cookie_name} ohne Secure-Flag auf {host}",
    "SP-COOK-002": "Cookie {cookie_name} ohne HttpOnly-Flag auf {host}",
    "SP-COOK-003": "Cookie {cookie_name} ohne SameSite-Attribut auf {host}",
    "SP-COOK-004": "Session-Cookie {cookie_name} ohne Secure-Flag auf {host}",
    # SP-COOK-005 → severity_policy.finding_type=cookie_no_samesite (war "HttpOnly")
    "SP-COOK-005": "Session-Cookie {cookie_name} ohne SameSite-Attribut auf {host}",
    # ── CSRF (SP-CSRF-*) ───────────────────────────────────────────
    "SP-CSRF-001": "Anti-CSRF-Token fehlt auf Login-Formular {host}",
    "SP-CSRF-002": "Anti-CSRF-Token fehlt auf Formular {host}",
    "SP-CSRF-003": "Anti-CSRF-Token nicht erforderlich fuer State-Aenderung auf {host}",
    # ── Information Disclosure (SP-DISC-*) ────────────────────────
    # Alignment mit severity_policy.finding_type (Test-Session Mai 2026):
    # SP-DISC-003..008 waren versetzt — phpinfo-Findings bekamen z.B.
    # ".git-Verzeichnis"-Title (SP-DISC-004 = phpinfo_exposed laut severity_policy).
    "SP-DISC-001": "Server-Banner mit Versions-Info auf {host}",
    "SP-DISC-002": "Server-Banner ohne Versions-Info auf {host}",
    "SP-DISC-003": "Nginx-Status-Endpoint oeffentlich erreichbar auf {host}",
    "SP-DISC-004": "phpinfo()-Endpoint oeffentlich erreichbar auf {host}",
    "SP-DISC-005": "Directory-Listing aktiv auf {host}",
    "SP-DISC-006": "Stacktrace in Fehlerseite auf {host}",
    "SP-DISC-007": ".git-Verzeichnis oeffentlich erreichbar auf {host}",
    "SP-DISC-008": ".env-Datei oeffentlich erreichbar auf {host}",
    "SP-DISC-009": "Private IP-Adresse {private_ip} im Response auf {host}",
    "SP-DISC-010": "Framework-Development-Build {framework} in Production auf {host}",
    # ── TLS (SP-TLS-*) ─────────────────────────────────────────────
    "SP-TLS-001": "TLS-Konfiguration unter TR-03116-Mindestanforderung auf {host}",
    "SP-TLS-002": "Schwache TLS-Cipher-Suites auf {host}",
    "SP-TLS-003": "Kein Perfect Forward Secrecy auf {host}",
    "SP-TLS-004": "TLS-Zertifikat abgelaufen auf {host}",
    "SP-TLS-005": "TLS-Zertifikat laeuft in {days} Tagen ab auf {host}",
    "SP-TLS-006": "Selbstsigniertes TLS-Zertifikat auf {host}",
    "SP-TLS-007": "TLS-Konfiguration mit Schwaechen auf {host}",
    # ── DNS / Mail (SP-DNS-*) ──────────────────────────────────────
    # IDs muessen mit reporter/severity_policy.py:finding_type-Zuordnung
    # 1:1 uebereinstimmen (Test-Drift Mai 2026: title_policy war zu severity_policy
    # versetzt → DKIM-Findings bekamen MTA-STS-Title etc.).
    "SP-DNS-001": "DNSSEC fehlt fuer {domain}",
    "SP-DNS-002": "DNSSEC-Kette unterbrochen fuer {domain}",
    "SP-DNS-003": "CAA-Record fehlt fuer {domain}",
    "SP-DNS-004": "SPF-Record fehlt fuer {domain}",
    "SP-DNS-005": "SPF-Policy auf softfail (~all) statt -all fuer {domain}",
    "SP-DNS-006": "DMARC-Record fehlt fuer {domain}",
    "SP-DNS-007": "DMARC-Policy auf 'none' statt 'quarantine' oder 'reject' fuer {domain}",
    "SP-DNS-008": "DKIM-Record fehlt fuer {domain}",
    "SP-DNS-009": "MTA-STS-Policy fehlt fuer {domain}",
    "SP-DNS-010": "DMARC-Policy auf 'quarantine' statt 'reject' fuer {domain}",
    # F-P0A-002 — neue Mail-/DNS-Security-Marker (2026-05-09.1)
    "SP-DNS-011": "TLS-RPT (RFC 8460) fehlt fuer {domain}",
    "SP-DNS-012": "BIMI-Record fehlt fuer {domain}",
    "SP-DNS-013": "DMARC-Policy nur teilweise aktiv (pct={pct}) fuer {domain}",
    "SP-DNS-014": "NSEC3 mit Iterations={iterations} > 0 (RFC 9276) fuer {domain}",
    # ── CVE (SP-CVE-*) ─────────────────────────────────────────────
    "SP-CVE-001": "{cve_id} mit aktiven Exploits ({tech}) auf {host}",
    "SP-CVE-002": "{cve_id} (CVSS {cvss}) in {tech} auf {host}",
    "SP-CVE-003": "{cve_id} ({tech}) auf {host}",
    "SP-CVE-004": "Schwachstelle in {tech} auf {host}",
    # ── EOL Software (SP-EOL-*) ────────────────────────────────────
    "SP-EOL-001": "{tech} {version} ist End-of-Life auf {host}",
    "SP-EOL-002": "{tech} {version} naehert sich End-of-Life auf {host}",
    "SP-EOL-003": "Veraltete {tech}-Version {version} auf {host}",
    "SP-EOL-004": "{tech} {version} ohne Sicherheitsupdates auf {host}",
    # ── WordPress (SP-WP-*) ────────────────────────────────────────
    "SP-WP-001": "WordPress-Plugin {plugin} mit bekannter Schwachstelle auf {host}",
    "SP-WP-002": "WordPress-User-Enumeration moeglich auf {host}",
    # ── Misc ───────────────────────────────────────────────────────
    "SP-ENUM-001": "User-Enumeration moeglich auf {host}",
    "SP-DB-001": "Datenbank-Port {port} oeffentlich erreichbar auf {host}",
    "SP-CORS-001": "CORS-Misconfiguration auf {host}",
    "SP-JS-001": "JavaScript-Bibliothek {library} mit Schwachstelle auf {host}",
    "SP-SRI-001": "Subresource-Integrity (SRI) fehlt auf {host}",
    "SP-SSH-001": "SSH-Dienst ohne Brute-Force-Schutz auf {host}",
    # F-P0A-003 — URLhaus Threat-Intel (2026-05-10.1)
    "SP-URLHAUS-001": "Host {host} bei URLhaus als kompromittiert gelistet ({url_count} URLs)",
}


# M2 Track 2b (P0-05): service-spezifische Banner-Templates — gegen Doppel-Titel
# bei info_disclosure_banner. Dispatcher in apply_title_template waehlt das
# spezifischere Template wenn finding_type=="info_disclosure_banner" UND
# title_vars["service"] in {ssh, http, smtp, ftp} gesetzt ist.
# Discriminated-finding_type-Keys: passend zu finding_type_mapper.py-Patterns.
SERVICE_BANNER_TEMPLATES: dict[str, str] = {
    "info_disclosure_banner_ssh":     "SSH-Banner mit Versions-Info auf {host}",
    "info_disclosure_banner_http":    "HTTP-Header mit Versions-Info auf {host}",
    "info_disclosure_banner_smtp":    "SMTP-Banner mit Versions-Info auf {host}",
    "info_disclosure_banner_ftp":     "FTP-Banner mit Versions-Info auf {host}",
    "info_disclosure_banner_generic": "Service-Banner mit Versions-Info auf {host}",
}

# M2 Track 2b (P0-03): service-spezifische Mail-Security-Templates — gegen
# falsche Klassifikation "SPF fehlt" im Title aber "DKIM fehlt" im Body.
# Discriminated-finding_type-Keys.
MAIL_SECURITY_TEMPLATES: dict[str, str] = {
    "mail_security_missing_spf":   "SPF-Record fehlt fuer {domain}",
    "mail_security_missing_dkim":  "DKIM-Record fehlt fuer {domain}",
    "mail_security_missing_dmarc": "DMARC-Policy fehlt fuer {domain}",
    "mail_security_dmarc_none":    "DMARC-Policy ohne Durchsetzung (p=none) fuer {domain}",
}


class TitleVarFallbackError(Exception):
    """Wird geworfen wenn auch nach voller Fallback-Kette eine Pflicht-Var
    (typisch {host}) nicht aufgeloest werden kann.

    Wird in apply_titles gefangen → Finding bekommt `_title_degraded=True`,
    der ValidationGate-Check titles.py meldet das als Error.
    """

    def __init__(self, finding_id: str | None, var: str, message: str = ""):
        self.finding_id = finding_id
        self.var = var
        super().__init__(message or f"Konnte Title-Var '{var}' fuer Finding {finding_id} nicht aufloesen")


# Standard-Service-Ports (Whitelist fuer Token-Linter, deckt sich mit
# validation/checks/titles.py:_KNOWN_PORTS).
_KNOWN_PORT_TOKENS: set[str] = {
    "20", "21", "22", "23", "25", "53", "80", "110", "143",
    "443", "465", "587", "636", "993", "995",
    "1433", "1521", "1723", "2049", "3306", "3389",
    "5432", "5900", "6379", "8080", "8443", "9200", "9300",
    "27017", "11211", "5060", "5061",
}

# Einheiten/Plurale die einer Zahl folgen duerfen (z.B. "27 Plugins")
_NUMBER_UNIT_RE = re.compile(
    r"^(?:Plugins?|Hosts?|Subdomains?|Findings?|Komponenten|Zeilen|Tage|Tagen|"
    r"Stunden|Monate|Monaten|Jahre|Jahren|Versionen|MB|GB|KB|TB|kbit|Mbit|Gbit|%)\b",
    re.IGNORECASE,
)
_BARE_NUMBER_TOKEN_RE = re.compile(r"\b(\d+)\b")


def _resolve_host_with_fallback(
    finding: dict[str, Any],
    scan_context: dict[str, Any] | None,
) -> str | None:
    """Aufgeweitete Host-Fallback-Kette fuer P0-01.

    Reihenfolge:
      1. finding["affected"]            (Liste oder CSV-String → erster Eintrag,
                                         bei >1 Host: "first (+N weitere)")
      2. finding["affected_hosts"]      (Liste → join CSV oder first+rest)
      3. finding["title_vars"]["host"]
      4. finding["vhost"] / finding["fqdn"]
      5. finding["host"] / finding["host_ip"] / finding["ip"]
      6. scan_context.host_inventory.hosts[*].fqdns (CSV-Sammelliste)
      7. scan_context.tech_profiles[*].fqdns        (CSV-Sammelliste)
      8. scan_context.domain                          (last resort)

    Returns None wenn nichts auffindbar → Caller wirft TitleVarFallbackError.
    """
    def _format_multi(items: list[str]) -> str:
        items = [str(x).strip() for x in items if x and str(x).strip()]
        if not items:
            return ""
        if len(items) == 1:
            return items[0]
        return f"{items[0]} (+{len(items)-1} weitere)"

    # 1. affected
    affected = finding.get("affected")
    if isinstance(affected, list) and affected:
        host = _format_multi([str(x) for x in affected])
        if host:
            return host
    elif isinstance(affected, str) and affected.strip():
        parts = [p.strip() for p in affected.split(",") if p.strip()]
        if parts:
            return _format_multi(parts)

    # 2. affected_hosts (Liste)
    affected_hosts = finding.get("affected_hosts")
    if isinstance(affected_hosts, list) and affected_hosts:
        host = _format_multi([str(x) for x in affected_hosts])
        if host:
            return host

    # 3. title_vars["host"]
    tv = finding.get("title_vars") or {}
    if isinstance(tv, dict):
        host = tv.get("host")
        if host and str(host).strip() and str(host).strip() != "?":
            return str(host).strip()

    # 4. vhost / fqdn
    for key in ("vhost", "fqdn"):
        v = finding.get(key)
        if v and str(v).strip():
            return str(v).strip()

    # 5. host / host_ip / ip
    for key in ("host", "host_ip", "ip"):
        v = finding.get(key)
        if v and str(v).strip():
            return str(v).strip()

    # 6. scan_context.host_inventory.hosts[*].fqdns
    if scan_context:
        hi = scan_context.get("host_inventory") or {}
        hosts = hi.get("hosts") if isinstance(hi, dict) else None
        if isinstance(hosts, list):
            fqdns_all: list[str] = []
            for h in hosts:
                if isinstance(h, dict):
                    fqdns = h.get("fqdns") or []
                    if isinstance(fqdns, list):
                        fqdns_all.extend([str(f) for f in fqdns if f])
            if fqdns_all:
                return ", ".join(dict.fromkeys(fqdns_all))  # de-dup mit Reihenfolge

        # 7. scan_context.tech_profiles[*].fqdns
        tps = scan_context.get("tech_profiles") or []
        if isinstance(tps, list):
            fqdns_all2: list[str] = []
            for tp in tps:
                if isinstance(tp, dict):
                    fqdns = tp.get("fqdns") or []
                    if isinstance(fqdns, list):
                        fqdns_all2.extend([str(f) for f in fqdns if f])
            if fqdns_all2:
                return ", ".join(dict.fromkeys(fqdns_all2))

        # 8. scan_context.domain
        d = scan_context.get("domain")
        if d and str(d).strip():
            return str(d).strip()

    return None


def _validate_title_tokens(title: str) -> tuple[bool, list[str]]:
    """Title-Linter (P0-04): erkennt nackte Zahl-Tokens ohne Port/Version/Einheit.

    Erlaubt sind:
      - Standard-Ports (22, 80, 443, ...)
      - Versionsnummern mit Punkt (1.2.3 — bereits Bestandteil eines groesseren Tokens)
      - Zahlen direkt gefolgt von einer Einheit ("27 Plugins", "30 Tage")

    Returns: (is_clean, list_of_suspicious_tokens)
    """
    suspicious: list[str] = []
    # Tokens nach Position scannen — Lookahead auf Einheit
    for m in _BARE_NUMBER_TOKEN_RE.finditer(title):
        num = m.group(1)
        start, end = m.span()
        # Teil einer Versionsnummer? (Punkt davor oder dahinter)
        before = title[max(0, start - 1):start]
        after = title[end:end + 1]
        if before == "." or after == ".":
            continue
        # Standard-Port?
        if num in _KNOWN_PORT_TOKENS:
            continue
        # Folgt eine Einheit/Plural?
        rest = title[end:].lstrip()
        if _NUMBER_UNIT_RE.match(rest):
            continue
        suspicious.append(num)
    return (len(suspicious) == 0, suspicious)


class _SafeDict(dict):
    """Dict-Subclass: gibt '?' zurueck wenn Key fehlt — verhindert KeyError
    bei fehlenden Platzhaltern in str.format_map().
    """

    def __missing__(self, key: str) -> str:
        return "?"


def apply_title_template(finding: dict[str, Any], scan_context: dict[str, Any] | None = None) -> str:
    """Wendet TITLE_TEMPLATES auf ein Finding an.

    Returns:
        Deterministischer Titel wenn Template existiert. Sonst KI-Original-Title.

    Flags am Finding:
      - `_title_template_missing=True`     → Template fehlt ganz
      - `_title_template_incomplete=True`  → Template hat Luecken (?), wir
        fielen auf KI-Original zurueck
    """
    policy_id = (finding.get("policy_id") or "").strip()
    original_title = finding.get("title", "") or ""
    finding_type = (finding.get("finding_type") or "").strip()
    title_vars_in = finding.get("title_vars") or {}
    if not isinstance(title_vars_in, dict):
        title_vars_in = {}

    # M2 Track 2b (P0-05/P0-03): Service-spezifische Templates haben Vorrang
    # wenn ein Service-Discriminator vorliegt.
    template: str | None = None

    # Banner-Service-Discriminator (info_disclosure_banner → ssh/http/smtp/ftp)
    if finding_type == "info_disclosure_banner":
        svc = str(title_vars_in.get("service") or "").lower().strip()
        if svc in {"ssh", "http", "smtp", "ftp"}:
            template = SERVICE_BANNER_TEMPLATES.get(f"info_disclosure_banner_{svc}")
        else:
            template = SERVICE_BANNER_TEMPLATES.get("info_disclosure_banner_generic")
    # Service-spezifischer finding_type direkt (mail_security_missing_dkim etc.)
    elif finding_type in SERVICE_BANNER_TEMPLATES:
        template = SERVICE_BANNER_TEMPLATES[finding_type]
    elif finding_type in MAIL_SECURITY_TEMPLATES:
        template = MAIL_SECURITY_TEMPLATES[finding_type]

    # Falls noch keins gewaehlt: ueber policy_id (bestehende Logik)
    if template is None:
        if not policy_id:
            # Auch ohne policy_id: cleanup-leftover-placeholders laeuft spaeter
            return original_title
        template = TITLE_TEMPLATES.get(policy_id)
        if template is None:
            finding["_title_template_missing"] = True
            return original_title

    # Vars sammeln: bevorzugt finding.title_vars, sonst aus Felder ableiten
    title_vars: dict[str, Any] = {}
    if isinstance(finding.get("title_vars"), dict):
        title_vars.update(finding["title_vars"])

    # Fallback-Vars aus haeufigen Finding-Feldern (legacy host/domain/cve/cvss)
    # M2 Track 2b (P0-01): aufgeweitete Host-Fallback-Kette.
    if "host" not in title_vars or not str(title_vars.get("host") or "").strip() or title_vars.get("host") == "?":
        host = _resolve_host_with_fallback(finding, scan_context)
        if host:
            title_vars["host"] = host
    if "domain" not in title_vars and scan_context:
        title_vars["domain"] = scan_context.get("domain", "?")
    if "domain" not in title_vars and "host" in title_vars:
        title_vars["domain"] = title_vars["host"]
    if "cve_id" not in title_vars and finding.get("cve"):
        title_vars["cve_id"] = finding["cve"]
    if "cvss" not in title_vars and finding.get("cvss_score"):
        title_vars["cvss"] = finding["cvss_score"]

    # A2 Smart-Fallback: Pro Template-Platzhalter nochmal versuchen aus
    # evidence/description/affected/tech_profiles abzuleiten.
    placeholders = re.findall(r"\{(\w+)\}", template)
    for ph in placeholders:
        if ph in title_vars and str(title_vars[ph]).strip() not in ("", "?"):
            continue
        derived = _derive_var_from_finding(ph, finding, scan_context)
        if derived:
            title_vars[ph] = derived

    try:
        rendered = template.format_map(_SafeDict(title_vars))
    except Exception as e:
        logger.warning(
            "title_template_format_failed policy_id=%s err=%s template=%s vars=%s",
            policy_id, e, template, list(title_vars.keys()),
        )
        return original_title

    # A1 Sicherheitsnetz: wenn rendered Title ein "?" enthaelt UND der
    # KI-Original-Title keine Luecke hat → KI-Original ist die bessere Quelle.
    if "?" in rendered and original_title and "?" not in original_title:
        finding["_title_template_incomplete"] = True
        logger.info(
            "title_template_incomplete policy_id=%s missing_vars=%s using_original=%r",
            policy_id,
            [ph for ph in placeholders if title_vars.get(ph) in (None, "", "?")],
            original_title[:60],
        )
        return original_title

    return rendered


_LEFTOVER_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def _cleanup_leftover_placeholders(
    title: str,
    finding: dict[str, Any],
    scan_context: dict[str, Any] | None,
    strict: bool = False,
) -> str:
    """Ersetze uebrig gebliebene ``{platzhalter}`` im Title.

    PR-H (Mai 2026): KI generiert Titel wie ``"RDP-Dienst auf {host}"`` und
    setzt den Platzhalter nicht selbst ein. Wenn keine policy_id zugeordnet
    ist (oder das Template fehlt), bleibt der literal Placeholder stehen.
    Wir versuchen jede uebrig gebliebene Variable aus title_vars +
    abgeleiteten Quellen + affected_hosts/vhost/finding-Feldern zu ersetzen.

    M2 Track 2b (P0-01): mit `strict=True` raisen wir TitleVarFallbackError,
    wenn {host} nach der vollen Fallback-Kette nicht aufloesbar ist. Caller
    (apply_titles) verwendet strict=True und fangt die Exception ab.
    `strict=False` (default) ist der legacy-Pfad — gibt einen lesbaren Title
    auch ohne Host zurueck (z.B. "JavaScript-Lib mit Schwachstelle").
    """
    if "{" not in title:
        return title

    # Quellen-Lookup wie in apply_title_template — mit aufgeweiteter Host-Kette
    title_vars: dict[str, Any] = {}
    if isinstance(finding.get("title_vars"), dict):
        title_vars.update(finding["title_vars"])
    if "host" not in title_vars or not str(title_vars.get("host") or "").strip() or title_vars.get("host") == "?":
        host = _resolve_host_with_fallback(finding, scan_context)
        if host:
            title_vars["host"] = host
    if "domain" not in title_vars and scan_context:
        title_vars["domain"] = scan_context.get("domain", "")
    if "cve_id" not in title_vars and finding.get("cve"):
        title_vars["cve_id"] = finding["cve"]
    if "cvss" not in title_vars and finding.get("cvss_score"):
        title_vars["cvss"] = finding["cvss_score"]

    # Pflicht-Pruefung (nur strict-Pfad): ist {host} Bestandteil des Templates
    # und nicht aufloesbar?
    if strict:
        placeholder_keys = _LEFTOVER_PLACEHOLDER_RE.findall(title)
        if "host" in placeholder_keys:
            v = title_vars.get("host")
            if v in (None, "", "?"):
                raise TitleVarFallbackError(
                    finding.get("id"),
                    "host",
                    f"Konnte {{host}} fuer Finding {finding.get('id')} nicht aufloesen "
                    f"(keine affected/affected_hosts/vhost/host_ip/scan_context-Quelle)",
                )

    def _replace(m: re.Match) -> str:
        key = m.group(1)
        val = title_vars.get(key)
        if val in (None, "", "?"):
            # Letzter Versuch: aus evidence/description ableiten
            val = _derive_var_from_finding(key, finding, scan_context)
        if val in (None, "", "?"):
            # Kompletten Platzhalter (mit "auf " Praefix wenn vorhanden)
            # einfach entfernen damit der Title les bar bleibt.
            return ""
        return str(val)

    cleaned = _LEFTOVER_PLACEHOLDER_RE.sub(_replace, title)
    # Doppelte/leftover Whitespace + dangling Praeposition aufraeumen
    cleaned = re.sub(r"\s+auf\s*$", "", cleaned)  # "...erreichbar auf" am Ende
    cleaned = re.sub(r"\s+bei\s*$", "", cleaned)
    cleaned = re.sub(r"\s+fuer\s*$", "", cleaned)
    cleaned = re.sub(r"\s+für\s*$", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned or title  # Niemals leeren String zurueck — Fallback Original


def apply_titles(findings: list[dict[str, Any]],
                 scan_context: dict[str, Any] | None = None) -> int:
    """Wendet Title-Templates auf alle Findings an. Modifiziert in-place.

    Returns: Anzahl der Findings deren Title durch Template ueberschrieben wurde.

    M2 Track 2b:
    - Faengt TitleVarFallbackError → Finding bekommt `_title_degraded=True`.
    - Token-Linter (P0-04): finale Titel mit nackten Zahl-Tokens werden
      degradiert (z.B. "WordPress-Plugin 27 ..."). `_title_degraded=True` +
      `_title_suspicious_tokens` gesetzt.
    """
    overridden = 0
    for f in findings:
        try:
            new_title = apply_title_template(f, scan_context)
        except TitleVarFallbackError as e:
            f["_title_degraded"] = True
            f["_title_degraded_reason"] = f"var_fallback_failed:{e.var}"
            logger.warning(
                "title_var_fallback_failed finding_id=%s var=%s",
                e.finding_id, e.var,
            )
            new_title = f.get("title", "") or ""
        if new_title and new_title != f.get("title"):
            f["title"] = new_title
            overridden += 1
        # PR-H: leftover-Cleanup auch bei nicht-ueberschriebenen Titles
        # (Original-KI-Title mit literalen Platzhaltern).
        try:
            final_title = _cleanup_leftover_placeholders(
                f.get("title", "") or "", f, scan_context, strict=True,
            )
        except TitleVarFallbackError as e:
            f["_title_degraded"] = True
            f["_title_degraded_reason"] = f"var_fallback_failed:{e.var}"
            logger.warning(
                "title_cleanup_var_fallback_failed finding_id=%s var=%s",
                e.finding_id, e.var,
            )
            final_title = f.get("title", "") or ""
        if final_title != f.get("title"):
            f["title"] = final_title

        # M2 Track 2b (P0-04): Token-Linter — nackte Zahlen ohne Port/Version/Unit
        if f.get("title"):
            is_clean, suspicious = _validate_title_tokens(f["title"])
            if not is_clean:
                f["_title_degraded"] = True
                f["_title_suspicious_tokens"] = suspicious
                logger.info(
                    "title_token_linter_flagged finding_id=%s suspicious=%s title=%r",
                    f.get("id"), suspicious, f["title"][:80],
                )
    return overridden

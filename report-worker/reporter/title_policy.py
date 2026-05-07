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
    "SP-CSP-001": "Content-Security-Policy fehlt auf {host}",
    "SP-CSP-002": "CSP enthaelt 'unsafe-inline' auf {host}",
    "SP-CSP-003": "CSP enthaelt 'unsafe-eval' auf {host}",
    "SP-CSP-004": "CSP enthaelt Wildcard-Quelle auf {host}",
    "SP-CSP-005": "CSP-Direktive {directive} unsicher konfiguriert auf {host}",
    # ── Cookies (SP-COOK-*) ────────────────────────────────────────
    "SP-COOK-001": "Cookie {cookie_name} ohne Secure-Flag auf {host}",
    "SP-COOK-002": "Cookie {cookie_name} ohne HttpOnly-Flag auf {host}",
    "SP-COOK-003": "Cookie {cookie_name} ohne SameSite-Attribut auf {host}",
    "SP-COOK-004": "Session-Cookie {cookie_name} ohne Secure-Flag auf {host}",
    "SP-COOK-005": "Session-Cookie {cookie_name} ohne HttpOnly-Flag auf {host}",
    # ── CSRF (SP-CSRF-*) ───────────────────────────────────────────
    "SP-CSRF-001": "Anti-CSRF-Token fehlt auf Login-Formular {host}",
    "SP-CSRF-002": "Anti-CSRF-Token fehlt auf Formular {host}",
    "SP-CSRF-003": "Anti-CSRF-Token nicht erforderlich fuer State-Aenderung auf {host}",
    # ── Information Disclosure (SP-DISC-*) ────────────────────────
    "SP-DISC-001": "Server-Banner mit Versions-Info auf {host}",
    "SP-DISC-002": "Server-Banner ohne Versions-Info auf {host}",
    "SP-DISC-003": ".env-Datei oeffentlich erreichbar auf {host}",
    "SP-DISC-004": ".git-Verzeichnis oeffentlich erreichbar auf {host}",
    "SP-DISC-005": "phpinfo()-Endpoint oeffentlich erreichbar auf {host}",
    "SP-DISC-006": "Directory-Listing aktiv auf {host}",
    "SP-DISC-007": "Stacktrace in Fehlerseite auf {host}",
    "SP-DISC-008": "Nginx-Status-Endpoint oeffentlich erreichbar auf {host}",
    "SP-DISC-009": "Private IP-Adresse {private_ip} im Response auf {host}",
    # ── TLS (SP-TLS-*) ─────────────────────────────────────────────
    "SP-TLS-001": "TLS-Konfiguration unter TR-03116-Mindestanforderung auf {host}",
    "SP-TLS-002": "Schwache TLS-Cipher-Suites auf {host}",
    "SP-TLS-003": "Kein Perfect Forward Secrecy auf {host}",
    "SP-TLS-004": "TLS-Zertifikat abgelaufen auf {host}",
    "SP-TLS-005": "TLS-Zertifikat laeuft in {days} Tagen ab auf {host}",
    "SP-TLS-006": "Selbstsigniertes TLS-Zertifikat auf {host}",
    "SP-TLS-007": "TLS-Konfiguration mit Schwaechen auf {host}",
    # ── DNS / Mail (SP-DNS-*) ──────────────────────────────────────
    "SP-DNS-001": "DNSSEC-Kette unterbrochen fuer {domain}",
    "SP-DNS-002": "DNSSEC fehlt fuer {domain}",
    "SP-DNS-003": "CAA-Record fehlt fuer {domain}",
    "SP-DNS-004": "SPF-Policy auf softfail (~all) statt -all fuer {domain}",
    "SP-DNS-005": "SPF-Record fehlt fuer {domain}",
    "SP-DNS-006": "DMARC-Record fehlt fuer {domain}",
    "SP-DNS-007": "DKIM-Record fehlt fuer {domain}",
    "SP-DNS-008": "MTA-STS-Policy fehlt fuer {domain}",
    "SP-DNS-009": "DMARC-Policy auf 'none' statt 'quarantine' oder 'reject' fuer {domain}",
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

    if not policy_id:
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
    if "host" not in title_vars:
        host = (
            finding.get("vhost")
            or finding.get("fqdn")
            or finding.get("affected_hosts", [None])[0]
            or finding.get("host_ip")
            or finding.get("host")
        )
        if host:
            title_vars["host"] = str(host)
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


def apply_titles(findings: list[dict[str, Any]],
                 scan_context: dict[str, Any] | None = None) -> int:
    """Wendet Title-Templates auf alle Findings an. Modifiziert in-place.

    Returns: Anzahl der Findings deren Title durch Template ueberschrieben wurde.
    """
    overridden = 0
    for f in findings:
        new_title = apply_title_template(f, scan_context)
        if new_title and new_title != f.get("title"):
            f["title"] = new_title
            overridden += 1
    return overridden

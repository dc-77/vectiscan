"""Deterministische Verifikations-Templates pro policy_id (M5 Track 5a).

Doc 02 Seite 11+ verlangt im Befund-Block einen Verifikations-Schritt:
"Wie kann der Admin pruefen, dass der Fix gewirkt hat?"

Diese Datei liefert pro policy_id ein versioniertes Template (analog zu
title_policy.TITLE_TEMPLATES). Smart-Var-Substitution fuellt {host}, {port},
{domain}, {cookie_name}, ... aus finding-Feldern.

Stand 2026-05-13: Top-15 policy_ids gepflegt (9 secumetrix + 6 trunk Reload).
Fallback bei fehlendem Template: generischer Hinweis-Block ohne Befehl
(`GENERIC_FALLBACK`), Finding bekommt Flag `_verification_template_missing`.

Code-Review-Pflicht: Neue Templates muessen ueber PR ergaenzt werden, der
Tech-Lead reviewt jeden Befehl auf Korrektheit + Idempotenz.
"""

from __future__ import annotations

import re
from typing import Any


# ====================================================================
# TEMPLATES PRO POLICY-ID
# ====================================================================
# Format: triple-quoted multi-line Strings; Smart-Var-Substitution wie in
# title_policy.TITLE_TEMPLATES. Platzhalter {host}, {port}, {domain},
# {cookie_name}, {cve_id}, {tech}, {version}, {plugin}, {library}.
#
# Jedes Template enthaelt:
#   1. eine kurze Beschreibung der erwarteten Pruefung
#   2. einen konkreten Verifizierungs-Befehl
#   3. das erwartete Ergebnis (Soll-Zustand)
#
# Stilkonventionen:
#   - kein Hersteller-Marketing-Sprech
#   - shell-tauglich (`$ <cmd>`) damit sie 1:1 kopiert werden koennen
#   - mehrzeilig wo eine zweite Pruefung sinnvoll ist
VERIFICATION_TEMPLATES: dict[str, str] = {
    # ── Datenbank-Ports (SP-DB-*) ─────────────────────────────────
    "SP-DB-001": (
        "Nach Umsetzung der Sofortmassnahme:\n"
        "$ nmap -sV -p {port} {host}\n"
        "Erwartet: filtered/closed (kein offener Dienst extern).\n"
        "Optional: aus externem Netz testen — interne Tests sind "
        "kein Beleg, dass die Firewall greift."
    ),
    # ── RDP (SP-RDP-*) ────────────────────────────────────────────
    "SP-RDP-001": (
        "Nach Firewall-/MFA-Massnahme:\n"
        "$ nmap -p 3389 {host}\n"
        "Erwartet: filtered/closed. Falls Remote-Wartung noetig: "
        "Zugriff nur via VPN, MFA fuer alle RDP-User in Active Directory "
        "bzw. Identity-Provider erzwingen."
    ),
    # ── FTP (SP-FTP-*) ────────────────────────────────────────────
    "SP-FTP-001": (
        "Nach Migration auf SFTP:\n"
        "$ nmap -p 21 {host}\n"
        "Erwartet: closed/filtered fuer TCP/21 (Klartext-FTP)\n"
        "$ ssh -p 22 user@{host}    (SFTP-Subsystem-Test)\n"
        "Erwartet: SFTP funktioniert, FTP/21 ist nicht mehr "
        "erreichbar."
    ),
    # ── SSH (SP-SSH-*) + EOL-SSH (SP-EOL-*) ───────────────────────
    "SP-EOL-002": (
        "Nach OpenSSH-Update:\n"
        "$ ssh -V    (lokal auf {host})\n"
        "Erwartet: OpenSSH >= 9.0 (oder vom Distro-Vendor unterstuetzte "
        "Version mit aktiven Sicherheits-Backports).\n"
        "$ nmap -sV -p 22 {host}\n"
        "Erwartet: Banner zeigt keine veraltete 7.x-Version mehr."
    ),
    # ── Generische EOL-Software ──────────────────────────────────
    "SP-EOL-001": (
        "Nach Migration auf supportete {tech}-Version:\n"
        "$ {tech} --version    (lokal auf {host})\n"
        "Erwartet: aktuelle, vom Hersteller unterstuetzte Version; "
        "Sicherheits-Updates vorhanden in den letzten 90 Tagen.\n"
        "Optional: Tech-Detection erneut laufen lassen (webtech/nmap-sV)."
    ),
    # ── Dev-Environment (SP-WEB-002) ──────────────────────────────
    "SP-WEB-002": (
        "Nach Absicherung der Dev-Umgebung:\n"
        "$ curl -I https://{host}\n"
        "Erwartet: 401 Unauthorized (Basic-Auth aktiv) oder "
        "Verbindung von externer IP wird per Firewall/IP-Whitelist "
        "geblockt. Aus internem Netz: weiterhin erreichbar fuer "
        "berechtigte Entwickler."
    ),
    # ── Cleartext-Login (SP-WEB-001) ──────────────────────────────
    "SP-WEB-001": (
        "Nach HTTPS-Erzwingung:\n"
        "$ curl -I http://{host}/login\n"
        "Erwartet: 301/308 Redirect auf https://{host}/login.\n"
        "$ curl -I https://{host}/login\n"
        "Erwartet: 200 OK ueber TLS, Strict-Transport-Security gesetzt."
    ),
    # ── WordPress / CMS (SP-WP-*, SP-CMS-*) ───────────────────────
    "SP-WP-001": (
        "Nach WordPress-Update:\n"
        "$ curl -s https://{host}/wp-includes/version.php | head\n"
        "(nur lokal — extern blockiert; alternativ /readme.html bzw "
        "/wp-login.php-Footer).\n"
        "Erwartet: WordPress >= aktuelle Stable-Version.\n"
        "Plugin-Pruefung im wp-admin: alle Plugins als 'aktuell' "
        "markiert, kein Hinweis auf bekannte CVEs."
    ),
    "SP-CMS-001": (
        "Nach Plugin-/Theme-Updates:\n"
        "Im Admin-Backend ueber Plugins → Installierte Plugins:\n"
        "Erwartet: kein Plugin zeigt 'Update verfuegbar' oder "
        "'bekannte Schwachstelle'. Zusaetzlich wpscan-Replay:\n"
        "$ wpscan --url https://{host} --enumerate vp\n"
        "Erwartet: 'No vulnerabilities found' fuer alle Plugins."
    ),
    # ── Mail-Security (SP-DNS-*) ──────────────────────────────────
    "SP-DNS-002": (
        "Nach DKIM-Aktivierung:\n"
        "$ dig +short TXT default._domainkey.{domain}\n"
        "Erwartet: gueltiger DKIM-Record mit p=<public-key>.\n"
        "Alternativ ueber Mail-Tester wie mxtoolbox.com pruefen — "
        "Test-Mail an check-auth@verifier.port25.com senden, "
        "Antwort muss DKIM=PASS zeigen."
    ),
    "SP-DNS-004": (
        "Nach DMARC-Verschaerfung:\n"
        "$ dig +short TXT _dmarc.{domain}\n"
        "Erwartet: v=DMARC1; p=quarantine (oder p=reject); pct=100; "
        "rua-Adresse fuer Reports gesetzt.\n"
        "Reports nach 7 Tagen pruefen — keine eigenen Mails landen "
        "in der Quarantaene."
    ),
    "SP-DNS-007": (
        "Nach DMARC-Verschaerfung (p=none -> p=quarantine/reject):\n"
        "$ dig +short TXT _dmarc.{domain}\n"
        "Erwartet: Policy ist nicht mehr 'none'. Vor dem Bump auf "
        "p=reject mindestens 14 Tage Reporting unter p=quarantine "
        "laufen lassen und rua-Reports auf 'legitime, blockierte' "
        "Mails pruefen."
    ),
    # ── Security-Header / Cookies (SP-HDR-*, SP-COOK-*) ───────────
    "SP-HDR-001": (
        "Nach HSTS-Konfiguration:\n"
        "$ curl -I https://{host} | grep -i strict-transport\n"
        "Erwartet: 'Strict-Transport-Security: max-age=31536000; "
        "includeSubDomains'. Optional 'preload' nach Eintragung in "
        "hstspreload.org.\n"
        "Browser-Test: chrome://net-internals/#hsts -> Eintrag fuer "
        "{host} mit static_sts_observed."
    ),
    "SP-COOK-003": (
        "Nach SameSite-Konfiguration:\n"
        "$ curl -I https://{host} | grep -i 'set-cookie'\n"
        "Erwartet: Cookie '{cookie_name}' enthaelt 'SameSite=Lax' "
        "(oder 'SameSite=Strict' fuer reine Session-Cookies). "
        "Bei Cross-Site-Workflows: 'SameSite=None; Secure'."
    ),
    # ── Information-Disclosure (SP-DISC-*) ────────────────────────
    "SP-DISC-001": (
        "Nach Banner-Reduzierung:\n"
        "$ curl -I https://{host}\n"
        "Erwartet: Server-Header zeigt keinen Versionsstring "
        "(z.B. nur 'Apache' statt 'Apache/2.4.49').\n"
        "$ nmap -sV -p 22,80,443 {host}\n"
        "Erwartet: nmap kann keine exakte Version mehr bestimmen "
        "(nmap zeigt 'service' aber keine Build-Nummer)."
    ),
}


# ====================================================================
# GENERIC FALLBACK
# ====================================================================
# Wird verwendet wenn keine policy_id-spezifische Vorlage greift.
# Doc 02-konformer Hinweis-Block — kein Befehl, da generisch nicht
# sinnvoll moeglich.
GENERIC_FALLBACK = (
    "Nach Umsetzung der Empfehlung: gezielter Re-Scan derselben "
    "Pruefkomponente mit identischer Tool-Konfiguration. Das Finding "
    "darf in der erneuten Pruefung nicht mehr reproduzierbar sein. "
    "Bei Befunden mit CVE-Bezug zusaetzlich Patchstand der "
    "betroffenen Software gegen Hersteller-Advisory verifizieren."
)


# ====================================================================
# SMART-VAR-SUBSTITUTION
# ====================================================================
_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


class _SafeDict(dict):
    """Dict-Subclass: '?' bei fehlendem Key — verhindert KeyError in format."""

    def __missing__(self, key: str) -> str:
        return "?"


def _collect_vars(
    finding: dict[str, Any],
    scan_context: dict[str, Any] | None,
) -> dict[str, str]:
    """Sammelt Smart-Vars aus finding + scan_context.

    Reihenfolge der Quellen pro Var:
      title_vars (KI-Output) ->
      Direkt-Felder (host_ip, port, version, ...) ->
      affected (parsed) ->
      scan_context.domain
    """
    vars_out: dict[str, str] = {}

    # 1. KI/Mapper-Output
    tv = finding.get("title_vars") or {}
    if isinstance(tv, dict):
        for k, v in tv.items():
            if v not in (None, "", "?"):
                vars_out[k] = str(v)

    # 2. host — Reihenfolge: title_vars > affected/affected_hosts > vhost/fqdn > host_ip
    if "host" not in vars_out or vars_out.get("host") == "?":
        for src_key in ("vhost", "fqdn", "host", "host_ip", "ip"):
            v = finding.get(src_key)
            if v and str(v).strip():
                vars_out["host"] = str(v).strip()
                break
        if "host" not in vars_out:
            # affected ('5.199.141.24:21' oder Liste)
            aff = finding.get("affected")
            if isinstance(aff, list) and aff:
                vars_out["host"] = str(aff[0]).split(":")[0].strip()
            elif isinstance(aff, str) and aff.strip():
                first = aff.split(",")[0].strip()
                vars_out["host"] = first.split(":")[0].strip()

    # 3. domain — title_vars > scan_context > finding.fqdn > host
    if "domain" not in vars_out or vars_out.get("domain") == "?":
        if scan_context and scan_context.get("domain"):
            vars_out["domain"] = str(scan_context["domain"])
        elif vars_out.get("host"):
            vars_out["domain"] = vars_out["host"]

    # 4. port — title_vars > finding.port > affected ":<port>"
    if "port" not in vars_out or vars_out.get("port") == "?":
        if finding.get("port"):
            vars_out["port"] = str(finding["port"])
        else:
            aff = finding.get("affected") or ""
            if isinstance(aff, str):
                m = re.search(r":(\d{1,5})\b", aff)
                if m:
                    vars_out["port"] = m.group(1)

    # 5. cookie_name — title_vars > evidence
    if "cookie_name" not in vars_out or vars_out.get("cookie_name") == "?":
        ev = finding.get("evidence")
        if isinstance(ev, dict) and ev.get("cookie_name"):
            vars_out["cookie_name"] = str(ev["cookie_name"])

    # 6. tech / version — title_vars > finding direct
    for key in ("tech", "version", "plugin", "library", "cve_id"):
        if (key not in vars_out or vars_out.get(key) == "?") and finding.get(key):
            vars_out[key] = str(finding[key])

    return vars_out


def get_verification_block(
    finding: dict[str, Any],
    scan_context: dict[str, Any] | None = None,
) -> tuple[str, bool]:
    """Returns (rendered_text, is_generic_fallback).

    - rendered_text: deutscher Multi-Line-Text mit substituierten Vars
    - is_generic_fallback: True wenn kein policy_id-Template gefunden wurde.
                            Caller (renderer) kann das in der UI sichtbar
                            machen ("Generischer Hinweis — kein spezifischer
                            Befehl hinterlegt") und der QA-Check kann zaehlen.
    """
    policy_id = (finding.get("policy_id") or "").strip()
    template = VERIFICATION_TEMPLATES.get(policy_id)
    if template is None:
        return GENERIC_FALLBACK, True

    vars_map = _collect_vars(finding, scan_context)
    rendered = template.format_map(_SafeDict(vars_map))
    return rendered, False


__all__ = [
    "VERIFICATION_TEMPLATES",
    "GENERIC_FALLBACK",
    "get_verification_block",
]

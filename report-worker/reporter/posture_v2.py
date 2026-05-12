"""Per-Scan Posture-Indikatoren fuer Doc 02 Seite 7.

Vier kompakte Mini-Dashboards:

   E-Mail-Authentifizierung:  SPF / DKIM / DMARC
   Web-Hygiene (HSTS/CSP):    Header-Implementierungs-Anteil
   DNS-Hygiene:               AXFR / Dangling-CNAMEs / DNSSEC
   TLS-Konfiguration:         TR-03116-4 (oder Heuristik aus Findings)

Quelle ist primaer ``claude_output.findings`` (Spec: 02 Seite 7 listet
``passive_intel.dns_security``, ``header_check``-Korrelation,
``tr03116_checker``). Da das Reporter-Modul nicht direkt auf die raw
Scan-Daten zugreift, leiten wir alles aus den Findings + dem optional
schon im ``report_data`` befindlichen TR-03116-Block ab. Das ist die
Single-Source-of-Truth, durch die der Determinismus-Block laeuft.

Abgrenzung zu ``reporter/posture_aggregator.py``: dieses Modul
aggregiert nur fuer EINEN Scan und schreibt nichts in die DB. Der
existierende ``posture_aggregator.py`` ist DB-gebunden und macht
Subscription-Lifecycle.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# Erwartete Sub-Indikatoren-Reihenfolge pro Kategorie (stabil fuer Render).
EMAIL_SUBS = ("SPF", "DKIM", "DMARC")
WEB_SUBS = ("HSTS", "CSP", "X-Frame", "Cookies")
DNS_SUBS = ("AXFR", "Dangling", "DNSSEC")
TLS_SUBS = ("TLS-Cipher", "TLS-Version", "TR-03116")


# ====================================================================
# FINDING-MATCHER
# ====================================================================
def _matches_policy(finding: dict, *prefixes: str) -> bool:
    pid = (finding.get("policy_id") or "").upper().strip()
    return any(pid.startswith(p) for p in prefixes)


def _matches_finding_type(finding: dict, *needles: str) -> bool:
    ft = (finding.get("finding_type") or "").lower().strip()
    return any(n in ft for n in needles)


def _matches_text(finding: dict, *needles: str) -> bool:
    blob = " ".join((
        str(finding.get("title") or ""),
        str(finding.get("description") or ""),
        str(finding.get("evidence") or ""),
    )).lower()
    return any(n in blob for n in needles)


# ====================================================================
# E-MAIL-AUTHENTIFIZIERUNG
# ====================================================================
def _email_indicator(findings: list[dict]) -> list[tuple[str, str]]:
    """Drei Sub-Indikatoren SPF / DKIM / DMARC.

    Default: 'ok' (kein Befund = nichts beanstandet).
    Wenn ein Finding mit Type/Text spezifisch auf ein Sub-Element zeigt,
    wird das Sub auf 'fail' (fehlt) oder 'warn' (Konfiguration suboptimal,
    z.B. DMARC p=none) gesetzt.
    """
    spf, dkim, dmarc = "ok", "ok", "ok"

    for f in findings:
        if not _matches_policy(f, "SP-DNS") and not _matches_finding_type(
            f, "mail_security", "spf", "dkim", "dmarc",
        ):
            continue
        ft = (f.get("finding_type") or "").lower()
        text_blob = " ".join((
            str(f.get("title") or ""), str(f.get("description") or ""),
        )).lower()

        if "spf" in ft or "spf" in text_blob:
            if "missing" in ft or "fehl" in text_blob:
                spf = "fail"
            elif "weak" in ft or "softfail" in text_blob or "~all" in text_blob:
                spf = "warn"
        if "dkim" in ft or "dkim" in text_blob:
            if "missing" in ft or "fehl" in text_blob:
                dkim = "fail"
        if "dmarc" in ft or "dmarc" in text_blob:
            if "missing" in ft or ("fehl" in text_blob and "dmarc" in text_blob):
                dmarc = "fail"
            elif "p=none" in text_blob or "dmarc_none" in ft:
                dmarc = "warn"

        # Generisches "mail_security_missing" ohne Sub-Hinweis: alle drei,
        # die noch 'ok' sind, abklappern und konservativ auf 'warn' setzen
        # (mind. ein Sub-Element ist nicht okay).
        if ft == "mail_security_missing" and spf == "ok" and dkim == "ok" and dmarc == "ok":
            dkim = "warn"

    return [
        ("SPF", spf),
        ("DKIM", dkim),
        ("DMARC", dmarc),
    ]


# ====================================================================
# WEB-HYGIENE
# ====================================================================
def _web_indicator(findings: list[dict]) -> list[tuple[str, str]]:
    """HSTS / CSP / X-Frame / Cookies — pro Sub: ok wenn kein Finding."""
    hsts, csp, xframe, cookies = "ok", "ok", "ok", "ok"
    for f in findings:
        if not _matches_policy(f, "SP-HDR", "SP-CSP", "SP-COOK", "SP-CSRF"):
            continue
        ft = (f.get("finding_type") or "").lower()
        text_blob = " ".join((
            str(f.get("title") or ""), str(f.get("description") or ""),
        )).lower()
        if "hsts" in ft or "hsts" in text_blob or "strict-transport" in text_blob:
            hsts = "fail"
        if "csp" in ft or "content-security-policy" in text_blob:
            csp = "fail"
        if "x-frame" in ft or "x-frame" in text_blob or "clickjack" in text_blob:
            xframe = "fail"
        if "cookie" in ft or "samesite" in text_blob or "httponly" in text_blob:
            cookies = "warn" if cookies == "ok" else cookies
    return [
        ("HSTS", hsts),
        ("CSP", csp),
        ("X-Frame", xframe),
        ("Cookies", cookies),
    ]


# ====================================================================
# DNS-HYGIENE
# ====================================================================
def _dns_indicator(findings: list[dict]) -> list[tuple[str, str]]:
    """AXFR / Dangling / DNSSEC. Default ok wenn nicht erwaehnt."""
    axfr, dangling, dnssec = "ok", "ok", "ok"
    for f in findings:
        ft = (f.get("finding_type") or "").lower()
        text_blob = " ".join((
            str(f.get("title") or ""), str(f.get("description") or ""),
        )).lower()
        if "axfr" in ft or "axfr" in text_blob or "zone transfer" in text_blob:
            axfr = "fail"
        if "dangling" in ft or "dangling" in text_blob or "takeover" in text_blob:
            dangling = "fail"
        if "dnssec" in ft or "dnssec" in text_blob:
            dnssec = "warn" if dnssec == "ok" else dnssec
    return [
        ("AXFR", axfr),
        ("Dangling", dangling),
        ("DNSSEC", dnssec),
    ]


# ====================================================================
# TLS-KONFIGURATION
# ====================================================================
def _tls_indicator(
    findings: list[dict],
    tr03116_results: list[dict] | None,
) -> list[tuple[str, str]]:
    """Cipher / Version / TR-03116-4.

    TR-03116 nutzt — wenn vorhanden — den ``overall_status`` aus dem
    tr03116_checker-Output (PASS / WARN / FAIL).
    """
    cipher, version, tr = "ok", "ok", "ok"
    for f in findings:
        ft = (f.get("finding_type") or "").lower()
        text_blob = " ".join((
            str(f.get("title") or ""), str(f.get("description") or ""),
        )).lower()
        if not _matches_policy(f, "SP-TLS"):
            continue
        if "weak" in ft or "weak" in text_blob or "rc4" in text_blob or "3des" in text_blob:
            cipher = "fail"
        if "obsolete" in ft or "sslv3" in text_blob or "tls 1.0" in text_blob or "tls 1.1" in text_blob:
            version = "fail"

    if tr03116_results:
        worst = "PASS"
        order = {"PASS": 0, "WARN": 1, "FAIL": 2}
        for r in tr03116_results:
            status = (r.get("overall_status") or "PASS").upper()
            if order.get(status, 0) > order.get(worst, 0):
                worst = status
        tr = {"PASS": "ok", "WARN": "warn", "FAIL": "fail"}.get(worst, "ok")

    return [
        ("Ciphers", cipher),
        ("Version", version),
        ("TR-03116", tr),
    ]


# ====================================================================
# HAUPT-FUNKTION
# ====================================================================
def build_posture_indicators(
    claude_output: dict[str, Any] | None,
    tr03116_results: list[dict] | None = None,
) -> list[dict[str, Any]]:
    """Liefert die 4 Mini-Dashboards fuer Doc 02 Seite 7.

    Args:
        claude_output: Erwartet ``findings``-Liste.
        tr03116_results: Optional aus ``report_data["tr03116_compliance"]``.

    Returns:
        Liste mit 4 Eintraegen — jeder Eintrag ist Dict mit
        ``label`` (Anzeigen-Titel) und ``items`` (Liste (sub_label, status)).
    """
    findings = (claude_output or {}).get("findings") or []
    return [
        {
            "key": "email",
            "label": "E-Mail-Authentifizierung",
            "items": _email_indicator(findings),
        },
        {
            "key": "web",
            "label": "Web-Hygiene (HSTS/CSP)",
            "items": _web_indicator(findings),
        },
        {
            "key": "dns",
            "label": "DNS-Hygiene",
            "items": _dns_indicator(findings),
        },
        {
            "key": "tls",
            "label": "TLS-Konfiguration",
            "items": _tls_indicator(findings, tr03116_results),
        },
    ]


__all__ = [
    "EMAIL_SUBS", "WEB_SUBS", "DNS_SUBS", "TLS_SUBS",
    "build_posture_indicators",
]

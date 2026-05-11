"""Heuristik-Builder fuer Per-VHost-Beschreibungssatz + Klassifikation.

PR-E (Mai 2026): Erzeugt deterministisch einen 1-Satz-Snapshot pro VHost
und ordnet ihn einer Klasse zu, die spaeter den Default-Filter im UI
("Echte Sites" vs. "Panels" vs. "Skipped") steuert.

Datenquellen:
- ``vhost`` (aus ``host["vhosts"][i]``): fqdn, status, title, final_url, is_primary
- ``tech_profile`` (aus Phase 1 ``build_tech_profile``): cms, cms_version,
  server, technologies, open_ports
- ``skipped_entry`` (aus ``host["vhost_skipped"][i]``, fuer parking/extern-Redirects):
  reason, status, title

AI-Verfeinerung ist optional und passiert NACH diesem Modul in
``ai_site_descriptions.refine_with_ai`` — diese hier liefert die deterministische
Basis, die immer da ist.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

import structlog

log = structlog.get_logger()


Classification = Literal[
    "web_content",
    "control_panel",
    "login_only",
    "parking",
    "error",
    "non_web",
    "unknown",
]


@dataclass
class SiteSummary:
    """1-Satz-Snapshot pro VHost."""
    description: str
    classification: Classification
    is_real_content: bool
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["confidence"] = round(self.confidence, 2)
        return d


# ---------------------------------------------------------------------------
# Title-Blocklisten (case-insensitive Substring-Match)
# ---------------------------------------------------------------------------

GENERIC_DEFAULT_TITLES = (
    "apache2 ubuntu default page",
    "apache2 debian default page",
    "welcome to nginx",
    "it works!",
    "iis windows server",
    "default web site page",
    "test page for the apache",
    "tomcat default",
    "404 not found",
    "403 forbidden",
    "401 unauthorized",
    "500 internal server error",
    "502 bad gateway",
    "service unavailable",
)

CONTROL_PANEL_TITLES = (
    "plesk",
    "cpanel",
    "directadmin",
    "ispconfig",
    "webmin",
    "virtualmin",
    "froxlor",
)

LOGIN_TITLES = (
    "login",
    "anmeldung",
    "sign in",
    "sign-in",
    "log in",
    "log-in",
    "authenticate",
    "owa",  # Exchange Outlook Web Access
    "rdweb",
)

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000}
MAIL_PORTS = {25, 465, 587, 110, 143, 993, 995}
SSH_PORTS = {22, 2222}
FTP_PORTS = {21, 990}
DB_PORTS = {3306, 5432, 1433, 27017, 6379}


def _truncate(s: str, max_len: int = 120) -> str:
    s = s.strip()
    if len(s) <= max_len:
        return s
    return s[: max_len - 1].rstrip() + "…"


def _tech_label(tech_profile: dict[str, Any]) -> str:
    """Kompakter Tech-Stack-String, z.B. 'WordPress 6.4 auf Apache 2.4.62'."""
    parts: list[str] = []
    cms = (tech_profile or {}).get("cms")
    if cms:
        ver = tech_profile.get("cms_version")
        parts.append(f"{cms} {ver}" if ver else str(cms))
    server = (tech_profile or {}).get("server")
    if server:
        # Falls cms-Server-Banner identisch ist, nicht doppelt einbauen.
        if not parts or server.lower() not in parts[0].lower():
            parts.append(f"auf {server}" if parts else str(server))
    return " ".join(parts)


def classify(
    vhost: dict[str, Any],
    tech_profile: dict[str, Any] | None,
    skipped_entry: dict[str, Any] | None = None,
) -> SiteSummary:
    """Klassifiziere einen VHost basierend auf den verfuegbaren Signalen.

    Reihenfolge (erstes passendes Match gewinnt):

    1. skipped_entry mit reason=parking → ``parking``, is_real=False
    2. skipped_entry mit reason=redirect-extern → ``error``, is_real=False
    3. status >= 400 → ``error``, is_real=False
    4. title in GENERIC_DEFAULT_TITLES → ``error``, is_real=False
    5. title in CONTROL_PANEL_TITLES → ``control_panel``, is_real=True
    6. tech_profile.open_ports OHNE Web-Port → ``non_web``, is_real=False
    7. title in LOGIN_TITLES + status 200/401/403 → ``login_only``, is_real=True
    8. sonst → ``web_content``, is_real=True (Heuristik-Default)
    """
    # ── (1)/(2) skipped Entries ─────────────────────────────────────────
    if skipped_entry:
        reason = (skipped_entry.get("reason") or "").lower()
        if "parking" in reason:
            return SiteSummary(
                description="Parking-Page — Domain ist nicht aktiv im Einsatz",
                classification="parking",
                is_real_content=False,
                confidence=1.0,
            )
        if "extern" in reason or "redirect" in reason:
            target = skipped_entry.get("final_url") or "externes Ziel"
            return SiteSummary(
                description=_truncate(f"Redirect zu {target} — kein eigener Inhalt"),
                classification="error",
                is_real_content=False,
                confidence=1.0,
            )

    status = vhost.get("status")
    title = (vhost.get("title") or "").strip()
    title_lower = title.lower()
    tp = tech_profile or {}

    # ── (3) Error-Status ─────────────────────────────────────────────────
    if isinstance(status, int) and status >= 400:
        return SiteSummary(
            description=f"HTTP {status} — keine erreichbare Webseite",
            classification="error",
            is_real_content=False,
            confidence=1.0,
        )

    # ── (4) Generic Default Title ────────────────────────────────────────
    if title and any(g in title_lower for g in GENERIC_DEFAULT_TITLES):
        srv = tp.get("server") or "Webserver"
        return SiteSummary(
            description=f"Default-Page von {srv} — keine produktive Anwendung",
            classification="error",
            is_real_content=False,
            confidence=1.0,
        )

    # ── (5) Control-Panel ────────────────────────────────────────────────
    if title and any(p in title_lower for p in CONTROL_PANEL_TITLES):
        panel = next(p for p in CONTROL_PANEL_TITLES if p in title_lower)
        return SiteSummary(
            description=f"{panel.capitalize()}-Verwaltungspanel (Login-Seite)",
            classification="control_panel",
            is_real_content=True,
            confidence=1.0,
        )

    # ── (6) Non-Web (keine Web-Ports offen) ──────────────────────────────
    open_ports = set(tp.get("open_ports") or [])
    has_status = isinstance(status, int) and 200 <= status < 400
    if open_ports and not (open_ports & WEB_PORTS) and not has_status:
        services: list[str] = []
        if open_ports & MAIL_PORTS:
            services.append("Mail-Server")
        if open_ports & SSH_PORTS:
            services.append("SSH")
        if open_ports & FTP_PORTS:
            services.append("FTP")
        if open_ports & DB_PORTS:
            services.append("Datenbank")
        label = " + ".join(services) if services else "Nicht-HTTP-Dienst"
        return SiteSummary(
            description=f"{label} — keine oeffentliche Webseite",
            classification="non_web",
            is_real_content=False,
            confidence=1.0,
        )

    # ── (7) Login-Only (Titel signalisiert Login + 2xx/40x) ──────────────
    if title and any(l in title_lower for l in LOGIN_TITLES) \
            and isinstance(status, int) and status in (200, 201, 301, 302, 401, 403):
        tech = _tech_label(tp)
        descr = (
            f"Login-Seite ({tech})" if tech else "Login-Seite — kein oeffentlicher Inhalt"
        )
        return SiteSummary(
            description=_truncate(descr),
            classification="login_only",
            is_real_content=True,
            confidence=0.9,
        )

    # ── (8) Web-Content Default ──────────────────────────────────────────
    tech = _tech_label(tp)
    title_suffix = f' — Titel: "{title}"' if title else ""
    desc = (tech or "Webseite") + title_suffix
    return SiteSummary(
        description=_truncate(desc),
        classification="web_content",
        is_real_content=True,
        confidence=0.7,
    )


def build_summaries_for_host(
    host: dict[str, Any],
    tech_profile: dict[str, Any] | None,
) -> dict[str, SiteSummary]:
    """Erzeuge Summaries fuer alle vhosts + vhost_skipped eines Hosts.

    Returns:
        Dict ``{fqdn -> SiteSummary}``. Enthaelt sowohl primary VHosts
        (mit tech_profile-Inputs) als auch skipped Entries (parking,
        extern-redirect) damit der Filter "Skipped" alle erfassen kann.
    """
    out: dict[str, SiteSummary] = {}

    for v in host.get("vhosts") or []:
        fqdn = (v.get("fqdn") or "").strip()
        if not fqdn:
            continue
        out[fqdn] = classify(v, tech_profile, skipped_entry=None)

    for sk in host.get("vhost_skipped") or []:
        fqdn = (sk.get("fqdn") or "").strip()
        if not fqdn or fqdn in out:
            continue
        # Synthetic vhost-Dict aus dem skipped-Entry
        synthetic = {
            "fqdn": fqdn,
            "status": sk.get("status"),
            "title": sk.get("title"),
        }
        out[fqdn] = classify(synthetic, tech_profile, skipped_entry=sk)

    return out


def tech_label(tech_profile: dict[str, Any]) -> str:
    """Public Alias fuer _tech_label — kann der Caller fuer AI-Hints
    wiederverwenden (z.B. ``ai_site_descriptions.refine_with_ai``)."""
    return _tech_label(tech_profile)


__all__ = [
    "Classification",
    "SiteSummary",
    "GENERIC_DEFAULT_TITLES",
    "CONTROL_PANEL_TITLES",
    "LOGIN_TITLES",
    "classify",
    "build_summaries_for_host",
    "tech_label",
]

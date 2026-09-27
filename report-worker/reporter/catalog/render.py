"""Sicheres Rendern von ``affected_template`` und ``texts.observation``.

Templates benutzen ``str.format``-Platzhalter mit festen Variablennamen je Scope. Eine
unbekannte Variable ist ein Ladefehler (``validate_template``), ein fehlender Wert zur
Laufzeit wird nie zu ``?`` oder ``{...}``: Nonewerte heissen ``unbekannt``, Listen werden
mit Komma verbunden.
"""
from __future__ import annotations

import string
from typing import Any, Optional

from reporter.catalog import tables as T
from reporter.catalog.expr import CatalogSpecError
from reporter.catalog.scope import FactsIndex, Group, Item
from reporter.facts import schema as FS

UNKNOWN = "unbekannt"

# S6b-2 (spec/09 Q7): ZAP-Konfidenz im Kundentext deutsch.
CONFIDENCE_TEXT = {"High": "hoch", "Medium": "mittel", "Low": "niedrig", "Confirmed": "bestätigt"}

# Variablen je Scope fuer affected_template.
ITEM_VARS: dict[str, tuple[str, ...]] = {
    "scan": ("domain", "domains", "order_id"),
    "service": ("host_ip", "port", "proto", "service", "product", "product_or_service", "version", "family",
                "db_name", "admin_name", "mail_name", "legacy_name", "fqdn_names", "host_label", "tls_note",
                "mail_login", "admin_label", "kennung_label", "cert_validity_text", "cert_cn", "cert_issuer"),
    "host": ("host_ip", "fqdn_names", "host_label", "ports_list", "reverse", "abuseipdb_score", "otx_pulse_count"),
    "fqdn": ("fqdn", "host_ip", "title", "http_status", "final_url", "waf_name", "host_label", "year_hint_names"),
    "http": ("fqdn", "host_ip", "url", "score", "missing_headers", "missing_headers_basic", "server_header", "powered_by",
             "disclosure_headers", "hsts_max_age", "csp_flags", "duplicate_headers", "x_feserver", "wp_users",
             "wp_users_text",
             "wp_version_status", "host_label"),
    "http.alerts": ("fqdn", "host_ip", "plugin_id", "name", "risk", "confidence", "url_path", "count",
                    "host_label", "run_label"),
    "http.paths": ("fqdn", "host_ip", "url_path", "status", "host_label"),
    "http.cookies": ("fqdn", "host_ip", "name", "flags_missing", "host_label"),
    "tls": ("fqdn", "host_ip", "port", "legacy_protocols", "ciphers_weak", "vulns", "cert_cn", "days_left", "not_after",
            "issuer", "grade", "hsts_max_age", "host_label", "target", "days_left_text", "validity_text",
            "valid_elsewhere"),
    "tls.vulns": ("fqdn", "host_ip", "port", "name", "status", "host_label", "target", "name_label"),
    "dns": ("domain", "spf_raw", "spf_qualifier", "dmarc_p", "dmarc_raw", "mx", "mx_count", "ns", "dkim_selectors",
            "spf_shared_hosts", "dkim_selector_note", "dmarc_rua", "dmarc_rua_own", "dmarc_rua_foreign",
            "dmarc_delegated_to"),
    "dns.dangling_cnames": ("domain", "fqdn", "cname_target", "takeover_risk"),
    "software": ("host_ip", "fqdn", "product", "family", "kind", "version", "build", "edition", "eol_date", "eol_status",
                 "lifecycle_text",
                 "host_label", "vulnerabilities_count", "target_versions"),
    "passive": ("host_ip", "port", "product", "version", "source", "seen_at", "domain", "host_label",
                "product_or_banner", "login_url", "seen_date", "seen_text"),
    "threat": ("cve_id", "host_ip", "port", "cvss", "epss", "kev", "product", "version", "host_label"),
    "target": ("domain", "expires_at", "registrar", "days_left"),
}

# Variablen fuer texts.observation (Gruppenebene).
OBSERVATION_VARS: tuple[str, ...] = ("affected", "count", "group", "fqdn_names", "domain", "host_ip", "notes",
                                     "n", "m", "missing_header_names", "passed", "valid_elsewhere",
                                     "target_versions", "dmarc_rua", "mx", "dmarc_rua_own", "dmarc_rua_foreign",
                                     "dmarc_delegated_to", "version_headers", "feserver_names", "cert_summary", "shared_domains")
# S6b-4 (spec/11 T12, T14): Item-Werte, die die Engine ueber die fehlgeschlagenen Mitglieder einer
# Gruppe sammelt und als Gruppenvariable in Texte gibt.
COLLECT_VARS: tuple[str, ...] = ("valid_elsewhere", "target_versions", "dmarc_rua", "mx", "dmarc_rua_own",
                                  "dmarc_rua_foreign", "dmarc_delegated_to", "version_headers", "feserver_names", "cert_summary", "shared_domains")

# S6b-3 (spec/10 R2): Anzeigenamen der Sicherheits-Header im Kundentext.
HEADER_NAMES = {
    "x-frame-options": "X-Frame-Options", "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy",
    "content-security-policy": "Content-Security-Policy",
}


def header_names(keys: Any) -> list[str]:
    return [HEADER_NAMES.get(k, k) for k in keys or []]


def date_de(iso: Any, *, with_time: bool = False) -> Optional[str]:
    """ISO-Zeitpunkt als deutsches Datum ("24.09.2026", mit Uhrzeit "24.09.2026, 23:59 UTC")."""
    text = str(iso or "")
    if len(text) < 10 or text[4] != "-":
        return None
    out = f"{text[8:10]}.{text[5:7]}.{text[:4]}"
    if with_time and len(text) >= 16 and text[10] == "T" and text[11:16] != "00:00":
        out += f", {text[11:16]} UTC"
    return out


class Numerus:
    """Einzahl oder Mehrzahl nach der Zahl der benannten Hosts (S6b-1, spec/09 Teil 3).

    In Texten steht ``{n:Der Host|Die Hosts} {group} {n:bietet|bieten}``: vor dem
    senkrechten Strich die Einzahl, dahinter die Mehrzahl. Ohne Formatangabe steht
    die Zahl selbst da. Bis S6b-1 hiess es "Der Host A, B, C bietet" und bei mehr als
    drei Hosts "Der Host den geprueften Hosts bietet".
    """

    def __init__(self, count: int):
        self.count = int(count)

    def __format__(self, spec: str) -> str:
        if "|" in spec:
            one, many = spec.split("|", 1)
            return one if self.count == 1 else many
        return str(self.count)

    def __str__(self) -> str:
        return str(self.count)

    def __repr__(self) -> str:  # pragma: no cover - Anzeige in Fehlermeldungen
        return f"Numerus({self.count})"


def _s(value: Any) -> Any:
    if isinstance(value, Numerus):
        return value
    if value is None:
        return UNKNOWN
    if isinstance(value, bool):
        return "ja" if value else "nein"
    if isinstance(value, (list, tuple, set, frozenset)):
        vals = [str(v) for v in value if v is not None]
        return ", ".join(sorted(vals) if isinstance(value, (set, frozenset)) else vals) if vals else UNKNOWN
    return str(value)


class _Strict(dict):
    def __missing__(self, key: str) -> str:
        raise KeyError(key)


def template_fields(template: str) -> list[str]:
    out: list[str] = []
    for _, field_name, _, _ in string.Formatter().parse(template):
        if field_name:
            base = field_name.split(".")[0].split("[")[0]
            out.append(base)
    return out


def validate_template(template: str, allowed: tuple[str, ...] | set[str], where: str) -> None:
    for name in template_fields(template):
        if name not in allowed:
            raise CatalogSpecError(f"{where}: Template-Variable {{{name}}} ist hier nicht erlaubt (erlaubt: {', '.join(sorted(allowed))})")
    if "?" in template:
        raise CatalogSpecError(f"{where}: Fragezeichen im Template sind nicht erlaubt")


def format_strict(template: str, values: dict[str, Any], where: str) -> str:
    try:
        return template.format_map(_Strict({k: _s(v) for k, v in values.items()}))
    except KeyError as exc:
        raise CatalogSpecError(f"{where}: Template-Variable {exc} fehlt") from None


# Kennungen im Banner, die ein Produkt benennen (S6b-2, spec/09 Q13).
_BANNER_PRODUCTS: tuple[tuple[str, str], ...] = (
    ("sw-cp-server", "Plesk"), ("miniserv", "Webmin"), ("webmin", "Webmin"), ("plesk", "Plesk"),
    ("sonicwall", "SonicWall"), ("fortigate", "FortiGate"), ("fortinet", "Fortinet"),
    ("cpanel", "cPanel"), ("portainer", "Portainer"), ("proxmox", "Proxmox"),
    ("froxlor", "froxlor"), ("directadmin", "DirectAdmin"), ("ispconfig", "ISPConfig"),
    # S6b-4n (spec/11 N15): Standardports der CDN-Kante mit "Server: cloudflare" im Banner.
    ("server: cloudflare", "Cloudflare"),
)


def banner_product(banner: str | None) -> str | None:
    low = (banner or "").lower()
    for token, name in _BANNER_PRODUCTS:
        if token in low:
            return name
    return None


def _host_label(index: FactsIndex, ip: str | None) -> str:
    if not ip:
        return UNKNOWN
    names = index.host_fqdn_names(ip)
    return f"{ip} ({', '.join(names)})" if names else ip


def _version_of(*candidates: Any) -> str:
    for c in candidates:
        if c:
            return str(c)
    return UNKNOWN


def item_vars(scope: str, item: Item, group: Group, index: FactsIndex) -> dict[str, Any]:
    """Variablen fuer affected_template eines Items."""
    o = item.obj
    ip = item.host_ip
    v: dict[str, Any] = {"host_ip": ip, "host_label": _host_label(index, ip), "fqdn": item.fqdn, "port": item.port,
                         "domain": item.domain, "fqdn_names": index.host_fqdn_names(ip) if ip else []}
    if scope == "scan":
        v.update({"domain": o.domain, "domains": o.domains, "order_id": o.order_id})
    elif scope == "service":
        sw = next((s for s in index.software_by_ip.get(ip or "", []) if s.fqdn is None and s.family == o.family), None)
        product = (sw.product if sw else None) or o.product
        if o.port in T.DB_PORTS and sw is None:
            product = o.product if (o.product and "mysql" not in o.product.lower()) else T.DB_PORTS[o.port]
        # S6b-2 (spec/09 Q13): ohne nmap-Produkt nennt der Fingerabdruck die Software
        # ("Server: MiniServ" ist Webmin), nicht der geratene Portname.
        product = product or banner_product(o.fp_server) or banner_product(o.fp_title)
        if o.starttls is False:
            mail_login = "ohne STARTTLS"
        elif o.starttls is True and o.tls_required is False:
            mail_login = "mit Anmeldung vor STARTTLS"
        elif o.tls_required is False:
            mail_login = "ohne erzwungenes TLS"
        else:
            mail_login = ""
        v.update({"proto": o.proto, "service": o.service, "product": product, "product_or_service": product or o.service,
                  "mail_login": mail_login,
                  # S6b-2 (spec/09 Q13): die Verwaltungssoftware laut Fingerabdruck
                  # (Plesk auf 443 des Plesk-Servers, nicht "nginx").
                  "admin_label": (banner_product(o.fp_server) or banner_product(o.fp_title)
                                  or banner_product(o.product) or product or o.service),
                  "version": _version_of(sw.version_norm if sw else None, o.version_norm), "family": o.family,
                  "db_name": T.DB_PORTS.get(o.port), "admin_name": T.ADMIN_PORTS.get(o.port),
                  "mail_name": T.MAIL_PORTS.get(o.port), "legacy_name": T.LEGACY_PORTS.get(o.port),
                  # S6b-4n (spec/11 N15): mit STARTTLS "Anmeldung erst nach STARTTLS".
                  "tls_note": ("Anmeldung erst nach STARTTLS" if o.tls_required is True and o.starttls is True
                               else "TLS erzwungen" if o.tls_required is True
                               else ("STARTTLS" if o.starttls is True else "")),
                  # S6b-3 (spec/10 R9, R14): Kennung aus der Antwort des Dienstes; ohne Kennung
                  # "nicht identifiziert", nie der geratene nmap-Portname.
                  # MariaDB meldet sich im Handshake als "5.5.5-10.11.18-MariaDB" (Negativ-Fixture
                  # NEG-MARIADB-55): der Name kommt aus der Familie, nicht aus der Kennung.
                  "kennung_label": (mariadb_label(o) or o.kennung
                                    or ("nicht identifiziert" if o.unidentified else (product or o.service))),
                  "cert_validity_text": validity_text(o.cert, index.report_date) if o.cert else None,
                  "cert_cn": o.cert.cn if o.cert else None,
                  "cert_issuer": o.cert.issuer if o.cert else None,
                  # S6b-4n (spec/11 N10): das Zertifikat einmal fuer alle Ports (bergersysteme VS-003).
                  "cert_summary": ([f"Zertifikat {o.cert.cn}, {validity_text(o.cert, index.report_date)}"]
                                   if o.cert and o.cert.cn else []),
                  # S6b-4n (spec/11 N10, N11): weitere Domains des geteilten Servers je Quelle.
                  "shared_domains": _shared_domains(index, ip)})
    elif scope == "host":
        rep = o.reputation
        v.update({"ports_list": sorted(s.port for s in index.services_by_ip.get(o.ip, [])), "reverse": o.reverse,
                  "abuseipdb_score": rep.abuseipdb_score if rep else None,
                  "otx_pulse_count": rep.otx_pulse_count if rep else None})
    elif scope == "fqdn":
        names = [o.name, *index.aliases_for(o.name, o.host_ip)]
        v.update({"title": o.title, "http_status": o.http_status, "final_url": o.final_url,
                  "waf_name": o.waf.name if o.waf else None,
                  "year_hint_names": [n for n in names if T.YEAR_HINT.search(n)]})
    elif scope == "http":
        missing = sorted(k for k, sh in o.security_headers.items() if not sh.present)
        basic = ("x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy")
        missing_basic = header_names([k for k in basic if k in o.security_headers and not o.security_headers[k].present])
        csp_flags = []
        if o.csp:
            # S6b-3 (spec/10 R1): Freigaben mit ihrer Direktive, nur was den Befund traegt.
            if o.csp.script_unsafe_inline:
                csp_flags.append("unsafe-inline für Skripte")
            if o.csp.script_unsafe_eval:
                csp_flags.append("unsafe-eval für Skripte")
            if o.csp.wildcard_directives:
                csp_flags.append("Wildcard-Quelle in " + ", ".join(o.csp.wildcard_directives[:6]))
        disclosure = [f"{k}: {val}" for k, val in (("Server", o.server_header), ("X-Powered-By", o.powered_by),
                                                     ("X-AspNet-Version", o.aspnet_version),
                                                     ("X-FEServer", o.x_feserver)) if val]
        # S6b-4n (spec/11 N10): X-FEServer ist ein interner Servername, keine Version.
        version = [f"{k}: {val}" for k, val in (("Server", o.server_header), ("X-Powered-By", o.powered_by),
                                                  ("X-AspNet-Version", o.aspnet_version)) if val]
        v.update({"version_headers": [f"{item.fqdn or ip} ({', '.join(version)})"] if version else [],
                  "feserver_names": [f"{item.fqdn or ip} (X-FEServer: {o.x_feserver})"] if o.x_feserver else []})
        v.update({"url": o.url, "score": o.score, "missing_headers": missing, "missing_headers_basic": missing_basic,
                  "disclosure_headers": disclosure, "server_header": o.server_header,
                  "powered_by": o.powered_by, "hsts_max_age": o.hsts.max_age if o.hsts else None,
                  "csp_flags": csp_flags, "duplicate_headers": o.duplicate_headers, "x_feserver": o.x_feserver,
                  "wp_users": o.wordpress.users if o.wordpress else [],
                  # S6b-4n (E25, spec/11 N15): Anmeldenamen in Personenform nur als Anzahl und Fundweg.
                  "wp_users_text": wp_users_text(o.wordpress),
                  "wp_version_status": o.wordpress.version_status if o.wordpress else None})
    elif scope == "http.alerts":
        from reporter.catalog.scope import _url_path
        v.update({"plugin_id": o.plugin_id, "name": o.name, "risk": o.risk,
                  "confidence": CONFIDENCE_TEXT.get(o.confidence or "", "nicht angegeben"),
                  "url_path": _url_path(o.url), "count": o.count,
                  # S6b-2 (spec/09 Q14): die Quelle nennt den Lauf, aus dem die Meldung stammt.
                  "run_label": {"passive": "passiv gemeldet von ZAP",
                                "active": "aktiv gemeldet von ZAP"}.get(o.run or "", "gemeldet von ZAP")})
    elif scope == "http.paths":
        from reporter.catalog.scope import _url_path
        v.update({"url_path": _url_path(o.url), "status": o.status})
    elif scope == "http.cookies":
        flags = [n for n, on in (("Secure", o.secure), ("HttpOnly", o.httponly)) if not on]
        if not o.samesite:
            flags.append("SameSite")
        v.update({"name": o.name, "flags_missing": flags})
    elif scope == "tls":
        legacy = [p for p in T.TLS_LEGACY if o.protocols.get(p) is True]
        cert = o.cert
        v.update({"legacy_protocols": [p.replace("TLS1.", "TLS 1.") for p in legacy], "ciphers_weak": sorted(o.ciphers_weak),
                  "vulns": [x.name for x in o.vulns], "cert_cn": cert.cn if cert else None,
                  "days_left": cert.days_left if cert else None,
                  # S6b-1 (spec/09 Teil 3): "1 Tag", nicht "1 Tage"
                  "days_left_text": (None if not cert or cert.days_left is None
                                     else f"{cert.days_left} {'Tag' if cert.days_left == 1 else 'Tage'}"),
                  "not_after": (cert.not_after or "")[:10] if cert and cert.not_after else None,
                  # S6b-3 (spec/10 R18): absolutes Datum statt relativer Frist; liegt der
                  # Ablauf vor dem Berichtsdatum, sagt der Text das.
                  "validity_text": validity_text(cert, index.report_date),
                  "valid_elsewhere": valid_elsewhere_text(cert),
                  "issuer": cert.issuer if cert else None, "grade": o.grade,
                  "hsts_max_age": o.hsts.max_age if o.hsts else None, "target": f"{o.fqdn or ip}:{o.port}"})
    elif scope == "tls.vulns":
        parent = item.ctx.get("tls")
        v.update({"name": o.name, "status": o.status, "target": f"{parent.fqdn or ip}:{parent.port}" if parent else UNKNOWN,
                  # S6b-4 (spec/11 Teil 3 JW): testssl "VULNERABLE ... (likely mitigated)" bei BEAST.
                  "name_label": o.name + (", vermutlich abgeschwächt" if likely_mitigated(parent, o.name) else "")})
    elif scope == "dns":
        v.update({"domain": o.domain, "spf_raw": o.spf.raw if o.spf else None,
                  "spf_qualifier": o.spf.all_qualifier if o.spf else None, "dmarc_p": o.dmarc.p if o.dmarc else None,
                  "dmarc_raw": o.dmarc.raw if o.dmarc else None, "mx": o.mx, "mx_count": len(o.mx), "ns": o.ns,
                  "dkim_selectors": o.dkim.selectors if o.dkim else [],
                  # S6b-4 (spec/11 Teil 3 DB): Meldeadressen ohne "mailto:".
                  "dmarc_rua": [str(a).split(":", 1)[-1] for a in (o.dmarc.rua if o.dmarc else [])],
                  # S6b-4n (spec/11 N7): Meldeadressen je eigener und fremder Domain getrennt.
                  "dmarc_rua_own": _rua_split(o, index, eigene=True),
                  "dmarc_rua_foreign": _rua_split(o, index, eigene=False),
                  "dmarc_delegated_to": [o.dmarc.delegated_to] if o.dmarc and o.dmarc.delegated_to else [],
                  # S6b-4 (spec/11 Teil 3 JW): die gefundenen Selektoren im Positivbefund.
                  "dkim_selector_note": _selector_note(o.dkim.selectors if o.dkim else []),
                  # S6b-3 (spec/10 R19): freigegebene geteilte Server mit Betreiber.
                  "spf_shared_hosts": _spf_shared_label(o, index)})
    elif scope == "dns.dangling_cnames":
        v.update({"fqdn": o.fqdn, "cname_target": o.cname_target, "takeover_risk": o.takeover_risk})
    elif scope == "software":
        v.update({"product": product_name(o), "family": o.family, "kind": o.kind,
                  "version": _version_of(o.version_norm, o.version_raw),
                  "build": o.build, "edition": o.edition, "eol_date": date_de(o.eol.date) if o.eol.date else o.eol.date, "eol_status": o.eol.status,
                  # S6b-3 (spec/10 R6): Lebenszyklus mit Datum und Quelle je Produkt.
                  "lifecycle_text": lifecycle_text(o.eol),
                  "vulnerabilities_count": o.vulnerabilities_count,
                  # S6b-4n (spec/11 N9): "fehlerbereinigt ab" (hoechstes "behoben in") getrennt von
                  # "neueste laut wpscan"; liegt die Bereinigung ueber der neuesten Version, ist das
                  # Verzeichnis von wpscan veraltet.
                  "target_versions": [z] if (z := target_text(o)) else []})
    elif scope == "passive":
        v.update({"product": o.product, "version": o.version, "source": o.source, "seen_at": (o.seen_at or "")[:10] or None,
                  "domain": o.domain, "product_or_banner": o.product or banner_product(o.banner_excerpt),
                  # Adresse ohne Abfrageteil: Parameter sind kein Beleg und tragen "?" in den Text.
                  "login_url": (str((o.details or {}).get("login_over_http")).split("?")[0]
                                if (o.details or {}).get("login_over_http") else None),
                  "seen_date": date_de(o.service_seen_at or o.seen_at),
                  # S6b-4n (spec/11 N15): ohne Zeitstempel des Dienstes ist das Datum die letzte
                  # Aktualisierung des Hosteintrags bei der Quelle, nicht "gesehen am".
                  "seen_text": (f"gesehen am {date_de(o.service_seen_at)}" if o.service_seen_at
                                else f"Hosteintrag aktualisiert am {date_de(o.seen_at)}"
                                if o.seen_at else "ohne Datum")})
    elif scope == "threat":
        sw = item.ctx.get("software")
        v.update({"cve_id": o.cve_id, "cvss": o.cvss_nvd.score if o.cvss_nvd else None,
                  "epss": o.epss.score if o.epss else None, "kev": bool(o.kev and o.kev.listed),
                  "product": sw.product if sw else None, "version": _version_of(sw.version_norm if sw else None)})
    elif scope == "target":
        w = o.whois
        from reporter.facts.serialize import days_between
        v.update({"expires_at": (w.expires_at or "")[:10] if w and w.expires_at else None, "registrar": w.registrar if w else None,
                  "days_left": days_between(w.expires_at, index.facts.scan.finished_at) if w and w.expires_at else None})
    return v


def likely_mitigated(tls: Any, name: str) -> bool:
    """testssl haelt die Schwaeche fuer abgeschwaecht ("likely mitigated", BEAST neben TLS 1.1
    und 1.2)."""
    eintrag = next((e for e in (getattr(tls, "entries", None) or []) if e.id == name), None)
    return bool(eintrag and eintrag.finding and "likely mitigated" in eintrag.finding.lower())


def _shared_domains(index: FactsIndex, ip: str | None) -> list[str]:
    """"Auf dem Server liegen laut Passivquelle 2 weitere Domains" (spec/11 N10, N11); leer ohne
    Fakt. Vorher stand "laut Zertifikat oder Passivquelle weitere Domains" ohne Zertifikatsfakt
    und im Plural neben "1 weitere Domain"."""
    from reporter.facts.systems import foreign_domains_text
    host = index.hosts_by_ip.get(ip or "")
    text, n = foreign_domains_text(host.shared if host is not None else None)
    if not n:
        return []
    return [f"Auf dem Server {'liegt' if n == 1 else 'liegen'} {text}"]


def _spf_label_domains(h: Any) -> str:
    from reporter.facts.systems import foreign_domains_text
    text, _ = foreign_domains_text(h.shared if h is not None else None)
    return f", {text}" if text else ""


def wp_users_text(wp: Any) -> str:
    """"2 Anmeldenamen, gefunden über /wp-json/wp/v2/users" (Entscheidung E25): der Bericht geht an
    Hoster und Agentur weiter; die Namen selbst bleiben in den Rohdaten."""
    if wp is None or not getattr(wp, "users", None):
        return ""
    n = len(wp.users)
    text = f"{n} {'Anmeldename' if n == 1 else 'Anmeldenamen'}"
    wege = [str(w) for w in (getattr(wp, "users_found_by", None) or [])][:3]
    if wege:
        text += ", gefunden über " + ", ".join(wege)
    return text


def _rua_split(dns: Any, index: FactsIndex, *, eigene: bool) -> list[str]:
    """Meldeadressen der eigenen (``eigene``) oder fremder Domains, ohne "mailto:" (spec/11 N7)."""
    doms = [str(d).rstrip(".").lower() for d in (index.facts.scan.domains or [index.facts.scan.domain]) if d]
    out: list[str] = []
    for addr in (dns.dmarc.rua if dns.dmarc else []):
        adresse = str(addr).split(":", 1)[-1]
        host = adresse.split("@")[-1].rstrip(".").lower()
        eigen = any(host == d or host.endswith("." + d) for d in doms)
        if eigen == eigene:
            out.append(adresse)
    return out


def _selector_note(selectors: list[str]) -> str:
    if not selectors:
        return ""
    wort = "Selektor" if len(selectors) == 1 else "Selektoren"
    return f"({wort} {', '.join(selectors)})"


def _spf_shared_label(dns: Any, index: FactsIndex) -> list[str]:
    from reporter.catalog.expr import f_spf_shared_ips
    out = []
    for ip in f_spf_shared_ips(dns, index.hosts):
        h = index.hosts_by_ip.get(ip)
        shared = h.shared if h is not None else None
        # S6b-4 (spec/11 T9): Betreiber des Servers laut rDNS vor dem Netzbetreiber.
        weitere = _spf_label_domains(h)
        if shared is not None and shared.server_operator:
            dc = f" im Rechenzentrum {shared.operator}" if shared.operator else ""
            out.append(f"{ip}, Server von {shared.server_operator}{dc}{weitere}")
            continue
        op = shared.operator if shared is not None else None
        out.append((f"{ip} beim Hoster {op}" if op else ip) + weitere)
    return out


def lifecycle_text(eol: Any) -> Optional[str]:
    """Lebenszyklus mit Datum und Quelle ("Herstellerpflege bis 30.06.2028 laut Debian LTS")."""
    if eol is None:
        return None
    quelle = str(eol.source or "").split(",")[0].strip() or None
    quelle = {"endoflife_date": "endoflife.date"}.get(quelle or "", quelle)
    datum = date_de(eol.date)
    if eol.status == "eol":
        if not datum:
            return "Herstellerpflege beendet"
        return f"Herstellerpflege beendet {datum}" + (f" laut {quelle}" if quelle else "")
    if eol.status == "supported":
        if datum and quelle and getattr(eol, "lts_since", None):
            # S6b-4 (spec/11 T11): in der LTS-Phase nicht "aktuell", sondern Langzeitpflege.
            # S6b-4n (spec/11 N9, N15): Wortlaut wie die Hinweisspalte in 3.1, ohne zweite Klammer
            # hinter der Version ("Debian GNU/Linux 12 (in Langzeitpflege bis ...)").
            herausgeber = quelle.replace(" LTS", "")
            return f"in Langzeitpflege bis {datum} laut {herausgeber}"
        if datum and quelle:
            return f"Herstellerpflege bis {datum} laut {quelle}"
        return f"gepflegt laut {quelle}" if quelle else "gepflegt"
    return None


def mariadb_label(o: Any) -> Optional[str]:
    if getattr(o, "family", None) != "mariadb":
        return None
    return f"MariaDB {o.version_norm}" if getattr(o, "version_norm", None) else "MariaDB"


def _vkey(v: str) -> tuple:
    import re as _re
    return tuple(int(x) if x.isdigit() else 0 for x in _re.split(r"[.\-+]", str(v)) if x)


def product_name(sw: Any) -> str:
    """Produktname statt Slug (spec/11 N9): "Slider Revolution" statt "revslider"."""
    return T.PRODUCT_NAMES.get(getattr(sw, "family", "") or "", getattr(sw, "product", "") or "")


def fixed_version(sw: Any) -> Optional[str]:
    """Hoechste Version, in der eine laut wpscan genannte Schwachstelle behoben ist."""
    werte = [x.fixed_in for x in (getattr(sw, "vulnerabilities", None) or []) if x.fixed_in]
    return max(werte, key=_vkey) if werte else None


def wpscan_directory_stale(sw: Any) -> bool:
    """Liegt die Fehlerbereinigung ueber der neuesten Version laut wpscan (dortmund-beach revslider:
    behoben in 6.7.38, neueste 6.7.35)? Dann ist das Verzeichnis von wpscan veraltet."""
    fix, latest = fixed_version(sw), getattr(sw, "latest_version", None)
    return bool(fix and latest and _vkey(fix) > _vkey(latest))


def version_parts(sw: Any) -> list[str]:
    """"fehlerbereinigt ab 6.7.38", "neueste laut wpscan 6.7.35" (spec/11 N9); gleiche Werte stehen
    einmal ("neueste und fehlerbereinigte Version laut wpscan 7.5.5")."""
    fix, latest = fixed_version(sw), getattr(sw, "latest_version", None)
    if fix and latest and _vkey(fix) == _vkey(latest):
        return [f"neueste und fehlerbereinigte Version laut wpscan {latest}"]
    teile = []
    if fix:
        teile.append(f"fehlerbereinigt ab {fix}")
    if latest:
        teile.append(f"neueste laut wpscan {latest}")
    return teile


def target_text(sw: Any) -> Optional[str]:
    """"Slider Revolution fehlerbereinigt ab 6.7.38, neueste laut wpscan 6.7.35 (Verzeichnis von
    wpscan veraltet)" (spec/11 N9)."""
    teile = version_parts(sw)
    if not teile:
        return None
    if wpscan_directory_stale(sw):
        teile.append("Verzeichnis von wpscan veraltet")
    return f"{product_name(sw)} ({', '.join(teile)})"


def target_version(sw: Any) -> Optional[str]:
    """Zielversion einer Erweiterung laut wpscan: die aktuelle Version, mindestens aber die
    hoechste Version, in der eine genannte Schwachstelle behoben ist (spec/11 T12)."""
    kandidaten = [v for v in [getattr(sw, "latest_version", None),
                              *[x.fixed_in for x in (getattr(sw, "vulnerabilities", None) or []) if x.fixed_in]] if v]
    if not kandidaten:
        return None
    return max(kandidaten, key=_vkey)


def valid_elsewhere_text(cert: Any) -> list[str]:
    """ "195.50.179.4:443 und 195.50.179.6:443 (gültig bis 14.03.2027)" (spec/11 T14)."""
    orte = list(getattr(cert, "valid_elsewhere", None) or []) if cert is not None else []
    if not orte:
        return []
    bis = date_de(getattr(cert, "valid_elsewhere_not_after", None))
    text = (", ".join(orte[:-1]) + " und " + orte[-1]) if len(orte) > 1 else orte[0]
    return [f"{text} (gültig bis {bis})" if bis else text]


def validity_text(cert: Any, report_date: Optional[str]) -> Optional[str]:
    """ "gültig bis 24.09.2026, 23:59 UTC; am Scantag 1 Tag Restlaufzeit" oder, wenn das
    Berichtsdatum nach dem Ablauf liegt, "seit 24.09.2026, 23:59 UTC abgelaufen, sofern nicht
    erneuert" (spec/10 R18, Entscheidung DC E12)."""
    if cert is None or not cert.not_after:
        return None
    bis = date_de(cert.not_after, with_time=True)
    if cert.days_left is not None and cert.days_left < 0:
        return f"am Scantag seit {bis} abgelaufen"
    if report_date and str(cert.not_after)[:10] < str(report_date)[:10]:
        return f"seit {bis} abgelaufen, sofern nicht erneuert"
    if cert.days_left is None:
        return f"gültig bis {bis}"
    tage = f"{cert.days_left} {'Tag' if cert.days_left == 1 else 'Tage'}"
    return f"gültig bis {bis}; am Scantag {tage} Restlaufzeit"


def group_vars(group: Group, labels: list[str], notes: list[str],
               extra: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    out = {"affected": labels, "count": len(labels), "group": group.label, "fqdn_names": group.fqdn_names,
           "domain": group.domain or "", "host_ip": group.host.ip if group.host else "", "notes": notes,
           "n": Numerus(1), "m": Numerus(len(labels)), "missing_header_names": [], "passed": [],
           "valid_elsewhere": [], "target_versions": [], "dmarc_rua": [], "mx": [], "dmarc_rua_own": [],
           "dmarc_rua_foreign": [], "dmarc_delegated_to": [], "version_headers": [], "feserver_names": [],
           "cert_summary": [], "shared_domains": []}
    out.update(extra or {})
    return out


__all__ = ["ITEM_VARS", "OBSERVATION_VARS", "UNKNOWN", "Numerus", "validate_template", "format_strict", "template_fields",
           "item_vars", "group_vars"]

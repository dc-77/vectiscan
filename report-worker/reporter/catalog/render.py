"""Sicheres Rendern von ``affected_template`` und ``texts.observation``.

Templates benutzen ``str.format``-Platzhalter mit festen Variablennamen je Scope. Eine
unbekannte Variable ist ein Ladefehler (``validate_template``), ein fehlender Wert zur
Laufzeit wird nie zu ``?`` oder ``{...}``: Nonewerte heissen ``unbekannt``, Listen werden
mit Komma verbunden.
"""
from __future__ import annotations

import string
from typing import Any

from reporter.catalog import tables as T
from reporter.catalog.expr import CatalogSpecError
from reporter.catalog.scope import FactsIndex, Group, Item
from reporter.facts import schema as FS

UNKNOWN = "unbekannt"

# Variablen je Scope fuer affected_template.
ITEM_VARS: dict[str, tuple[str, ...]] = {
    "scan": ("domain", "domains", "order_id"),
    "service": ("host_ip", "port", "proto", "service", "product", "product_or_service", "version", "family",
                "db_name", "admin_name", "mail_name", "legacy_name", "fqdn_names", "host_label", "tls_note"),
    "host": ("host_ip", "fqdn_names", "host_label", "ports_list", "reverse", "abuseipdb_score", "otx_pulse_count"),
    "fqdn": ("fqdn", "host_ip", "title", "http_status", "final_url", "waf_name", "host_label", "year_hint_names"),
    "http": ("fqdn", "host_ip", "url", "score", "missing_headers", "missing_headers_basic", "server_header", "powered_by",
             "disclosure_headers", "hsts_max_age", "csp_flags", "duplicate_headers", "x_feserver", "wp_users",
             "wp_version_status", "host_label"),
    "http.alerts": ("fqdn", "host_ip", "plugin_id", "name", "risk", "confidence", "url_path", "count",
                    "host_label"),
    "http.paths": ("fqdn", "host_ip", "url_path", "status", "host_label"),
    "http.cookies": ("fqdn", "host_ip", "name", "flags_missing", "host_label"),
    "tls": ("fqdn", "host_ip", "port", "legacy_protocols", "ciphers_weak", "vulns", "cert_cn", "days_left", "not_after",
            "issuer", "grade", "hsts_max_age", "host_label", "target"),
    "tls.vulns": ("fqdn", "host_ip", "port", "name", "status", "host_label", "target"),
    "dns": ("domain", "spf_raw", "spf_qualifier", "dmarc_p", "dmarc_raw", "mx", "mx_count", "ns", "dkim_selectors"),
    "dns.dangling_cnames": ("domain", "fqdn", "cname_target", "takeover_risk"),
    "software": ("host_ip", "fqdn", "product", "family", "kind", "version", "build", "edition", "eol_date", "eol_status",
                 "host_label", "vulnerabilities_count"),
    "passive": ("host_ip", "port", "product", "version", "source", "seen_at", "domain", "host_label"),
    "threat": ("cve_id", "host_ip", "port", "cvss", "epss", "kev", "product", "version", "host_label"),
    "target": ("domain", "expires_at", "registrar", "days_left"),
}

# Variablen fuer texts.observation (Gruppenebene).
OBSERVATION_VARS: tuple[str, ...] = ("affected", "count", "group", "fqdn_names", "domain", "host_ip", "notes")


def _s(value: Any) -> str:
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
        v.update({"proto": o.proto, "service": o.service, "product": product, "product_or_service": product or o.service,
                  "version": _version_of(sw.version_norm if sw else None, o.version_norm), "family": o.family,
                  "db_name": T.DB_PORTS.get(o.port), "admin_name": T.ADMIN_PORTS.get(o.port),
                  "mail_name": T.MAIL_PORTS.get(o.port), "legacy_name": T.LEGACY_PORTS.get(o.port),
                  "tls_note": "TLS erzwungen" if o.tls_required is True else ("STARTTLS" if o.starttls is True else "")})
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
        missing_basic = [k for k in basic if k in o.security_headers and not o.security_headers[k].present]
        csp_flags = []
        if o.csp:
            csp_flags = [k for k, on in (("unsafe-inline", o.csp.unsafe_inline), ("unsafe-eval", o.csp.unsafe_eval),
                                         ("Wildcard", o.csp.wildcard)) if on]
        disclosure = [f"{k}: {val}" for k, val in (("Server", o.server_header), ("X-Powered-By", o.powered_by),
                                                     ("X-FEServer", o.x_feserver)) if val]
        v.update({"url": o.url, "score": o.score, "missing_headers": missing, "missing_headers_basic": missing_basic,
                  "disclosure_headers": disclosure, "server_header": o.server_header,
                  "powered_by": o.powered_by, "hsts_max_age": o.hsts.max_age if o.hsts else None,
                  "csp_flags": csp_flags, "duplicate_headers": o.duplicate_headers, "x_feserver": o.x_feserver,
                  "wp_users": o.wordpress.users if o.wordpress else [],
                  "wp_version_status": o.wordpress.version_status if o.wordpress else None})
    elif scope == "http.alerts":
        from reporter.catalog.scope import _url_path
        v.update({"plugin_id": o.plugin_id, "name": o.name, "risk": o.risk,
                  "confidence": o.confidence or "", "url_path": _url_path(o.url), "count": o.count})
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
                  "days_left": cert.days_left if cert else None, "not_after": (cert.not_after or "")[:10] if cert and cert.not_after else None,
                  "issuer": cert.issuer if cert else None, "grade": o.grade,
                  "hsts_max_age": o.hsts.max_age if o.hsts else None, "target": f"{o.fqdn or ip}:{o.port}"})
    elif scope == "tls.vulns":
        parent = item.ctx.get("tls")
        v.update({"name": o.name, "status": o.status, "target": f"{parent.fqdn or ip}:{parent.port}" if parent else UNKNOWN})
    elif scope == "dns":
        v.update({"domain": o.domain, "spf_raw": o.spf.raw if o.spf else None,
                  "spf_qualifier": o.spf.all_qualifier if o.spf else None, "dmarc_p": o.dmarc.p if o.dmarc else None,
                  "dmarc_raw": o.dmarc.raw if o.dmarc else None, "mx": o.mx, "mx_count": len(o.mx), "ns": o.ns,
                  "dkim_selectors": o.dkim.selectors if o.dkim else []})
    elif scope == "dns.dangling_cnames":
        v.update({"fqdn": o.fqdn, "cname_target": o.cname_target, "takeover_risk": o.takeover_risk})
    elif scope == "software":
        v.update({"product": o.product, "family": o.family, "kind": o.kind, "version": _version_of(o.version_norm, o.version_raw),
                  "build": o.build, "edition": o.edition, "eol_date": o.eol.date, "eol_status": o.eol.status,
                  "vulnerabilities_count": o.vulnerabilities_count})
    elif scope == "passive":
        v.update({"product": o.product, "version": o.version, "source": o.source, "seen_at": (o.seen_at or "")[:10] or None,
                  "domain": o.domain})
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


def group_vars(group: Group, labels: list[str], notes: list[str]) -> dict[str, Any]:
    return {"affected": labels, "count": len(labels), "group": group.label, "fqdn_names": group.fqdn_names,
            "domain": group.domain or "", "host_ip": group.host.ip if group.host else "", "notes": notes}


__all__ = ["ITEM_VARS", "OBSERVATION_VARS", "UNKNOWN", "validate_template", "format_strict", "template_fields",
           "item_vars", "group_vars"]

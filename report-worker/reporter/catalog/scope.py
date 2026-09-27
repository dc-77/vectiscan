"""Scopes, Gruppen und Bindungen: welche Fakten ein Check sieht und wie sie heissen.

Ein Check iteriert ueber einen Scope (``service``, ``tls``, ``http.alerts`` ...), die
Ergebnisse werden je Gruppe (``global``, ``domain``, ``host``, ``fqdn``) zusammengefasst.
Dieses Modul baut aus einem ``Facts``-Objekt einen Index, die Gruppen mit ihrem Kontext
(Bindungen fuer ``applicable_when``/``not_testable_when``) und die Items je Gruppe mit
ihrem Kontext (Bindungen fuer ``when``/``positive_when``).

Schluesselschema (Drift-Test): service ``ip:port``, host ``ip``, fqdn ``name@ip``,
http ``name@ip``, tls ``name:port@ip``, alert ``name@ip#plugin_id|name``, path
``name@ip#pfad``, cookie ``name@ip#name``, vuln ``name:port@ip#name``, dns ``domain``,
dangling ``domain#fqdn``, software ``sw-id``, passive ``quelle:ip:port``, threat
``cve@ip:port``, target ``domain``.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from reporter.catalog import tables as T
from reporter.catalog.expr import CALLABLE, CatalogSpecError
from reporter.facts import schema as FS
from reporter.facts.serialize import ip_token, sort_key

# ---------------------------------------------------------------- Scope-Definitionen


@dataclass(frozen=True)
class ScopeDef:
    name: str
    item_name: str
    item_type: Any
    parent_name: Optional[str] = None
    parent_type: Any = None
    allowed_group_by: tuple[str, ...] = ("global", "host")


SCOPES: dict[str, ScopeDef] = {
    "scan": ScopeDef("scan", "scan", FS.ScanFact, allowed_group_by=("global",)),
    "service": ScopeDef("service", "service", FS.ServiceFact),
    "host": ScopeDef("host", "host", FS.HostFact),
    "fqdn": ScopeDef("fqdn", "fqdn", FS.FqdnFact, allowed_group_by=("global", "host", "fqdn")),
    "http": ScopeDef("http", "http", FS.HttpFact, allowed_group_by=("global", "host", "fqdn")),
    "http.alerts": ScopeDef("http.alerts", "alert", FS.WebAlert, "http", FS.HttpFact, ("global", "host", "fqdn")),
    "http.paths": ScopeDef("http.paths", "path", FS.WebPath, "http", FS.HttpFact, ("global", "host", "fqdn")),
    "http.cookies": ScopeDef("http.cookies", "cookie", FS.Cookie, "http", FS.HttpFact, ("global", "host", "fqdn")),
    "tls": ScopeDef("tls", "tls", FS.TlsFact, allowed_group_by=("global", "host", "fqdn")),
    "tls.vulns": ScopeDef("tls.vulns", "vuln", FS.TlsVuln, "tls", FS.TlsFact, ("global", "host", "fqdn")),
    "dns": ScopeDef("dns", "dns", FS.DnsFact, allowed_group_by=("global", "domain")),
    "dns.dangling_cnames": ScopeDef("dns.dangling_cnames", "dangling", FS.DanglingCname, "dns", FS.DnsFact, ("global", "domain")),
    "software": ScopeDef("software", "software", FS.SoftwareFact, allowed_group_by=("global", "host", "fqdn")),
    "passive": ScopeDef("passive", "passive", FS.PassiveFact),
    "threat": ScopeDef("threat", "threat", FS.ThreatFact),
    "target": ScopeDef("target", "target", FS.TargetFact, allowed_group_by=("global", "domain")),
}

# Bindungen des Gruppenkontexts (fuer applicable_when, not_testable_when und alle Items).
GROUP_TYPES: dict[str, Any] = {
    "scan": FS.ScanFact, "host": FS.HostFact, "fqdn": FS.FqdnFact, "http": FS.HttpFact, "dns": FS.DnsFact,
    "target": FS.TargetFact, "hosts": list, "services": list, "ports": set, "http_list": list, "tls_list": list,
    "softwares": list, "passives": list, "threats": list, "fqdns": list, "items": list, "fqdn_names": list,
    "group_key": str, "coverage_ok": CALLABLE, "coverage_status": CALLABLE, "coverage_reason": CALLABLE,
    # S6b-3 (spec/10 R18): Berichtsdatum (JJJJ-MM-TT), ohne Angabe das Scanende.
    "report_date": str,
}


def binding_types(scope: str, group_by: str) -> dict[str, Any]:
    """Typtabelle fuer den Compiler: Gruppenbindungen plus Item- und Parent-Bindung."""
    sd = SCOPES.get(scope)
    if sd is None:
        raise CatalogSpecError(f"unbekannter scope {scope!r}")
    if group_by not in sd.allowed_group_by:
        raise CatalogSpecError(f"scope {scope!r} erlaubt group_by {sd.allowed_group_by}, nicht {group_by!r}")
    out = dict(GROUP_TYPES)
    out[sd.item_name] = sd.item_type
    if sd.parent_name:
        out[sd.parent_name] = sd.parent_type
    return out


# ---------------------------------------------------------------- Index


def _url_path(url: str | None) -> str:
    if not url:
        return ""
    parts = urlsplit(url)
    return parts.path or "/"


def _fqdn_key(name: str | None, ip: str) -> str:
    return f"{name or ip_token(ip)}@{ip_token(ip)}"


def without_third_party(facts: FS.Facts) -> FS.Facts:
    """Fakten ohne Drittanbieter-Adressen (S6b-1, spec/09 Teil 2).

    Eine Adresse, die der Scanner begruendet uebersprungen hat und auf die jeder
    Kundenname per CNAME nach draussen zeigt (Microsoft-Autodiscover bei
    bergersysteme), ist kein System des Kunden. Sie liefert weder Befunde noch
    Positivbefunde; der Bericht nennt sie als "Drittanbieter, nicht geprueft".
    """
    fremd = {h.ip for h in facts.hosts if h.third_party is not None}
    # S6b-4 (spec/11 T9, E18): Dienste anderer Nutzer eines geteilten Servers (Shoutcast und
    # Icecast auf dem Hoster-Server von castenow) sind kein Dienst des Kunden. Mit ihnen fallen
    # die Passiveintraege und die Software desselben Ports aus der Auswertung; der Bericht nennt
    # sie als eine Beobachtung beim Betreiber.
    fremde_ports = {(s.host_ip, s.port) for s in facts.services if getattr(s, "foreign", None)}
    if not fremd and not fremde_ports:
        return facts

    def keep(items: list, attr: str = "host_ip") -> list:
        return [x for x in items if getattr(x, attr, None) not in fremd]

    def software_fremd(sw: Any) -> bool:
        # Fremd, wenn ein Beleg an einem fremden Port steht und keiner an einem anderen Port
        # des Hosts; Belege ohne Port ("technologies: Icecast ...") entscheiden nicht.
        belege = [e.excerpt or "" for e in sw.evidence]
        ports = [port for ip, port in fremde_ports if ip == sw.host_ip]
        if not ports:
            return False
        am_port = [b for b in belege if re.match(r"\d+/", b)]
        return bool(am_port) and all(any(b.startswith(f"{p}/") for p in ports) for b in am_port)

    return facts.model_copy(update={
        "hosts": [h for h in facts.hosts if h.ip not in fremd],
        "fqdns": keep(facts.fqdns),
        "services": [s for s in keep(facts.services) if (s.host_ip, s.port) not in fremde_ports],
        "tls": [t for t in keep(facts.tls) if (t.host_ip, t.port) not in fremde_ports],
        "http": keep(facts.http),
        "software": [sw for sw in keep(facts.software) if not software_fremd(sw)],
        "passive": [p for p in keep(facts.passive) if (p.host_ip, p.port) not in fremde_ports],
        "threats": keep(facts.threats), "coverage": keep(facts.coverage),
        "unprocessed": keep(facts.unprocessed),
    })


class FactsIndex:
    """Nachschlagestrukturen ueber ein Facts-Objekt (einmal je Auswertung)."""

    def __init__(self, facts: FS.Facts, report_date: str | None = None):
        self.facts = facts
        self.report_date: str | None = (report_date or (facts.scan.finished_at or facts.scan.started_at or "")[:10]
                                        or None)
        self.domains: list[str] = list(facts.scan.domains) or [facts.scan.domain]
        self.hosts: list[FS.HostFact] = sorted(facts.hosts, key=lambda h: sort_key(h.family, h.ip))
        self.hosts_by_ip: dict[str, FS.HostFact] = {h.ip: h for h in self.hosts}
        self.services_by_ip: dict[str, list[FS.ServiceFact]] = defaultdict(list)
        for s in sorted(facts.services, key=lambda s: sort_key(s.host_ip, s.port, s.proto)):
            if s.state == "open":
                self.services_by_ip[s.host_ip].append(s)
        self.software_by_ip: dict[str, list[FS.SoftwareFact]] = defaultdict(list)
        self.software_by_key: dict[tuple[str, str], list[FS.SoftwareFact]] = defaultdict(list)
        for sw in sorted(facts.software, key=lambda x: sort_key(x.id)):
            self.software_by_ip[sw.host_ip].append(sw)
            if sw.fqdn:
                self.software_by_key[(sw.fqdn, sw.host_ip)].append(sw)
        self.passive_by_ip: dict[str, list[FS.PassiveFact]] = defaultdict(list)
        for p in sorted(facts.passive, key=lambda x: sort_key(x.id)):
            if p.host_ip:
                self.passive_by_ip[p.host_ip].append(p)
        self.threats_by_ip: dict[str, list[FS.ThreatFact]] = defaultdict(list)
        for t in sorted(facts.threats, key=lambda x: sort_key(x.id)):
            if t.host_ip:
                self.threats_by_ip[t.host_ip].append(t)
        self.http_by_key: dict[tuple[str, str], list[FS.HttpFact]] = defaultdict(list)
        self.http_by_ip: dict[str, list[FS.HttpFact]] = defaultdict(list)
        for h in sorted(facts.http, key=lambda x: sort_key(x.id)):
            self.http_by_key[(h.fqdn or ip_token(h.host_ip), h.host_ip)].append(h)
            self.http_by_ip[h.host_ip].append(h)
        self.tls_by_key: dict[tuple[str, str], list[FS.TlsFact]] = defaultdict(list)
        self.tls_by_ip: dict[str, list[FS.TlsFact]] = defaultdict(list)
        for t in sorted(facts.tls, key=lambda x: sort_key(x.id)):
            self.tls_by_key[(t.fqdn or ip_token(t.host_ip), t.host_ip)].append(t)
            self.tls_by_ip[t.host_ip].append(t)
        self.dns_by_domain: dict[str, FS.DnsFact] = {d.domain: d for d in facts.dns}
        self.primary_dns: FS.DnsFact | None = facts.dns[0] if facts.dns else None
        self.target_by_domain: dict[str, FS.TargetFact] = {t.domain: t for t in facts.targets}
        self.fqdn_by_key: dict[tuple[str, str], FS.FqdnFact] = {}
        self.fqdns_by_ip: dict[str, list[FS.FqdnFact]] = defaultdict(list)
        for f in sorted(facts.fqdns, key=lambda x: sort_key(x.name, x.host_ip)):
            # S6 (spec/08 Punkt 13): Ein Wildcard-Eintrag steht fuer alle nicht
            # einzeln benannten Namen und ist selbst kein pruefbarer Host. Er
            # wuerde sonst in jeder Betroffenenliste und unter jedem Bild stehen.
            if f.wildcard:
                continue
            self.fqdn_by_key[(f.name, f.host_ip)] = f
            self.fqdns_by_ip[f.host_ip].append(f)
        # Alias-Aufloesung: (alias, ip) -> kanonischer Name
        self.alias_of: dict[tuple[str, str], str] = {}
        for f in facts.fqdns:
            for a in f.aliases:
                if (a.fqdn, f.host_ip) not in self.fqdn_by_key or a.fqdn != f.name:
                    self.alias_of[(a.fqdn, f.host_ip)] = f.name
        self.coverage: list[FS.CoverageFact] = sorted(facts.coverage, key=lambda c: sort_key(c.tool, c.scope, c.host_ip, c.fqdn, c.domain))
        self.software_by_id: dict[str, FS.SoftwareFact] = {s.id: s for s in facts.software}

    # -- Hilfen ------------------------------------------------------------
    def host(self, ip: str | None) -> FS.HostFact | None:
        return self.hosts_by_ip.get(ip) if ip else None

    def canonical_name(self, name: str | None, ip: str) -> str | None:
        if name is None:
            return None
        return self.alias_of.get((name, ip), name)

    def aliases_for(self, name: str, ip: str) -> list[str]:
        f = self.fqdn_by_key.get((name, ip))
        return sorted(a.fqdn for a in f.aliases) if f else []

    def host_fqdn_names(self, ip: str) -> list[str]:
        names = set(self.hosts_by_ip[ip].fqdns) if ip in self.hosts_by_ip else set()
        names |= {f.name for f in self.fqdns_by_ip.get(ip, [])}
        # S6b-2 (spec/09 Teil 2 DB): ein Wildcard-Eintrag ist kein Hostname (spec/08 Punkt 13)
        # und steht auch nicht im Namen einer Gruppe.
        return sorted(n for n in names if not n.startswith("*."))

    def is_cdn_host(self, ip: str | None) -> bool:
        h = self.host(ip)
        if h is not None and h.cdn_provider:
            return True
        for s in self.services_by_ip.get(ip or "", []):
            if T.CDN_PRODUCTS.search(str(s.product or "")):
                return True
        for f in self.fqdns_by_ip.get(ip or "", []):
            if f.waf and f.waf.name and T.CDN_PRODUCTS.search(f.waf.name):
                return True
        return False

    def coverage_rows(self, tool: str, *, host_ip: str | None = None, fqdn: str | None = None,
                      domain: str | None = None) -> list[FS.CoverageFact]:
        """Zeilen eines Werkzeugs, vom engsten zum weitesten Geltungsbereich: fqdn, host, domain, scan."""
        rows = [c for c in self.coverage if c.tool == tool]
        if fqdn is not None:
            hit = [c for c in rows if c.fqdn == fqdn]
            if hit:
                return hit
        if host_ip is not None:
            hit = [c for c in rows if c.host_ip == host_ip]
            if hit:
                return hit
        dom = domain or (self.domains[0] if self.domains else None)
        if dom is not None:
            hit = [c for c in rows if c.domain == dom and c.host_ip is None]
            if hit:
                return hit
        return [c for c in rows if c.scope in ("scan", "domain") and c.host_ip is None and c.fqdn is None]

    def coverage_status(self, tool: str, **where: Any) -> tuple[str, str | None]:
        """(status, reason_code) fuer ein Werkzeug im Gruppenkontext; ``ok`` gewinnt."""
        rows = self.coverage_rows(tool, **where)
        if not rows:
            return "unknown", "no_coverage_rows"
        for r in rows:
            if r.status == "ok":
                return "ok", r.reason
        r = rows[0]
        return r.status, normalize_reason(r.reason, r.raw_status)


def normalize_reason(reason: str | None, raw_status: str | None = None) -> str:
    """Rohgrund aus coverage auf einen Code aus COVERAGE_REASONS abbilden."""
    text = (reason or "").strip()
    if not text:
        return raw_status or "no_output"
    low = text.lower()
    # S6 (spec/08 Punkt 9): Der Scanner schreibt fuer ein Werkzeug ausserhalb des
    # gebuchten Pakets teils "not_in_package", teils "package_<paket>"
    # (phase2, zap_active im WebCheck). Der zweite Fall stand in keiner Tabelle und
    # wurde deshalb zu "nicht pruefbar": der WebCheck-Bericht behauptete, die aktive
    # Webanalyse habe kein Ergebnis geliefert, obwohl das Paket sie gar nicht enthaelt.
    if low.startswith("package_") or low == "not_in_package":
        return "not_in_package"
    if low.startswith("wordlist_missing"):
        return "wordlist_missing"
    if low.startswith("timeout"):
        return "timeout"
    if "does_not_exist" in low:
        return "does_not_exist"
    if low.startswith("zap api error"):
        return "zap_api_error"
    if low.startswith("zap unreachable"):
        return "zap_unreachable"
    if low.startswith("exit_"):
        return "no_output"
    return text if text in T.COVERAGE_REASONS else text.split(":")[0] if text.split(":")[0] in T.COVERAGE_REASONS else text


# ---------------------------------------------------------------- Gruppen und Items


@dataclass
class Item:
    obj: Any
    key: str
    ctx: dict[str, Any]
    fact: Any                      # Faktum mit id/evidence (Item selbst oder Parent)
    claim_id: str
    host_ip: Optional[str] = None
    fqdn: Optional[str] = None
    port: Optional[int] = None
    domain: Optional[str] = None
    source_mode: str = "active"
    verified: Optional[bool] = None
    via_cdn: bool = False
    alias_of: Optional[str] = None


@dataclass
class Group:
    kind: str
    key: str
    label: str
    ctx: dict[str, Any] = field(default_factory=dict)
    items: list[Item] = field(default_factory=list)
    host: Optional[FS.HostFact] = None
    fqdn_name: Optional[str] = None
    domain: Optional[str] = None
    fqdn_names: list[str] = field(default_factory=list)
    dns_missing_reason: Optional[str] = None

    def coverage(self, index: FactsIndex, tool: str) -> tuple[str, str | None]:
        if self.kind == "fqdn":
            return index.coverage_status(tool, host_ip=self.host.ip if self.host else None, fqdn=self.fqdn_name)
        if self.kind == "host":
            return index.coverage_status(tool, host_ip=self.host.ip if self.host else None)
        if self.kind == "domain":
            return index.coverage_status(tool, domain=self.domain)
        return index.coverage_status(tool)


def _fact_mode(obj: Any) -> str:
    return getattr(obj, "mode", "active") or "active"


def _iter_items(index: FactsIndex, scope: str) -> list[Item]:
    """Alle Items eines Scopes ueber die ganze Faktendatei, mit Schluessel und Kontext."""
    f = index.facts
    out: list[Item] = []
    sd = SCOPES[scope]

    def add(obj: Any, key: str, fact: Any, claim_id: str, *, host_ip=None, fqdn=None, port=None, domain=None,
            extra: dict[str, Any] | None = None, verified=None) -> None:
        ctx = {sd.item_name: obj}
        if extra:
            ctx.update(extra)
        out.append(Item(obj=obj, key=key, ctx=ctx, fact=fact, claim_id=claim_id, host_ip=host_ip,
                        fqdn=index.canonical_name(fqdn, host_ip) if (fqdn and host_ip) else fqdn, port=port,
                        domain=domain, source_mode=_fact_mode(fact), verified=verified,
                        via_cdn=index.is_cdn_host(host_ip) if host_ip else False,
                        alias_of=(index.alias_of.get((fqdn, host_ip)) if fqdn and host_ip else None)))

    if scope == "scan":
        add(f.scan, "scan", f.scan, f.scan.id)
    elif scope == "service":
        for ip, svcs in sorted(index.services_by_ip.items(), key=lambda kv: sort_key(kv[0])):
            for s in svcs:
                add(s, f"{ip_token(ip)}:{s.port}", s, s.id, host_ip=ip, port=s.port)
    elif scope == "host":
        for h in index.hosts:
            add(h, ip_token(h.ip), h, h.id, host_ip=h.ip)
    elif scope == "fqdn":
        for (name, ip), fq in sorted(index.fqdn_by_key.items(), key=lambda kv: sort_key(kv[0][0], kv[0][1])):
            if (name, ip) in index.alias_of:
                continue
            add(fq, _fqdn_key(name, ip), fq, fq.id, host_ip=ip, fqdn=name)
    elif scope in ("http", "http.alerts", "http.paths", "http.cookies"):
        for (name, ip), hs in sorted(index.http_by_key.items(), key=lambda kv: sort_key(kv[0][0], kv[0][1])):
            for h in hs:
                base = _fqdn_key(h.fqdn, ip)
                if scope == "http":
                    add(h, base, h, h.id, host_ip=ip, fqdn=h.fqdn)
                elif scope == "http.alerts":
                    for a in h.alerts:
                        ident = a.plugin_id or a.name
                        add(a, f"{base}#{ident}", h, f"{h.id}#alert:{a.plugin_id or '-'}|{a.name}", host_ip=ip,
                            fqdn=h.fqdn, extra={"http": h})
                elif scope == "http.paths":
                    for p in h.paths:
                        add(p, f"{base}#{_url_path(p.url)}", h, f"{h.id}#path:{_url_path(p.url)}", host_ip=ip,
                            fqdn=h.fqdn, extra={"http": h})
                else:
                    for c in h.cookies:
                        add(c, f"{base}#{c.name}", h, f"{h.id}#cookie:{c.name}", host_ip=ip, fqdn=h.fqdn,
                            extra={"http": h})
    elif scope in ("tls", "tls.vulns"):
        for (name, ip), ts in sorted(index.tls_by_key.items(), key=lambda kv: sort_key(kv[0][0], kv[0][1])):
            for t in ts:
                base = f"{t.fqdn or ip_token(ip)}:{t.port}@{ip_token(ip)}"
                if scope == "tls":
                    add(t, base, t, t.id, host_ip=ip, fqdn=t.fqdn, port=t.port)
                else:
                    for v in t.vulns:
                        add(v, f"{base}#{v.name}", t, f"{t.id}#vuln:{v.name}", host_ip=ip, fqdn=t.fqdn, port=t.port,
                            extra={"tls": t})
    elif scope in ("dns", "dns.dangling_cnames"):
        for dom in index.domains:
            d = index.dns_by_domain.get(dom)
            if d is None:
                continue
            if scope == "dns":
                add(d, dom, d, d.id, domain=dom)
            else:
                for dc in d.dangling_cnames:
                    add(dc, f"{dom}#{dc.fqdn}", d, f"{d.id}#dangling:{dc.fqdn}", domain=dom, extra={"dns": d})
    elif scope == "software":
        for sw in sorted(f.software, key=lambda x: sort_key(x.id)):
            add(sw, sw.id, sw, sw.id, host_ip=sw.host_ip, fqdn=sw.fqdn)
    elif scope == "passive":
        for p in sorted(f.passive, key=lambda x: sort_key(x.id)):
            key = f"{p.source}:{ip_token(p.host_ip) if p.host_ip else (p.domain or '-')}:{p.port if p.port is not None else '-'}"
            add(p, key, p, p.id, host_ip=p.host_ip, port=p.port, domain=p.domain, verified=p.verified)
    elif scope == "threat":
        for t in sorted(f.threats, key=lambda x: sort_key(x.id)):
            sw = index.software_by_id.get(t.affected_software_ref or "")
            add(t, f"{t.cve_id}@{ip_token(t.host_ip) if t.host_ip else '-'}:{t.port if t.port is not None else '-'}",
                t, t.id, host_ip=t.host_ip, port=t.port, extra={"software": sw})
    elif scope == "target":
        for tg in sorted(f.targets, key=lambda x: sort_key(x.domain)):
            add(tg, tg.domain, tg, tg.id, domain=tg.domain)
    else:
        raise CatalogSpecError(f"unbekannter scope {scope!r}")
    return out


def _group_ctx(index: FactsIndex, g: Group) -> dict[str, Any]:
    f = index.facts
    ip = g.host.ip if g.host else None
    ctx: dict[str, Any] = {
        "scan": f.scan, "hosts": index.hosts, "group_key": g.key, "fqdn_names": g.fqdn_names,
        "host": g.host, "fqdn": None, "http": None, "dns": None, "target": None,
        "services": [], "ports": set(), "http_list": [], "tls_list": [], "softwares": [], "passives": [],
        "threats": [], "fqdns": [], "items": [], "report_date": index.report_date,
    }
    if g.kind in ("host", "fqdn") and ip:
        ctx["services"] = index.services_by_ip.get(ip, [])
        ctx["ports"] = {s.port for s in ctx["services"]}
        ctx["passives"] = index.passive_by_ip.get(ip, [])
        ctx["threats"] = index.threats_by_ip.get(ip, [])
        ctx["fqdns"] = [x for x in index.fqdns_by_ip.get(ip, []) if (x.name, ip) not in index.alias_of]
        ctx["dns"] = index.primary_dns
        ctx["target"] = index.target_by_domain.get(index.domains[0]) if index.domains else None
    if g.kind == "host" and ip:
        ctx["http_list"] = index.http_by_ip.get(ip, [])
        ctx["tls_list"] = index.tls_by_ip.get(ip, [])
        ctx["softwares"] = index.software_by_ip.get(ip, [])
    elif g.kind == "fqdn" and ip:
        name = g.fqdn_name
        ctx["fqdn"] = index.fqdn_by_key.get((name, ip)) if name else None
        hl = index.http_by_key.get((name or ip_token(ip), ip), [])
        ctx["http_list"] = hl
        ctx["http"] = hl[0] if hl else None
        ctx["tls_list"] = index.tls_by_key.get((name or ip_token(ip), ip), [])
        ctx["softwares"] = [s for s in index.software_by_ip.get(ip, []) if s.fqdn in (None, name)]
    elif g.kind == "domain":
        ctx["dns"] = index.dns_by_domain.get(g.domain or "")
        ctx["target"] = index.target_by_domain.get(g.domain or "")
    elif g.kind == "global":
        ctx["dns"] = index.primary_dns
        ctx["target"] = index.target_by_domain.get(index.domains[0]) if index.domains else None
        ctx["services"] = [s for ip_ in index.services_by_ip for s in index.services_by_ip[ip_]]
        ctx["ports"] = {s.port for s in ctx["services"]}
        ctx["http_list"] = list(f.http)
        ctx["tls_list"] = list(f.tls)
        ctx["softwares"] = list(f.software)
        ctx["passives"] = list(f.passive)
        ctx["threats"] = list(f.threats)
        ctx["fqdns"] = [x for (n, i), x in index.fqdn_by_key.items() if (n, i) not in index.alias_of]

    def coverage_status(tool: str) -> str:
        return g.coverage(index, tool)[0]

    def coverage_reason(tool: str) -> str | None:
        return g.coverage(index, tool)[1]

    def coverage_ok(tool: str) -> bool:
        return g.coverage(index, tool)[0] == "ok"

    ctx["coverage_status"] = coverage_status
    ctx["coverage_reason"] = coverage_reason
    ctx["coverage_ok"] = coverage_ok
    return ctx


def build_groups(index: FactsIndex, scope: str, group_by: str) -> list[Group]:
    """Gruppen fuer einen Check inklusive Kontext und zugeordneter Items."""
    if scope not in SCOPES:
        raise CatalogSpecError(f"unbekannter scope {scope!r}")
    items = _iter_items(index, scope)
    groups: dict[str, Group] = {}
    order: list[str] = []

    def ensure(kind: str, key: str, **kw: Any) -> Group:
        if key not in groups:
            groups[key] = Group(kind=kind, key=key, label=kw.pop("label", key), **kw)
            order.append(key)
        return groups[key]

    if group_by == "global":
        label = ", ".join(index.domains)
        g = ensure("global", "scan", label=label, fqdn_names=[])
        g.items = items
    elif group_by == "domain":
        for dom in index.domains:
            g = ensure("domain", dom, label=dom, domain=dom, fqdn_names=[])
            if dom not in index.dns_by_domain:
                st, reason = index.coverage_status("dns", domain=dom)
                g.dns_missing_reason = reason if (reason and st != "ok" and reason != "no_coverage_rows") else "no_dns_facts"
        for it in items:
            if it.domain and it.domain in groups:
                groups[it.domain].items.append(it)
    elif group_by == "host":
        for h in index.hosts:
            ensure("host", ip_token(h.ip), label=f"{h.ip} ({', '.join(index.host_fqdn_names(h.ip))})" if index.host_fqdn_names(h.ip) else h.ip,
                   host=h, fqdn_names=index.host_fqdn_names(h.ip))
        for it in items:
            if it.host_ip is None:
                continue
            key = ip_token(it.host_ip)
            if key not in groups:
                ensure("host", key, label=it.host_ip, host=index.host(it.host_ip), fqdn_names=index.host_fqdn_names(it.host_ip))
            groups[key].items.append(it)
    elif group_by == "fqdn":
        for (name, ip), fq in sorted(index.fqdn_by_key.items(), key=lambda kv: sort_key(kv[0][0], kv[0][1])):
            if (name, ip) in index.alias_of:
                continue
            aliases = index.aliases_for(name, ip)
            ensure("fqdn", _fqdn_key(name, ip), label=name if not aliases else f"{name} (+{', '.join(aliases)})",
                   host=index.host(ip), fqdn_name=name, fqdn_names=[name, *aliases])
        for it in items:
            if it.host_ip is None:
                continue
            name = it.fqdn
            key = _fqdn_key(name, it.host_ip)
            if key not in groups:
                ensure("fqdn", key, label=name or it.host_ip, host=index.host(it.host_ip), fqdn_name=name,
                       fqdn_names=[name] if name else [])
            groups[key].items.append(it)
    else:
        raise CatalogSpecError(f"unbekanntes group_by {group_by!r}")

    result: list[Group] = []
    for key in order:
        g = groups[key]
        g.ctx = _group_ctx(index, g)
        g.ctx["items"] = [it.obj for it in g.items]
        result.append(g)
    return result


__all__ = ["SCOPES", "ScopeDef", "GROUP_TYPES", "binding_types", "FactsIndex", "Group", "Item",
           "build_groups", "normalize_reason"]

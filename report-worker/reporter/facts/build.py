"""Builder: ScanBundle -> Facts (spec/05 M1 und M5).

Reihenfolge der Quellen je Feld steht im README des Pakets. Kurzfassung:
strukturierte Tar-Datei vor Zeilen-Rohtext, ausser bei den bekannten Tar-Luecken
(header_check je VHost, testssl-Protokolle, KI#3-Konfiguration, IPv6-nmap).
Der Builder erzeugt keine Befunde und keine Einstufungen.
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from reporter.facts import schema as S
from reporter.facts.nmap_parse import NmapHost, NmapRun, derive_service_flags, parse_nmap_text, parse_nmap_xml
from reporter.facts.serialize import (
    days_between, dumps, excerpt, ip_family, ip_token, iso_utc, sha256_text_file, short_hash,
    sort_key, try_json,
)
from reporter.facts.sources import (
    ScanBundle, ToolRun, apply_overrides, attach_orders_json, load_from_snapshot, load_scan_source,
    load_tool_runs, merge_tool_runs,
)
from reporter.facts.testssl_parse import (
    VULN_SEVERITIES as TESTSSL_VULN_SEVERITIES, TestsslResult, parse_testssl,
)
from reporter.facts.tool_coverage import WEB_PORTS, HostSignals, build_coverage, derive_blocked
from reporter.facts.versions import Normalized, lookup_eol, normalize

GENERATOR_NAME = "reporter.facts"
GENERATOR_VERSION = "1.0.0"

_LOGIN_URL_RE = re.compile(r"/owa/auth/logon|wp-login|/login|/signin|/auth/|login_uid", re.I)
_OWA_BUILD_RE = re.compile(r"/owa/auth/(\d+\.\d+\.\d+(?:\.\d+)?)/")
_TOOL_VERSION_RE = re.compile(r"^(\S+)\s+(.*)$")
TOOLS_WITHOUT_PARSER = frozenset({"katana", "nuclei", "nikto", "dalfox", "gowitness", "amass", "gobuster_dir"})
# httpx-"Technologien", die keine Software sind (Header-Merkmale, Formate).
NON_SOFTWARE_TECH = frozenset({"hsts", "open graph", "pwa", "rss", "json", "xml", "webp", "http/2", "http/3",
                               "priority hints", "module federation"})
MAX_EVIDENCE = 5
MAX_PATHS = 200


class _Ctx:
    def __init__(self, bundle: ScanBundle):
        self.b = bundle
        self.warnings: list[str] = list(bundle.warnings)
        self.unprocessed: list[S.UnprocessedFact] = []
        self.software: dict[tuple, S.SoftwareFact] = {}
        self.runs: dict[tuple[str, Optional[str]], list[ToolRun]] = defaultdict(list)
        for r in bundle.tool_runs:
            self.runs[(r.tool_norm, r.host_ip)].append(r)
        meta = bundle.meta or {}
        self.started = iso_utc(meta.get("startedAt"))
        finished = iso_utc(meta.get("finishedAt"))
        if not finished:
            created = [r.created_at for r in bundle.tool_runs if r.created_at]
            finished = max(created) if created else None
        self.finished = finished
        self.scan_date = (finished or self.started or "")[:10] or None
        self.nmap_runs: dict[str, Optional[NmapRun]] = {}
        self.nmap_hosts: dict[str, Optional[NmapHost]] = {}
        self.testssl: dict[str, Optional[TestsslResult]] = {}
        self.id_seen: set[str] = set()

    def warn(self, text: str) -> None:
        if text not in self.warnings:
            self.warnings.append(text)

    def run_time(self, tool: str, ip: Optional[str] = None, fqdn: Optional[str] = None) -> Optional[str]:
        runs = self.runs.get((tool, ip)) or []
        if fqdn:
            for r in runs:
                if r.vhost() == fqdn and r.created_at:
                    return r.created_at
        for r in runs:
            if r.created_at:
                return r.created_at
        return None

    def unique_id(self, base: str, suffix: str) -> str:
        fid = base
        if fid in self.id_seen:
            fid = f"{base}@{suffix}"
        n = 2
        while fid in self.id_seen:
            fid = f"{base}@{suffix}#{n}"
            n += 1
        self.id_seen.add(fid)
        return fid

    def add_unprocessed(self, kind: str, what: str, *, host_ip=None, fqdn=None, count=1,
                        source="facts_builder", ref: str = "", excerpt_text: str = "") -> None:
        fid = f"unp:{kind}:{short_hash(f'{what}|{host_ip}|{fqdn}')}"
        for u in self.unprocessed:
            if u.id == fid:
                u.count += count
                return
        self.unprocessed.append(S.UnprocessedFact(
            id=fid, source=source, mode="active", observed_at=self.finished,
            confidence=S.CONFIDENCE_DERIVED, kind=kind, what=what[:300], host_ip=host_ip, fqdn=fqdn,
            count=count, evidence=[S.Evidence(tool=source, ref=ref, excerpt=excerpt(excerpt_text))] if ref else [],
        ))


# ------------------------------------------------------------------ Einstieg

def build_facts(scan_data_dir: str | Path | None, host_inventory: dict | None = None,
                tech_profiles: list | None = None, correlated_findings: list | None = None,
                job_payload: dict | None = None, *, tool_runs: Any = None,
                order: dict | None = None, orders_json: str | Path | None = None) -> S.Facts:
    """Spec-Signatur (spec/07 S1) plus optionale Kwargs ``tool_runs`` und ``order``.

    ``scan_data_dir`` ist ein entpacktes Scan-Verzeichnis oder direkt das ``.tar.gz``.
    ``tool_runs`` sind die ``scan_results``-Zeilen (Liste, DB-Dicts oder Pfad zu
    ``results.json``); ohne sie bleibt die Coverage ``unknown``.
    """
    if scan_data_dir is None:
        raise ValueError("scan_data_dir (Tar oder Verzeichnis) ist erforderlich")
    bundle = load_scan_source(scan_data_dir)
    if tool_runs is not None:
        runs, name, sha = load_tool_runs(tool_runs)
        merge_tool_runs(bundle, runs, name=name, sha256=sha)
    if orders_json:
        attach_orders_json(bundle, orders_json)
    apply_overrides(bundle, host_inventory=host_inventory, tech_profiles=tech_profiles,
                    correlated_findings=correlated_findings, job_payload=job_payload, order=order)
    return build_from_bundle(bundle)


def build_from_snapshot(order_dir: str | Path) -> S.Facts:
    return build_from_bundle(load_from_snapshot(order_dir))


def build_from_bundle(bundle: ScanBundle) -> S.Facts:
    ctx = _Ctx(bundle)
    b = bundle
    inv_hosts = [h for h in (b.host_inventory.get("hosts") or []) if isinstance(h, dict) and h.get("ip")]
    inv_by_ip = {str(h["ip"]): h for h in inv_hosts}
    all_ips = sorted(set(inv_by_ip) | set(b.hosts), key=sort_key)
    for ip in all_ips:
        if ip not in inv_by_ip:
            ctx.warn(f"Host {ip} hat Werkzeugausgaben, steht aber nicht im Host-Inventar")

    _prepare_hosts(ctx, all_ips)
    scan = _build_scan(ctx)
    targets, primary_domain, extra_domains = _build_targets(ctx, inv_hosts)
    hosts, signals, blocked = _build_hosts(ctx, all_ips, inv_by_ip)
    fqdns = _build_fqdns(ctx, all_ips, inv_by_ip)
    services = _build_services(ctx, all_ips)
    tls = _build_tls(ctx, all_ips, inv_by_ip)
    http = _build_http(ctx, all_ips, inv_by_ip)
    dns = _build_dns(ctx, [primary_domain, *extra_domains])
    _software_from_profiles(ctx, all_ips)
    software = _finish_software(ctx)
    passive = _build_passive(ctx, all_ips, inv_by_ip, primary_domain)
    coverage = build_coverage(b, signals, blocked, ctx.finished, primary_domain, extra_domains)
    threats = _build_threats(ctx, software, services)
    _unprocessed_from_bundle(ctx)
    decisions = _build_decisions(ctx, all_ips, inv_by_ip)

    if extra_domains:
        ctx.warn("Multi-Target: nur die erste Domain hat eigene DNS- und Passivlaeufe; "
                 "weitere Domains: " + ", ".join(extra_domains))

    generator = S.Generator(name=GENERATOR_NAME, version=GENERATOR_VERSION, inputs=_generator_inputs(b))
    facts = S.Facts(
        schema_version=S.FACTS_SCHEMA_VERSION, generator=generator, scan=scan,
        targets=targets, hosts=hosts, fqdns=fqdns, services=services, tls=tls, http=http, dns=dns,
        software=software, passive=passive, coverage=coverage, threats=threats,
        unprocessed=sorted(ctx.unprocessed, key=lambda u: sort_key(u.kind, u.host_ip, u.fqdn, u.id)),
        decisions=decisions, warnings=sorted(ctx.warnings),
    )
    _check_ids(facts)
    return facts


def _generator_inputs(b: ScanBundle) -> list[S.GeneratorInput]:
    inputs = [S.GeneratorInput(kind=b.source_kind, name=b.source_name, sha256=b.source_sha256)]
    if b.tool_runs_name:
        inputs.append(S.GeneratorInput(kind="tool_runs", name=b.tool_runs_name, sha256=b.tool_runs_sha256))
    try:
        import reporter.eol_data_generated as feed
        p = Path(feed.__file__)
        inputs.append(S.GeneratorInput(kind="eol_feed", name=p.name, sha256=sha256_text_file(p)))
    except Exception:  # noqa: BLE001 - Feed optional
        inputs.append(S.GeneratorInput(kind="eol_feed", name="eol_data_generated.py", sha256=None))
    return inputs


def _check_ids(facts: S.Facts) -> None:
    seen: set[str] = set()
    for f in facts.all_facts():
        if f.id in seen:
            raise ValueError(f"doppelte Fakt-ID: {f.id}")
        seen.add(f.id)


# ------------------------------------------------------------------ Vorbereitung je Host

def _prepare_hosts(ctx: _Ctx, ips: list[str]) -> None:
    for ip in ips:
        h = ctx.b.hosts.get(ip)
        run: Optional[NmapRun] = None
        if h is not None and h.nmap_xml:
            run = parse_nmap_xml(h.nmap_xml)
        if run is None and h is not None and h.nmap_txt:
            run = parse_nmap_text(h.nmap_txt, ip)
        ctx.nmap_runs[ip] = run
        ctx.nmap_hosts[ip] = run.host_for(ip) if run else None
        ts: Optional[TestsslResult] = None
        if h is not None and (h.testssl_json is not None or h.testssl_txt):
            ts = parse_testssl(h.testssl_json, h.testssl_txt, host_ip=ip)
            if ts.json_filtered and not ts.text_parsed:
                ctx.warn(f"testssl {ip}: Tar-JSON ohne Protokollzeilen (severity-Filter), "
                         "Protokolle bleiben unbekannt")
        ctx.testssl[ip] = ts


# ------------------------------------------------------------------ scan

def _build_scan(ctx: _Ctx) -> S.ScanFact:
    b = ctx.b
    meta = b.meta or {}
    tool_versions: dict[str, Optional[str]] = {}
    for entry in meta.get("toolVersions") or []:
        m = _TOOL_VERSION_RE.match(str(entry).strip())
        if not m:
            continue
        name, rest = m.group(1), m.group(2).strip()
        ver = None if rest.startswith("(") else rest.split()[0]
        tool_versions.setdefault(name, ver)
    nmap_args = None
    egress = None
    for ip in sorted(ctx.nmap_runs, key=sort_key):
        run = ctx.nmap_runs[ip]
        if run is None:
            continue
        if run.version and not tool_versions.get("nmap"):
            tool_versions["nmap"] = run.version
        if nmap_args is None and run.args:
            nmap_args = re.sub(r"/tmp/scan-[^\s]+", "<scan-dir>", run.args)
        host = ctx.nmap_hosts.get(ip)
        if host and egress is None:
            for p in host.ports:
                f = derive_service_flags(p)
                if f.egress_ip:
                    egress = f.egress_ip
                    break
    for ip, ts in ctx.testssl.items():
        pass
    domains = list(b.targets)
    domain = domains[0] if domains else str(meta.get("domain") or b.host_inventory.get("domain") or "")
    fp = sum(1 for c in b.correlated_findings if isinstance(c, dict) and c.get("is_false_positive"))
    policy = meta.get("policyVersion") or None
    ev = [S.Evidence(tool="meta", ref="meta.json" if b.source_kind != "snapshot" else "order.json",
                     excerpt=excerpt(f"startedAt={meta.get('startedAt')} finishedAt={meta.get('finishedAt')}"))]
    return S.ScanFact(
        id=f"scan:{b.order_id}", source="meta", mode="active", observed_at=ctx.finished,
        confidence=S.CONFIDENCE_TOOL, evidence=ev, order_id=b.order_id,
        package=str(meta.get("package") or "unknown"), domain=domain, domains=domains,
        started_at=ctx.started, finished_at=ctx.finished,
        tool_versions=[S.ToolVersion(name=k, version=v) for k, v in sorted(tool_versions.items())],
        nmap_args=nmap_args, scanner_egress=egress,
        hosts_scanned=meta.get("hostsScanned") if isinstance(meta.get("hostsScanned"), int) else None,
        counts=S.ScanCounts(tool_runs=len(b.tool_runs), correlated_findings=len(b.correlated_findings),
                            correlated_fp=fp),
        policy_version=str(policy) if policy else None,
    )


# ------------------------------------------------------------------ targets

def _build_targets(ctx: _Ctx, inv_hosts: list[dict]) -> tuple[list[S.TargetFact], Optional[str], list[str]]:
    b = ctx.b
    domains = list(b.targets)
    if not domains:
        dom = b.host_inventory.get("domain") or (b.meta or {}).get("domain")
        domains = [str(dom)] if dom else []
    primary = domains[0] if domains else None
    extra = domains[1:]
    out_of_scope: list[S.OutOfScope] = []
    for sh in b.host_inventory.get("skipped_hosts") or []:
        if isinstance(sh, dict) and sh.get("ip"):
            out_of_scope.append(S.OutOfScope(kind="skipped_host", value=str(sh["ip"]),
                                             reason=str(sh.get("reason") or sh.get("_reasoning") or "max_hosts")[:160],
                                             host_ip=str(sh["ip"])))
        elif isinstance(sh, str):
            out_of_scope.append(S.OutOfScope(kind="skipped_host", value=sh, reason="max_hosts", host_ip=sh))
    for h in inv_hosts:
        for vs in h.get("vhost_skipped") or []:
            if isinstance(vs, dict) and vs.get("fqdn"):
                out_of_scope.append(S.OutOfScope(kind="vhost_skipped", value=str(vs["fqdn"]),
                                                 reason=str(vs.get("reason") or "")[:160] or None,
                                                 host_ip=str(h.get("ip"))))
    out_of_scope.sort(key=lambda o: sort_key(o.kind, o.value, o.host_ip))
    whois = _whois(b.passive.get("whois"))
    facts: list[S.TargetFact] = []
    for i, dom in enumerate(domains):
        ev = [S.Evidence(tool="host_inventory", ref=b.refs.get("host_inventory", ""), excerpt=f"domain={dom}")]
        # Issue #12: WHOIS laeuft seit S2b auch fuer jede weitere Domain.
        # Aeltere Scans haben dafuer nichts, dann bleibt es bei None.
        dom_whois = (whois if i == 0
                     else _whois((b.passive_by_domain.get(dom) or {}).get("whois")))
        facts.append(S.TargetFact(
            id=f"target:{dom}", source="host_inventory" if i == 0 else b.targets_source, mode="active",
            observed_at=ctx.started or ctx.finished, confidence=S.CONFIDENCE_TOOL, evidence=ev,
            domain=dom, is_primary=(i == 0), targets_source=b.targets_source,
            whois=dom_whois,
            discovery_health=b.host_inventory.get("discovery_health") if i == 0 else None,
            out_of_scope=out_of_scope if i == 0 else [],
        ))
    return facts, primary, extra


def _whois(data: Any) -> Optional[S.Whois]:
    if not isinstance(data, dict):
        return None
    d = data.get("domain") if isinstance(data.get("domain"), dict) else data
    if not isinstance(d, dict):
        return None
    dnssec = d.get("dnssec")
    if isinstance(dnssec, str):
        dnssec = dnssec.lower() in ("signed", "yes", "true", "signeddelegation")
    w = S.Whois(registrar=d.get("registrar"), created_at=iso_utc(d.get("creation_date") or d.get("created")),
                expires_at=iso_utc(d.get("expiration_date") or d.get("expires")),
                dnssec=dnssec if isinstance(dnssec, bool) else None)
    if not any([w.registrar, w.created_at, w.expires_at, w.dnssec is not None]):
        return None
    return w


# ------------------------------------------------------------------ hosts

def _build_hosts(ctx: _Ctx, ips: list[str], inv_by_ip: dict[str, dict]) -> tuple[list[S.HostFact], dict[str, HostSignals], dict[str, S.Blocked]]:
    b = ctx.b
    facts: list[S.HostFact] = []
    signals: dict[str, HostSignals] = {}
    blocked_map: dict[str, S.Blocked] = {}
    abuse = b.passive.get("abuseipdb") if isinstance(b.passive.get("abuseipdb"), dict) else {}
    greynoise = b.passive.get("greynoise") if isinstance(b.passive.get("greynoise"), dict) else {}
    for ip in ips:
        inv = inv_by_ip.get(ip, {})
        h = b.hosts.get(ip)
        run = ctx.nmap_runs.get(ip)
        nh = ctx.nmap_hosts.get(ip)
        open_ports = [p for p in (nh.ports if nh else []) if p.state == "open"]
        sig = HostSignals(ip=ip, nmap_run=run, nmap_host=nh,
                          web_ports_open=any(p.port in WEB_PORTS or p.tunnel == "ssl" for p in open_ports),
                          open_port_count=len(open_ports))
        headers_map = _headers_by_vhost(ctx, ip)
        sig.headers_reachable = {vh: (res.get("reachable") if isinstance(res, dict) else None)
                                 for vh, res in headers_map.items()}
        sig.httpx_has_output = bool(h and (h.httpx_lines or h.httpx_rows)) if h else None
        ts = ctx.testssl.get(ip)
        sig.testssl_connect_failed = ts.connect_failed if ts else None
        sig.testssl_has_data = bool(ts and ts.has_data and not ts.connect_failed)
        if h and h.zap_spider_summary and isinstance(h.zap_spider_summary.get("urls_found"), int):
            sig.zap_spider_urls = h.zap_spider_summary["urls_found"]
        elif h and h.zap_spider_urls is not None:
            sig.zap_spider_urls = len(h.zap_spider_urls)
        # Issue #13: Alertzahl aus dem Tar (Liste) oder aus der Zeile
        # (Zusammenfassung mit total_alerts). Nur wenn eine der beiden Quellen
        # vorliegt, ist die Zahl belastbar; sonst bleibt sie None und die
        # Abdeckung aendert sich nicht.
        if h and h.zap_alerts is not None:
            sig.zap_alerts_total = len(h.zap_alerts)
        elif h and isinstance((h.zap_summary or {}).get("total_alerts"), int):
            sig.zap_alerts_total = h.zap_summary["total_alerts"]
        if inv.get("blocked") is True:
            sig.inventory_blocked = S.Blocked(detected=True, reason=str(inv.get("blocked_reason") or "blocked")[:160],
                                              source="inventory")
        blocked = derive_blocked(sig, b.tool_runs)
        signals[ip] = sig
        blocked_map[ip] = blocked

        closed = filtered = None
        if nh is not None:
            closed = nh.extraports.get("closed")
            filtered = nh.extraports.get("filtered")
            for p in nh.ports:
                if p.state == "closed":
                    closed = (closed or 0) + 1
                elif p.state == "filtered":
                    filtered = (filtered or 0) + 1
        nmap_state = nh.state if nh else ("skipped" if run and not run.hosts_total else None)
        reachable: Optional[bool] = None
        if nmap_state == "up" or any(v is True for v in sig.headers_reachable.values()) \
                or any(isinstance(v.get("status"), int) for v in inv.get("vhosts") or [] if isinstance(v, dict)):
            reachable = True
        elif nmap_state == "down":
            reachable = False
        a = abuse.get(ip) if isinstance(abuse, dict) else None
        provider = None
        if isinstance(a, dict):
            provider = S.Provider(isp=a.get("isp"), usage_type=a.get("usageType"), country=a.get("countryCode"))
        pi = inv.get("passive_intel") if isinstance(inv.get("passive_intel"), dict) else {}
        gn = greynoise.get(ip) if isinstance(greynoise, dict) else None
        rep = S.Reputation(
            abuseipdb_score=_int_or_none(pi.get("abuseipdb_score", (a or {}).get("abuseConfidenceScore"))),
            is_tor=_bool_or_none(pi.get("is_tor", (a or {}).get("isTor"))),
            otx_pulse_count=_int_or_none(pi.get("otx_pulse_count")),
            urlhaus_compromised=_bool_or_none(pi.get("urlhaus_compromised")),
            greynoise_classification=(gn.get("classification") if isinstance(gn, dict) else pi.get("greynoise_classification")),
        )
        if not any(v is not None for v in rep.model_dump().values()):
            rep = None
        ev: list[S.Evidence] = []
        if h and h.refs.get("nmap.xml"):
            ev.append(S.Evidence(tool="nmap", ref=h.refs["nmap.xml"], excerpt=excerpt(run.summary if run else "", 160)))
        elif h and h.nmap_txt and (ctx.runs.get(("nmap", ip))):
            ev.append(S.Evidence(tool="nmap", ref=ctx.runs[("nmap", ip)][0].ref, excerpt=excerpt(run.summary if run else "", 160)))
        if inv:
            ev.append(S.Evidence(tool="host_inventory", ref=b.refs.get("host_inventory", ""),
                                 excerpt=excerpt(f"ip={ip} rdns={inv.get('rdns')} fqdns={','.join(inv.get('fqdns') or [])}", 200)))
        observed = (nh.end_time if nh else None) or ctx.run_time("nmap", ip) or ctx.finished
        facts.append(S.HostFact(
            id=f"host:{ip_token(ip)}", source="nmap" if nh else "host_inventory", mode="active",
            observed_at=observed, confidence=S.CONFIDENCE_TOOL if nh else S.CONFIDENCE_DERIVED, evidence=ev,
            ip=ip, family=ip_family(ip), reverse=inv.get("rdns") or None, provider=provider,
            reachable=reachable, nmap_state=nmap_state,
            ports_summary=S.PortsSummary(open=len(open_ports), closed=closed, filtered=filtered),
            blocked=blocked, cdn_provider=inv.get("cdn_provider") or None,
            edge_ips=sorted(str(x) for x in (inv.get("edge_ips") or [])),
            reputation=rep, fqdns=sorted((str(x) for x in (inv.get("fqdns") or [])), key=sort_key),
        ))
    return facts, signals, blocked_map


def _int_or_none(v: Any) -> Optional[int]:
    try:
        return int(v) if v is not None and not isinstance(v, bool) else None
    except (TypeError, ValueError):
        return None


def _bool_or_none(v: Any) -> Optional[bool]:
    return v if isinstance(v, bool) else None


def _headers_by_vhost(ctx: _Ctx, ip: str) -> dict[str, dict[str, Any]]:
    """Header-Ergebnisse je VHost, in fester Rangfolge.

    1. Tar-Datei je VHost (Issue #10, seit S2b) — das ungekuerzte Original.
    2. ``scan_results``-Zeile je VHost — auf 50000 Zeichen gekappt und im
       Snapshot zusaetzlich normalisiert.
    3. Legacy ``headers.json`` — nur der primaere VHost.

    Beide Quellen beschreiben dieselbe Messung, die reichere gewinnt. Aeltere
    Tars kennen Stufe 1 nicht, dort bleibt die bisherige Reihenfolge.
    """
    h = ctx.b.hosts.get(ip)
    out: dict[str, dict[str, Any]] = {}
    if h is None:
        return out
    for vh, res in h.headers_by_vhost_tar.items():
        out[vh] = res
    for vh, res in h.headers_by_vhost.items():
        out.setdefault(vh, res)
    if h.headers_json and isinstance(h.headers_json, dict):
        url = str(h.headers_json.get("url") or "")
        vh = urlsplit(url).hostname if url else None
        if vh and vh not in out:
            out[vh] = h.headers_json
    return out


# ------------------------------------------------------------------ fqdns

def _build_fqdns(ctx: _Ctx, ips: list[str], inv_by_ip: dict[str, dict]) -> list[S.FqdnFact]:
    b = ctx.b
    facts: list[S.FqdnFact] = []
    probe_time = ctx.run_time("web_probe") or ctx.started or ctx.finished
    for ip in ips:
        inv = inv_by_ip.get(ip, {})
        h = b.hosts.get(ip)
        vhosts = [v for v in (inv.get("vhosts") or []) if isinstance(v, dict) and v.get("fqdn")]
        by_name = {str(v["fqdn"]): v for v in vhosts}
        names = sorted(set(by_name) | {str(x) for x in (inv.get("fqdns") or [])}, key=sort_key)
        for name in names:
            v = by_name.get(name, {})
            waf = _waf_for(h, name, inv.get("ip"), b)
            aliases = [S.Alias(fqdn=str(a.get("fqdn")), status=_int_or_none(a.get("status")), reason=a.get("reason"))
                       for a in (v.get("aliases") or []) if isinstance(a, dict) and a.get("fqdn")]
            screenshot = v.get("screenshot_minio_key") or (inv.get("screenshot_minio_key") if len(vhosts) <= 1 else None)
            ev = [S.Evidence(tool="web_probe", ref=b.refs.get("host_inventory", ""),
                             excerpt=excerpt(f"{name}: status={v.get('status')} title={v.get('title')} final_url={v.get('final_url')}", 220))]
            facts.append(S.FqdnFact(
                id=ctx.unique_id(f"fqdn:{name}", ip_token(ip)), source="web_probe", mode="active",
                observed_at=probe_time, confidence=S.CONFIDENCE_TOOL, evidence=ev,
                name=name, host_ip=ip, http_status=_int_or_none(v.get("status")), title=v.get("title") or None,
                final_url=v.get("final_url") or None, body_hash=v.get("body_hash") or None,
                is_primary=_bool_or_none(v.get("is_primary")), aliases=aliases, screenshot_key=screenshot or None,
                web_probe_reachable=(True if isinstance(v.get("status"), int) else (False if v else None)),
                waf=waf,
            ))
    facts.sort(key=lambda f: sort_key(f.name, f.host_ip))
    return facts


def _waf_for(h, fqdn: str, ip: Any, b: ScanBundle) -> Optional[S.Waf]:
    if h is not None and h.wafw00f:
        for entry in h.wafw00f:
            if not isinstance(entry, dict):
                continue
            url_host = urlsplit(str(entry.get("url") or "")).hostname
            if url_host == fqdn:
                detected = entry.get("detected")
                name = entry.get("firewall")
                manu = entry.get("manufacturer")
                return S.Waf(detected=bool(detected) if detected is not None else None,
                             name=None if name in (None, "None") else str(name),
                             manufacturer=None if manu in (None, "None") else str(manu))
    if h is not None and fqdn in h.wafw00f_text:
        txt = h.wafw00f_text[fqdn]
        if "No WAF detected" in txt:
            return S.Waf(detected=False)
        m = re.search(r"is behind (.+?) WAF", txt) or re.search(r"\[\+\] The site .* is behind (.+?)\s*$", txt, re.M)
        if m:
            return S.Waf(detected=True, name=m.group(1).strip())
    if h is not None and h.tech_profile:
        vr = (h.tech_profile.get("vhost_results") or {}).get(fqdn)
        if isinstance(vr, dict) and vr.get("waf"):
            return S.Waf(detected=True, name=str(vr["waf"]))
    return None


# ------------------------------------------------------------------ services

def _build_services(ctx: _Ctx, ips: list[str]) -> list[S.ServiceFact]:
    facts: list[S.ServiceFact] = []
    for ip in ips:
        nh = ctx.nmap_hosts.get(ip)
        run = ctx.nmap_runs.get(ip)
        if nh is None:
            continue
        h = ctx.b.hosts.get(ip)
        ref = (h.refs.get("nmap.xml") if h and run and run.source_format == "xml" else None) \
            or (ctx.runs[("nmap", ip)][0].ref if ctx.runs.get(("nmap", ip)) else (h.refs.get("nmap.txt") if h else ""))
        observed = nh.end_time or ctx.run_time("nmap", ip) or ctx.finished
        for p in nh.ports:
            if p.state != "open":
                continue
            flags = derive_service_flags(p)
            norm = normalize(p.product, p.version, context=p.extrainfo) if (p.product or p.version) else None
            line = f"{p.port}/{p.proto} {p.state} {p.service or ''} {p.product or ''} {p.version or ''}" \
                   + (f" ({p.extrainfo})" if p.extrainfo else "") + (" tunnel=ssl" if p.tunnel == "ssl" else "")
            ev = [S.Evidence(tool="nmap", ref=ref or "", excerpt=excerpt(line, 200))]
            for sid in ("pop3-capabilities", "imap-capabilities", "smtp-commands", "mysql-info", "ftp-anon", "http-methods"):
                out = p.script(sid)
                if out:
                    ev.append(S.Evidence(tool="nmap", ref=ref or "", excerpt=excerpt(f"{sid}: {out}", 240)))
            cert = None
            if flags.cert_cn or flags.cert_not_after:
                cert = S.CertShort(cn=flags.cert_cn, san=flags.cert_san, not_after=flags.cert_not_after)
            conf = (p.conf / 10.0) if isinstance(p.conf, int) and 0 < p.conf <= 10 else S.CONFIDENCE_DERIVED
            facts.append(S.ServiceFact(
                id=f"svc:{ip_token(ip)}:{p.port}/{p.proto}", source="nmap", mode="active", observed_at=observed,
                confidence=conf, evidence=ev[:MAX_EVIDENCE], host_ip=ip, port=p.port, proto=p.proto,
                state=p.state, service=p.service, product=p.product, version_raw=p.version,
                version_norm=norm.version if norm else None, family=norm.family if norm else None,
                tunnel_ssl=flags.tunnel_ssl, tls_required=flags.tls_required, starttls=flags.starttls,
                login_disabled=flags.login_disabled, auth_required=flags.auth_required,
                auth_mechanisms=flags.auth_mechanisms, capabilities=[excerpt(c, 80) for c in flags.capabilities][:40],
                cert=cert, nmap_conf=p.conf, method=p.method,
            ))
            if p.product or p.version:
                _add_software(ctx, ip, None, p.product, p.version, "nmap", ref or "", line, conf,
                              context=p.extrainfo)
    facts.sort(key=lambda f: sort_key(f.host_ip, f.proto, f.port))
    return facts


# ------------------------------------------------------------------ software

def _add_software(ctx: _Ctx, ip: str, fqdn: Optional[str], product_raw: Optional[str], version_raw: Optional[str],
                  tool: str, ref: str, evidence_text: str, confidence: float, *, kind: Optional[str] = None,
                  vuln_count: Optional[int] = None, hints: Optional[list[str]] = None,
                  mode: str = "active", context: Optional[str] = None) -> Optional[S.SoftwareFact]:
    if not product_raw and not version_raw:
        return None
    norm = normalize(product_raw, version_raw, hints=hints, context=context)
    if not norm.product or not norm.family:
        return None
    if re.fullmatch(r"[\d.]+", norm.product):
        return None
    family = norm.family
    version = norm.version
    key_version = "" if family == "exchange" else (version or "")
    key = (ip, fqdn or "", family, key_version)
    conf = min(confidence, norm.confidence)
    ev = S.Evidence(tool=tool, ref=ref, excerpt=excerpt(evidence_text, 200))
    existing = ctx.software.get(key)
    if existing is None:
        eol = lookup_eol(norm, ctx.scan_date)
        fact = S.SoftwareFact(
            id=f"sw:{ip_token(ip)}:{fqdn or '-'}:{family}:{version or 'unknown'}", source=tool, mode=mode,
            observed_at=ctx.run_time(tool, ip, fqdn) or ctx.finished, confidence=conf, evidence=[ev],
            host_ip=ip, fqdn=fqdn, product=norm.product, family=family, kind=kind or norm.kind,
            version_raw=version_raw or (product_raw if version else None), version_norm=version,
            build=norm.build, distro=norm.distro, edition=norm.edition, hints=list(norm.hints), eol=eol,
            note=norm.note, detection_sources=[tool], vulnerabilities_count=vuln_count,
        )
        ctx.software[key] = fact
        return fact
    # Zusammenfuehren
    if tool not in existing.detection_sources:
        existing.detection_sources.append(tool)
    if len(existing.evidence) < MAX_EVIDENCE and ev.excerpt not in {e.excerpt for e in existing.evidence}:
        existing.evidence.append(ev)
    existing.confidence = max(existing.confidence, conf)
    for hnt in norm.hints:
        if hnt not in existing.hints:
            existing.hints.append(hnt)
    if norm.distro and not existing.distro:
        # Eine Quelle nennt die Distribution (nmap extrainfo, Server-Header), eine andere nicht:
        # die Distribution gilt fuer dieselbe Version am selben Ort, EOL wird neu bewertet.
        existing.distro = norm.distro
        existing.eol = lookup_eol(norm, ctx.scan_date)
    if family == "exchange" and norm.build and not existing.build:
        existing.build = norm.build
        existing.edition = norm.edition
        existing.version_norm = norm.version
        existing.version_raw = version_raw or product_raw
        existing.id = f"sw:{ip_token(ip)}:{fqdn or '-'}:{family}:{norm.version or 'unknown'}"
        existing.eol = lookup_eol(norm, ctx.scan_date)
        existing.note = norm.note
    if vuln_count is not None:
        existing.vulnerabilities_count = max(existing.vulnerabilities_count or 0, vuln_count)
    if kind and existing.kind == "component":
        existing.kind = kind
    return existing


def _software_from_profiles(ctx: _Ctx, ips: list[str]) -> None:
    b = ctx.b
    for ip in ips:
        h = b.hosts.get(ip)
        if h is None:
            continue
        tp = h.tech_profile
        ref = h.refs.get("tech_profile.json", "")
        if isinstance(tp, dict):
            details = tp.get("cms_details") if isinstance(tp.get("cms_details"), dict) else {}
            raw = details.get("details", {}).get("raw") if isinstance(details.get("details"), dict) else None
            if isinstance(raw, dict) and raw.get("name"):
                _add_software(ctx, ip, None, raw.get("name"), raw.get("version"), "cms_fingerprint", ref,
                              f"cms_details.raw: {raw.get('name')} {raw.get('version') or ''}",
                              float(details.get("confidence") or S.CONFIDENCE_DERIVED))
            elif details.get("cms"):
                _add_software(ctx, ip, None, details.get("cms"), details.get("version"), "cms_fingerprint", ref,
                              f"cms_details: {details.get('cms')} {details.get('version') or ''}",
                              float(details.get("confidence") or S.CONFIDENCE_DERIVED))
            for t in tp.get("technologies") or []:
                if isinstance(t, dict) and t.get("name"):
                    _add_software(ctx, ip, None, t.get("name"), t.get("version"), "webtech", ref,
                                  f"technologies: {t.get('name')} {t.get('version') or ''}", S.CONFIDENCE_DERIVED)
            server = tp.get("server")
            if isinstance(server, str) and server:
                _add_software(ctx, ip, None, server, None, "webtech", ref, f"server: {server}", S.CONFIDENCE_DERIVED)
            for fq, rd in (tp.get("redirect_data") or {}).items():
                if not isinstance(rd, dict):
                    continue
                for url in [rd.get("final_url")] + list(rd.get("redirect_chain") or []):
                    m = _OWA_BUILD_RE.search(str(url or ""))
                    if m:
                        _add_software(ctx, ip, None, "Outlook Web App", m.group(1), "redirect_probe", ref,
                                      f"redirect_chain: {url}", S.CONFIDENCE_DERIVED)
                        break
        if isinstance(h.webtech, dict) and tp is None:
            wt_ref = ctx.runs[("webtech", ip)][0].ref if ctx.runs.get(("webtech", ip)) else "scan_results:webtech"
            for t in h.webtech.get("tech") or []:
                if isinstance(t, dict) and t.get("name"):
                    _add_software(ctx, ip, None, t.get("name"), t.get("version"), "webtech", wt_ref,
                                  f"tech: {t.get('name')} {t.get('version') or ''}", S.CONFIDENCE_DERIVED)
        for url in h.zap_spider_urls or []:
            m = _OWA_BUILD_RE.search(url)
            if m:
                _add_software(ctx, ip, None, "Outlook Web App", m.group(1), "zap_spider",
                              h.refs.get("zap_spider_urls.json", ""), f"spider url: {url}", S.CONFIDENCE_DERIVED)
                break
        _software_from_wpscan(ctx, ip, h)


def _software_from_wpscan(ctx: _Ctx, ip: str, h) -> None:
    w = h.wpscan
    if not isinstance(w, dict):
        return
    ref = h.refs.get("wpscan.json") or (ctx.runs[("wpscan", ip)][0].ref if ctx.runs.get(("wpscan", ip)) else "")
    target = str(w.get("target_url") or w.get("effective_url") or "")
    fqdn = urlsplit(target).hostname if target else None
    ver = w.get("version") if isinstance(w.get("version"), dict) else None
    if ver and ver.get("number"):
        _add_software(ctx, ip, fqdn, "WordPress", str(ver["number"]), "wpscan", ref,
                      f"version: {ver['number']} status={ver.get('status')}", S.CONFIDENCE_TOOL,
                      kind="cms_core", vuln_count=len(ver.get("vulnerabilities") or []))
    for slug, pl in (w.get("plugins") or {}).items():
        if not isinstance(pl, dict):
            continue
        pv = (pl.get("version") or {}).get("number") if isinstance(pl.get("version"), dict) else None
        _add_software(ctx, ip, fqdn, str(slug), str(pv) if pv else None, "wpscan", ref,
                      f"plugin {slug} {pv or ''}", S.CONFIDENCE_TOOL, kind="plugin",
                      vuln_count=len(pl.get("vulnerabilities") or []))
    themes = dict(w.get("themes") or {})
    mt = w.get("main_theme")
    if isinstance(mt, dict) and mt.get("slug"):
        themes.setdefault(str(mt["slug"]), mt)
    for slug, th in themes.items():
        if not isinstance(th, dict):
            continue
        tv = (th.get("version") or {}).get("number") if isinstance(th.get("version"), dict) else None
        _add_software(ctx, ip, fqdn, str(slug), str(tv) if tv else None, "wpscan", ref,
                      f"theme {slug} {tv or ''}", S.CONFIDENCE_TOOL, kind="theme",
                      vuln_count=len(th.get("vulnerabilities") or []))


def _finish_software(ctx: _Ctx) -> list[S.SoftwareFact]:
    # X-FEServer-Hinweise an Exchange-Fakten haengen
    feservers: dict[str, set[str]] = defaultdict(set)
    for (ip, fqdn, family, _v), fact in ctx.software.items():
        pass
    for key, fact in list(ctx.software.items()):
        if fact.family == "exchange":
            h = ctx.b.hosts.get(fact.host_ip)
            if h is not None:
                for vh, res in _headers_by_vhost(ctx, fact.host_ip).items():
                    hdrs = {str(k).lower(): str(v) for k, v in (res.get("headers") or {}).items()} if isinstance(res, dict) else {}
                    fe = hdrs.get("x-feserver")
                    if fe:
                        hint = f"X-FEServer {vh}: {fe}"
                        if hint not in fact.hints:
                            fact.hints.append(hint)
    # versionslose Duplikate in versionierte Fakten derselben Familie am selben Ort mergen
    by_place: dict[tuple, list[tuple]] = defaultdict(list)
    for key in ctx.software:
        by_place[key[:3]].append(key)
    for place, keys in by_place.items():
        versioned = [k for k in keys if k[3]]
        unversioned = [k for k in keys if not k[3]]
        if versioned and unversioned and place[2] != "exchange":
            target = ctx.software[versioned[0]]
            for k in unversioned:
                src = ctx.software.pop(k)
                for t in src.detection_sources:
                    if t not in target.detection_sources:
                        target.detection_sources.append(t)
                for e in src.evidence:
                    if len(target.evidence) < MAX_EVIDENCE and e.excerpt not in {x.excerpt for x in target.evidence}:
                        target.evidence.append(e)
                for hnt in src.hints:
                    if hnt not in target.hints:
                        target.hints.append(hnt)
    facts = list(ctx.software.values())
    for f in facts:
        f.detection_sources = sorted(set(f.detection_sources))
        f.hints = sorted(set(f.hints))
        f.evidence = sorted(f.evidence, key=lambda e: sort_key(e.tool, e.ref, e.excerpt))
    facts.sort(key=lambda f: sort_key(f.host_ip, f.fqdn, f.family, f.version_norm, f.id))
    for f in facts:
        ctx.id_seen.add(f.id)
    return facts


# ------------------------------------------------------------------ tls

def _build_tls(ctx: _Ctx, ips: list[str], inv_by_ip: dict[str, dict]) -> list[S.TlsFact]:
    b = ctx.b
    facts: dict[tuple[str, str, int], S.TlsFact] = {}
    for ip in ips:
        h = b.hosts.get(ip)
        if h is None:
            continue
        ts = ctx.testssl.get(ip)
        # httpx-TLS-Bloecke (nur Tar). Issue #10: seit S2b liegt je VHost eine
        # eigene Datei daneben, httpx.json traegt nur den primaeren VHost.
        httpx_tls_lines: list[tuple[dict[str, Any], str]] = [
            (line, h.refs.get("httpx.json", "")) for line in h.httpx_lines
        ]
        for vh, lines in h.httpx_by_vhost_tar.items():
            ref = h.httpx_ref_by_vhost.get(vh, "")
            httpx_tls_lines.extend((line, ref) for line in lines)
        for line, httpx_ref in httpx_tls_lines:
            tls = line.get("tls")
            if not isinstance(tls, dict) or not tls.get("probe_status", True):
                continue
            fqdn = str(line.get("input") or tls.get("host") or line.get("host") or "")
            fqdn = fqdn.split("/")[0]
            try:
                port = int(tls.get("port") or line.get("port") or 443)
            except (TypeError, ValueError):
                port = 443
            key = (ip, fqdn, port)
            fact = facts.get(key) or _new_tls(ctx, ip, fqdn, port)
            cert = fact.cert or S.TlsCert()
            cert.cn = tls.get("subject_cn") or cert.cn
            san = tls.get("subject_an")
            if isinstance(san, list) and san:
                cert.san = sorted({str(x) for x in san})
            cert.issuer = tls.get("issuer_cn") or cert.issuer
            cert.not_before = iso_utc(tls.get("not_before")) or cert.not_before
            cert.not_after = iso_utc(tls.get("not_after")) or cert.not_after
            if isinstance(tls.get("mismatched"), bool):
                cert.mismatch = tls["mismatched"]
            if isinstance(tls.get("wildcard_certificate"), bool):
                cert.wildcard = tls["wildcard_certificate"]
            if isinstance(tls.get("self_signed"), bool):
                cert.self_signed = tls["self_signed"]
            fact.cert = cert
            ver = str(tls.get("tls_version") or "")
            for token, keyname in (("tls13", "TLS1.3"), ("tls12", "TLS1.2"), ("tls11", "TLS1.1"), ("tls10", "TLS1.0")):
                if ver == token and fact.protocols.get(keyname) is None:
                    fact.protocols[keyname] = True
            fact.evidence.append(S.Evidence(tool="httpx", ref=httpx_ref,
                                            excerpt=excerpt(f"{fqdn}:{port} tls={ver} cn={tls.get('subject_cn')} not_after={tls.get('not_after')} mismatched={tls.get('mismatched')}", 220)))
            fact.observed_at = iso_utc(line.get("timestamp")) or fact.observed_at
            facts[key] = fact
        # testssl
        if ts is not None and ts.has_data and not ts.connect_failed:
            fqdn = ts.fqdn or _primary_vhost(inv_by_ip.get(ip, {}))
            port = ts.port or 443
            key = (ip, fqdn or "", port)
            fact = facts.get(key) or _new_tls(ctx, ip, fqdn or "", port)
            fact.source = "testssl"
            for k, v in ts.protocols.items():
                if v is not None:
                    fact.protocols[k] = v
            fact.ciphers_weak = sorted(set(fact.ciphers_weak) | set(ts.ciphers_weak))
            fact.vulns = sorted([S.TlsVuln(name=n, status=s) for n, s in ts.vulns.items()], key=lambda x: x.name)
            cert = fact.cert or S.TlsCert()
            c = ts.cert
            cert.cn = cert.cn or c.get("cn")
            if not cert.san and c.get("san"):
                cert.san = list(c["san"])
            cert.issuer = cert.issuer or c.get("issuer")
            cert.not_before = cert.not_before or c.get("not_before")
            cert.not_after = cert.not_after or c.get("not_after")
            if cert.mismatch is None and c.get("mismatch") is not None:
                cert.mismatch = c["mismatch"]
            if c.get("chain_ok") is not None:
                cert.chain_ok = c["chain_ok"]
            if c.get("self_signed") is not None:
                cert.self_signed = c["self_signed"]
            if cert.wildcard is None and c.get("wildcard") is not None:
                cert.wildcard = c["wildcard"]
            if c.get("expired") is not None and cert.expired is None:
                cert.expired = c["expired"]
            fact.cert = cert
            if ts.hsts:
                fact.hsts = S.HstsInfo(**{k: ts.hsts.get(k) for k in ("present", "max_age", "include_subdomains", "preload", "raw")})
            fact.fallback_scsv = ts.fallback_scsv
            fact.grade = ts.grade
            fact.entries = [S.TlsEntry(id=e["id"], severity=e["severity"], finding=e["finding"], cve=e.get("cve")) for e in ts.entries]
            fact.json_filtered = ts.json_filtered
            ref = h.refs.get("testssl.json") or (ctx.runs[("testssl", ip)][0].ref if ctx.runs.get(("testssl", ip)) else "")
            if ts.text_parsed and ctx.runs.get(("testssl", ip)):
                fact.evidence.append(S.Evidence(tool="testssl", ref=ctx.runs[("testssl", ip)][0].ref,
                                                excerpt=excerpt("protocols " + " ".join(f"{k}={v}" for k, v in ts.protocols.items()), 200)))
            if ts.json_parsed:
                fact.evidence.append(S.Evidence(tool="testssl", ref=ref, excerpt=excerpt(
                    "; ".join(f"{e['id']}={e['finding']}" for e in ts.entries[:6]), 240)))
            fact.observed_at = ts.started_at or ctx.run_time("testssl", ip) or fact.observed_at
            facts[key] = fact
    out = []
    for fact in facts.values():
        if fact.cert:
            if fact.cert.not_after and ctx.finished:
                fact.cert.days_left = days_between(fact.cert.not_after, ctx.finished)
                if fact.cert.expired is None:
                    fact.cert.expired = fact.cert.days_left < 0
            if fact.cert.wildcard is None and fact.cert.cn:
                fact.cert.wildcard = fact.cert.cn.startswith("*.")
            if not any(v is not None for v in fact.cert.model_dump().values()):
                fact.cert = None
        fact.evidence = fact.evidence[:MAX_EVIDENCE]
        out.append(fact)
    out.sort(key=lambda f: sort_key(f.host_ip, f.fqdn, f.port))
    for f in out:
        ctx.id_seen.add(f.id)
    return out


def _new_tls(ctx: _Ctx, ip: str, fqdn: str, port: int) -> S.TlsFact:
    return S.TlsFact(id=f"tls:{fqdn or ip_token(ip)}:{port}@{ip_token(ip)}" if fqdn else f"tls:{ip_token(ip)}:{port}",
                     source="httpx", mode="active", observed_at=ctx.finished, confidence=S.CONFIDENCE_TOOL,
                     fqdn=fqdn or None, host_ip=ip, port=port)


def _primary_vhost(inv: dict) -> Optional[str]:
    for v in inv.get("vhosts") or []:
        if isinstance(v, dict) and v.get("is_primary") and v.get("fqdn"):
            return str(v["fqdn"])
    for v in inv.get("vhosts") or []:
        if isinstance(v, dict) and v.get("fqdn"):
            return str(v["fqdn"])
    fq = inv.get("fqdns") or []
    return str(fq[0]) if fq else None


# ------------------------------------------------------------------ http

def _build_http(ctx: _Ctx, ips: list[str], inv_by_ip: dict[str, dict]) -> list[S.HttpFact]:
    b = ctx.b
    facts: list[S.HttpFact] = []
    for ip in ips:
        h = b.hosts.get(ip)
        inv = inv_by_ip.get(ip, {})
        if h is None:
            continue
        headers_map = _headers_by_vhost(ctx, ip)
        httpx_map: dict[str, dict[str, Any]] = {}
        # Issue #10: Rangfolge wie bei den Headern — Tar-Datei je VHost vor
        # der Legacy-Datei und vor der Zeile.
        for vh, lines in h.httpx_by_vhost_tar.items():
            if lines:
                httpx_map.setdefault(vh, lines[0])
        for line in h.httpx_lines:
            vh = str(line.get("input") or line.get("host") or "").split("/")[0]
            if vh:
                httpx_map.setdefault(vh, line)
        for vh, line in h.httpx_rows.items():
            httpx_map.setdefault(vh, line)
        vhost_names = set(headers_map) | set(httpx_map)
        for v in inv.get("vhosts") or []:
            if isinstance(v, dict) and v.get("fqdn"):
                vhost_names.add(str(v["fqdn"]))
        alerts_by_host = _zap_alerts_by_host(ctx, h)
        paths_by_host = _paths_by_host(h)
        spider_by_host = _spider_by_host(h)
        ts = ctx.testssl.get(ip)
        tp = h.tech_profile if isinstance(h.tech_profile, dict) else {}
        redirect_data = tp.get("redirect_data") if isinstance(tp.get("redirect_data"), dict) else {}
        wp = h.wpscan if isinstance(h.wpscan, dict) else None
        wp_host = urlsplit(str((wp or {}).get("target_url") or "")).hostname if wp else None

        for vh in sorted(vhost_names, key=sort_key):
            res = headers_map.get(vh)
            line = httpx_map.get(vh)
            rd = redirect_data.get(vh) if isinstance(redirect_data.get(vh), dict) else None
            source = "header_check" if res is not None else ("httpx" if line else "redirect_probe")
            confidence = S.CONFIDENCE_TOOL if res is not None or line else S.CONFIDENCE_DERIVED
            headers: dict[str, str] = {}
            if isinstance(res, dict):
                headers = {str(k).lower(): str(v) for k, v in (res.get("headers") or {}).items()}
            elif rd and isinstance(rd.get("response_headers"), dict):
                headers = {str(k).lower(): str(v) for k, v in rd["response_headers"].items()}
            if not headers and not line and not res and not rd:
                continue
            sec: dict[str, S.SecHeader] = {}
            if isinstance(res, dict):
                for k, v in (res.get("security_headers") or {}).items():
                    if isinstance(v, dict):
                        sec[str(k).lower()] = S.SecHeader(present=bool(v.get("present")), value=v.get("value"))
            csp_raw = headers.get("content-security-policy")
            csp = S.Csp(present=True, value=csp_raw[:500], unsafe_inline="'unsafe-inline'" in csp_raw,
                        unsafe_eval="'unsafe-eval'" in csp_raw, wildcard=bool(re.search(r"(^|\s)\*(\s|;|$)", csp_raw))) \
                if csp_raw else (S.Csp(present=False) if res is not None and res.get("reachable") else None)
            hsts = _hsts_from_header(headers.get("strict-transport-security"), res)
            cookies = _cookies(headers.get("set-cookie"))
            technologies = []
            if line:
                for t in line.get("tech") or []:
                    name, ver = _split_httpx_tech(str(t))
                    technologies.append(S.Tech(name=name, version=ver))
                    if name.strip().lower() in NON_SOFTWARE_TECH:
                        continue
                    _add_software(ctx, ip, vh, name, ver, "httpx",
                                  h.httpx_ref_by_vhost.get(vh) or h.refs.get("httpx.json") or ctx.run_ref("httpx", ip),
                                  f"tech: {t}", S.CONFIDENCE_DERIVED)
            server = headers.get("server")
            powered = headers.get("x-powered-by")
            # Issue #10: zeigt auf die VHost-Datei, wenn sie die Quelle war.
            ref_hdr = (h.headers_ref_by_vhost.get(vh)
                       or (ctx.run_ref("header_check", ip, vh)
                           if (h.headers_by_vhost.get(vh) is not None
                               and ctx.runs.get(("header_check", ip)))
                           else h.refs.get("headers.json", "")))
            if server:
                _add_software(ctx, ip, vh, server, None, "header_check" if res is not None else "redirect_probe",
                              ref_hdr or h.refs.get("tech_profile.json", ""), f"server: {server}", confidence)
            if powered:
                for part in re.split(r"[,;]\s*|\n", powered):
                    if part.strip():
                        _add_software(ctx, ip, vh, part.strip(), None, "header_check" if res is not None else "redirect_probe",
                                      ref_hdr or h.refs.get("tech_profile.json", ""), f"x-powered-by: {powered}", confidence)
            if headers.get("x-aspnet-version"):
                _add_software(ctx, ip, vh, "ASP.NET", headers["x-aspnet-version"], "header_check" if res is not None else "redirect_probe",
                              ref_hdr or "", f"x-aspnet-version: {headers['x-aspnet-version']}", confidence)
            if line and line.get("webserver") and not server:
                _add_software(ctx, ip, vh, str(line["webserver"]), None, "httpx",
                              h.httpx_ref_by_vhost.get(vh) or h.refs.get("httpx.json") or ctx.run_ref("httpx", ip),
                              f"webserver: {line['webserver']}", S.CONFIDENCE_DERIVED)
            alerts = alerts_by_host.pop(vh, [])
            paths = paths_by_host.get(vh, [])[:MAX_PATHS]
            final_url = (line or {}).get("final_url") or (line or {}).get("url") or (rd or {}).get("final_url")
            login = None
            if any(a.plugin_id == "10111" for a in alerts):
                login = True
            elif final_url and _LOGIN_URL_RE.search(str(final_url)):
                login = True
            elif any(_LOGIN_URL_RE.search(a.url or "") for a in alerts):
                login = True
            wordpress = None
            if wp and wp_host == vh:
                users = sorted((wp.get("users") or {}).keys()) if isinstance(wp.get("users"), dict) else []
                ver = wp.get("version") if isinstance(wp.get("version"), dict) else {}
                wordpress = S.WordPressInfo(users=[str(u) for u in users], version_status=ver.get("status") if ver else None)
            status_code = _int_or_none((line or {}).get("status_code")) if line else None
            if status_code is None and rd:
                status_code = _int_or_none(rd.get("status_code"))
            if status_code is None:
                for v in inv.get("vhosts") or []:
                    if isinstance(v, dict) and v.get("fqdn") == vh:
                        status_code = _int_or_none(v.get("status"))
            if status_code == 0:
                status_code = None
            ev: list[S.Evidence] = []
            if res is not None:
                ev.append(S.Evidence(tool="header_check", ref=ref_hdr, excerpt=excerpt(
                    f"{vh}: reachable={res.get('reachable')} score={res.get('score')} server={server} x-feserver={headers.get('x-feserver')}", 220)))
            if line:
                ev.append(S.Evidence(tool="httpx", ref=(h.httpx_ref_by_vhost.get(vh)
                                                       or h.refs.get("httpx.json")
                                                       or ctx.run_ref("httpx", ip)), excerpt=excerpt(
                    f"{vh}: status={line.get('status_code')} title={line.get('title')} webserver={line.get('webserver')} tech={line.get('tech')}", 240)))
            if rd and res is None:
                ev.append(S.Evidence(tool="redirect_probe", ref=h.refs.get("tech_profile.json", ""), excerpt=excerpt(
                    f"{vh}: final_url={rd.get('final_url')} status={rd.get('status_code')}", 200)))
            observed = ctx.run_time("header_check", ip, vh) or iso_utc((line or {}).get("timestamp")) \
                or ctx.run_time("httpx", ip) or ctx.finished
            reachable = res.get("reachable") if isinstance(res, dict) and isinstance(res.get("reachable"), bool) else (
                True if line else None)
            facts.append(S.HttpFact(
                id=ctx.unique_id(f"http:{vh}", ip_token(ip)), source=source, mode="active", observed_at=observed,
                confidence=confidence, evidence=ev, fqdn=vh, host_ip=ip,
                url=(res or {}).get("url") or (line or {}).get("url") or (rd or {}).get("final_url"),
                reachable=reachable, status_code=status_code, headers=headers, security_headers=sec,
                score=(res or {}).get("score"), csp=csp, hsts=hsts, cookies=cookies, server_header=server,
                powered_by=powered, x_feserver=headers.get("x-feserver"),
                duplicate_headers=list(ts.duplicate_headers) if ts and (ts.fqdn == vh or not ts.fqdn) else [],
                technologies=technologies, forms=[], login_form=login, alerts=alerts, paths=paths,
                spider_url_count=spider_by_host.get(vh), wordpress=wordpress,
            ))
        # Alerts, die zu keinem VHost gehoeren: Host-Ebene
        for other_host, alerts in sorted(alerts_by_host.items(), key=lambda kv: sort_key(kv[0])):
            if not alerts:
                continue
            facts.append(S.HttpFact(
                id=ctx.unique_id(f"http:{other_host or ip_token(ip)}", ip_token(ip)), source="zap", mode="active",
                observed_at=ctx.run_time("zap", ip) or ctx.finished, confidence=S.CONFIDENCE_TOOL,
                evidence=[S.Evidence(tool="zap", ref=h.refs.get("zap_alerts.json") or ctx.run_ref("zap", ip),
                                     excerpt=f"{len(alerts)} alerts fuer {other_host}")],
                fqdn=other_host or None, host_ip=ip, alerts=alerts,
                paths=paths_by_host.get(other_host, [])[:MAX_PATHS], spider_url_count=spider_by_host.get(other_host),
            ))
    facts.sort(key=lambda f: sort_key(f.fqdn, f.host_ip))
    return facts


def _split_httpx_tech(t: str) -> tuple[str, Optional[str]]:
    if ":" in t:
        name, ver = t.rsplit(":", 1)
        if re.match(r"^\d", ver):
            return name.strip(), ver.strip()
    return t.strip(), None


def _hsts_from_header(value: Optional[str], res: Any) -> Optional[S.HstsInfo]:
    if value:
        m = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
        return S.HstsInfo(present=True, max_age=int(m.group(1)) if m else None,
                          include_subdomains="includesubdomains" in value.lower(),
                          preload="preload" in value.lower(), raw=value[:200])
    if isinstance(res, dict) and res.get("reachable"):
        return S.HstsInfo(present=False)
    return None


def _cookies(value: Optional[str]) -> list[S.Cookie]:
    out: list[S.Cookie] = []
    if not value:
        return out
    for part in re.split(r",(?=[^;,]+=)", value):
        seg = part.strip()
        if "=" not in seg:
            continue
        name = seg.split("=", 1)[0].strip()
        low = seg.lower()
        m = re.search(r"samesite=(\w+)", low)
        out.append(S.Cookie(name=name, secure="secure" in low.split(";")[1:] or "; secure" in low,
                            httponly="httponly" in low, samesite=m.group(1) if m else None))
    return out


def _zap_alerts_by_host(ctx: _Ctx, h) -> dict[str, list[S.WebAlert]]:
    grouped: dict[tuple[str, str], S.WebAlert] = {}
    by_host: dict[str, list[S.WebAlert]] = defaultdict(list)
    raw_alerts: list[dict[str, Any]] = []
    truncated = False
    if h.zap_alerts is not None:
        raw_alerts = h.zap_alerts
    elif isinstance(h.zap_summary, dict):
        raw_alerts = [a for a in (h.zap_summary.get("top_alerts") or []) if isinstance(a, dict)]
        total = h.zap_summary.get("total_alerts")
        if isinstance(total, int) and total > len(raw_alerts):
            truncated = True
    if truncated:
        ctx.warn(f"ZAP {h.ip}: nur top_alerts aus dem Snapshot, Alertliste gekuerzt")
    urls: dict[tuple[str, str], set[str]] = defaultdict(set)
    for a in raw_alerts:
        if not isinstance(a, dict):
            continue
        name = str(a.get("name") or a.get("alert") or "").strip()
        if not name:
            continue
        plugin = a.get("pluginId")
        plugin = str(plugin) if plugin not in (None, "") else None
        url = str(a.get("url") or "")
        host = urlsplit(url).hostname or ""
        if plugin is None:
            ctx.add_unprocessed("zap_alert_without_plugin_id", name, host_ip=h.ip, fqdn=host or None,
                                source="zap", ref=ctx.run_ref("zap", h.ip), excerpt_text=f"{name} {url}")
        key = (host, plugin or f"name:{name}")
        if url:
            urls[key].add(url)
        if key in grouped:
            continue
        cwe = a.get("cweid")
        grouped[key] = S.WebAlert(
            plugin_id=plugin, name=name, risk=str(a.get("risk") or a.get("riskcode") or "unknown"),
            confidence=str(a.get("confidence")) if a.get("confidence") not in (None, "") else None,
            url=None, cwe=f"CWE-{cwe}" if cwe not in (None, "", "-1", "0") else None,
            evidence=excerpt(a.get("evidence"), 200) or None, count=0,
        )
    for key, alert in grouped.items():
        host = key[0]
        sample = sorted(urls.get(key, set()), key=sort_key)
        alert.count = max(1, len(sample))
        alert.url = sample[0] if sample else None
        alert.urls_sample = sample[:5]
        by_host[host].append(alert)
    for host in by_host:
        by_host[host].sort(key=lambda x: sort_key(x.plugin_id, x.name, x.url))
    return dict(by_host)


def _paths_by_host(h) -> dict[str, list[S.WebPath]]:
    out: dict[str, list[S.WebPath]] = defaultdict(list)
    for rec in h.feroxbuster or []:
        if rec.get("type") != "response":
            continue
        url = str(rec.get("url") or "")
        host = urlsplit(url).hostname or ""
        out[host].append(S.WebPath(url=url, status=_int_or_none(rec.get("status")), length=_int_or_none(rec.get("content_length"))))
    if isinstance(h.ffuf, dict):
        seen: set[str] = set()
        for r in h.ffuf.get("results") or []:
            if not isinstance(r, dict):
                continue
            url = str(r.get("url") or "")
            base = url.split("?", 1)[0]
            if base in seen:
                continue
            seen.add(base)
            host = urlsplit(url).hostname or str(r.get("host") or "")
            out[host].append(S.WebPath(url=base, status=_int_or_none(r.get("status")), length=_int_or_none(r.get("length"))))
    for host in out:
        out[host] = sorted({p.url: p for p in out[host]}.values(), key=lambda p: sort_key(p.url))
    return dict(out)


def _spider_by_host(h) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for url in h.zap_spider_urls or []:
        host = urlsplit(str(url)).hostname or ""
        out[host] += 1
    return dict(out)


# ------------------------------------------------------------------ dns

def _build_dns(ctx: _Ctx, domains: list[Optional[str]]) -> list[S.DnsFact]:
    """Ein DnsFact je Domain der Order (Issue #12).

    Bis S2b gab es nur das Primaerziel; fuer jede weitere Domain meldete der
    Katalog `second_target_unlabeled`. Die Quellen des Primaerziels bleiben die
    bisherigen Skalare, damit sein Fakt unveraendert bleibt; weitere Domains
    lesen aus den `*_by_domain`-Maps, die nur neuere Scans fuellen.
    """
    b = ctx.b
    out: list[S.DnsFact] = []
    for index, domain in enumerate(d for d in domains if d):
        if index == 0:
            fact = _dns_fact(
                ctx, domain,
                dr=b.dns_records if isinstance(b.dns_records, dict) else {},
                ds=b.dns_security if isinstance(b.dns_security, dict) else {},
                dnsf=(b.host_inventory.get("dns_findings")
                      if isinstance(b.host_inventory.get("dns_findings"), dict) else {}),
                zone_txt=b.zone_transfer_txt,
                ref_dr=b.refs.get("dns_records", ""),
                ref_ds=b.refs.get("dns_security", ""),
            )
        else:
            fact = _dns_fact(
                ctx, domain,
                dr=b.dns_records_by_domain.get(domain) or {},
                ds=b.dns_security_by_domain.get(domain) or {},
                dnsf={},
                zone_txt=b.zone_transfer_by_domain.get(domain),
                ref_dr=b.refs.get(f"dns_records:{domain}", ""),
                ref_ds=b.refs.get(f"dns_security:{domain}", ""),
            )
        if fact is not None:
            out.append(fact)
    return out


def _dns_fact(ctx: _Ctx, domain: str, *, dr: dict, ds: dict, dnsf: dict,
              zone_txt: Optional[str], ref_dr: str, ref_ds: str) -> Optional[S.DnsFact]:
    b = ctx.b
    if not dr and not dnsf and not ds:
        return None
    spf_raw = dr.get("spf") if dr.get("spf") is not None else dnsf.get("spf")
    spf = None
    if isinstance(spf_raw, str) and spf_raw.strip():
        m = re.search(r"([~+?-]?)all\b", spf_raw)
        spf = S.Spf(raw=spf_raw.strip(), all_qualifier=(m.group(1) or "+") + "all" if m else None)
    dmarc = _dmarc(dr.get("dmarc_policy") if isinstance(dr.get("dmarc_policy"), dict) else None,
                   dr.get("dmarc") if dr.get("dmarc") is not None else dnsf.get("dmarc"),
                   ds.get("dmarc") if isinstance(ds.get("dmarc"), dict) else None)
    dkim_present = dr.get("dkim") if isinstance(dr.get("dkim"), bool) else _bool_or_none(dnsf.get("dkim"))
    dkim = S.Dkim(present=dkim_present, selectors=sorted(str(s) for s in (dr.get("dkim_selectors") or []))) \
        if dkim_present is not None or dr.get("dkim_selectors") else None
    dnssec = caa = mta = tlsrpt = dane = bimi = None
    if isinstance(ds.get("dnssec"), dict):
        d = ds["dnssec"]
        dnssec = S.Dnssec(signed=_bool_or_none(d.get("dnssec_signed")), valid=_bool_or_none(d.get("dnssec_valid")),
                          issues=[str(x) for x in (d.get("issues") or [])])
    if isinstance(ds.get("caa"), dict):
        c = ds["caa"]
        caa = S.Caa(present=_bool_or_none(c.get("has_caa")), issuers=[str(x) for x in (c.get("issuers") or [])],
                    records=[str(x) for x in (c.get("records") or [])])
    if isinstance(ds.get("mta_sts"), dict):
        m_ = ds["mta_sts"]
        mta = S.MtaSts(dns_record=_bool_or_none(m_.get("has_dns_record")), policy=_bool_or_none(m_.get("has_policy")),
                       mode=m_.get("mode"))
    if isinstance(ds.get("tls_rpt"), dict):
        t_ = ds["tls_rpt"]
        tlsrpt = S.TlsRpt(present=_bool_or_none(t_.get("tlsrpt_present")), rua=[str(x) for x in (t_.get("rua_targets") or [])])
    if isinstance(ds.get("dane_tlsa"), dict):
        d_ = ds["dane_tlsa"]
        dane = S.Dane(smtp=_bool_or_none(d_.get("has_smtp_dane")), https=_bool_or_none(d_.get("has_https_dane")))
    if isinstance(ds.get("bimi"), dict):
        bimi = S.Bimi(present=_bool_or_none(ds["bimi"].get("bimi_present")))
    zt = None
    zt_allowed = _bool_or_none(dnsf.get("zone_transfer"))
    ns_tested = re.findall(r"=== NS: (\S+) ===", zone_txt or "")
    if zt_allowed is not None or ns_tested:
        zt = S.ZoneTransfer(allowed=zt_allowed, ns_tested=sorted(set(ns_tested)))
    dangling = []
    for dc in dnsf.get("dangling_cnames") or []:
        if isinstance(dc, dict) and dc.get("fqdn"):
            dangling.append(S.DanglingCname(fqdn=str(dc["fqdn"]), cname_target=dc.get("cname_target"),
                                            takeover_risk=str(dc.get("takeover_risk")) if dc.get("takeover_risk") is not None else None,
                                            reason=dc.get("reason")))
    ev = []
    if dr:
        ev.append(S.Evidence(tool="dns_records", ref=ref_dr, excerpt=excerpt(f"spf={spf_raw} dmarc={dr.get('dmarc')} dkim={dr.get('dkim')} mx={dr.get('mx')}", 240)))
    elif dnsf:
        ev.append(S.Evidence(tool="dns_records", ref=b.refs.get("host_inventory", ""), excerpt=excerpt(f"dns_findings: spf={spf_raw} dmarc={dnsf.get('dmarc')} dkim={dnsf.get('dkim')}", 240)))
    if ds:
        ev.append(S.Evidence(tool="dns_security", ref=ref_ds, excerpt=excerpt(
            f"dnssec_signed={(ds.get('dnssec') or {}).get('dnssec_signed')} caa={(ds.get('caa') or {}).get('has_caa')} mta_sts={(ds.get('mta_sts') or {}).get('has_policy')}", 200)))
    fact = S.DnsFact(
        id=f"dns:{domain}", source="dns_records", mode="active",
        observed_at=ctx.run_time("dns_records") or ctx.run_time("dns_security") or ctx.started or ctx.finished,
        confidence=S.CONFIDENCE_TOOL, evidence=ev, domain=domain,
        ns=sorted(str(x) for x in (dr.get("ns") or dnsf.get("ns") or [])),
        mx=sorted(str(x) for x in (dr.get("mx") or dnsf.get("mx") or [])),
        spf=spf, dmarc=dmarc, dkim=dkim, dnssec=dnssec, caa=caa, mta_sts=mta, tls_rpt=tlsrpt, dane=dane,
        bimi=bimi, zone_transfer=zt, dangling_cnames=dangling,
    )
    return fact


def _dmarc(policy: Optional[dict], raw: Any, sec: Optional[dict]) -> Optional[S.Dmarc]:
    src = policy or sec
    if isinstance(src, dict) and src:
        present = _bool_or_none(src.get("dmarc_present"))
        if present is None:
            present = bool(src.get("raw") or raw)
        return S.Dmarc(present=present, raw=src.get("raw") or (raw if isinstance(raw, str) else None),
                       p=src.get("p"), sp=src.get("sp"), pct=_int_or_none(src.get("pct")),
                       rua=[str(x) for x in (src.get("rua") or [])], ruf=[str(x) for x in (src.get("ruf") or [])],
                       adkim=src.get("adkim"), aspf=src.get("aspf"))
    if isinstance(raw, str) and raw.strip():
        tags = dict(re.findall(r"(\w+)\s*=\s*([^;]+)", raw))
        return S.Dmarc(present=True, raw=raw.strip(), p=tags.get("p"), sp=tags.get("sp"),
                       pct=_int_or_none(tags.get("pct")), rua=[x.strip() for x in tags.get("rua", "").split(",") if x.strip()],
                       ruf=[x.strip() for x in tags.get("ruf", "").split(",") if x.strip()], adkim=tags.get("adkim"), aspf=tags.get("aspf"))
    if raw is None and (policy is None and sec is None):
        return None
    return S.Dmarc(present=False)


# ------------------------------------------------------------------ passive

def _build_passive(ctx: _Ctx, ips: list[str], inv_by_ip: dict[str, dict], domain: Optional[str]) -> list[S.PassiveFact]:
    b = ctx.b
    facts: list[S.PassiveFact] = []
    shodan = b.passive.get("shodan_hosts")
    if isinstance(shodan, dict):
        ref = b.refs.get("shodan_hosts", "")
        for ip in sorted(shodan, key=sort_key):
            entry = shodan[ip]
            if not isinstance(entry, dict):
                continue
            if ip not in inv_by_ip and ip not in b.hosts:
                ctx.add_unprocessed("shodan_host_outside_inventory", ip, host_ip=ip, source="shodan", ref=ref,
                                    excerpt_text=f"ports={entry.get('ports')}")
                continue
            nh = ctx.nmap_hosts.get(ip)
            open_ports = {p.port for p in (nh.ports if nh else []) if p.state == "open"} if nh else None
            seen = iso_utc(entry.get("last_update"))
            services = {int(s["port"]): s for s in (entry.get("services") or []) if isinstance(s, dict) and str(s.get("port", "")).isdigit()}
            ports = sorted({int(p) for p in (entry.get("ports") or []) if str(p).isdigit()} | set(services))
            hostnames = sorted(str(x) for x in (entry.get("hostnames") or []))
            for port in ports:
                s = services.get(port, {})
                facts.append(S.PassiveFact(
                    id=f"passive:shodan:{ip_token(ip)}:{port}", source="shodan", mode="passive", observed_at=seen or ctx.finished,
                    confidence=S.CONFIDENCE_PASSIVE if not (open_ports and port in open_ports) else S.CONFIDENCE_DERIVED,
                    evidence=[S.Evidence(tool="shodan", ref=ref, excerpt=excerpt(f"{ip}:{port} {s.get('product') or ''} {s.get('version') or ''} | {s.get('banner') or ''}", 200))],
                    host_ip=ip, port=port, transport=s.get("transport"), product=s.get("product") or None,
                    version=str(s.get("version")) if s.get("version") else None,
                    banner_excerpt=excerpt(s.get("banner"), 160) or None, seen_at=seen,
                    verified=(port in open_ports) if open_ports is not None else None, hostnames=hostnames,
                ))
    otx = b.passive.get("otx")
    if isinstance(otx, dict) and isinstance(otx.get("domain"), dict) and domain:
        d = otx["domain"]
        facts.append(S.PassiveFact(id=f"passive:otx:{domain}", source="otx", mode="passive", observed_at=ctx.run_time("otx") or ctx.finished,
                                   confidence=S.CONFIDENCE_PASSIVE, evidence=[S.Evidence(tool="otx", ref=b.refs.get("otx", ""), excerpt=f"pulse_count={d.get('pulse_count')}")],
                                   domain=domain, details={"pulse_count": _int_or_none(d.get("pulse_count"))}))
    st = b.passive.get("securitytrails")
    if isinstance(st, dict) and isinstance(st.get("domain"), dict) and domain:
        d = st["domain"]
        details = {k: d.get(k) for k in ("a_records", "mx_records", "ns_records") if isinstance(d.get(k), list)}
        txt = d.get("txt_records")
        if isinstance(txt, list):
            details["txt_records"] = [str(x)[:200] for x in txt[:10]]
        facts.append(S.PassiveFact(id=f"passive:securitytrails:{domain}", source="securitytrails", mode="passive",
                                   observed_at=ctx.run_time("securitytrails") or ctx.finished, confidence=S.CONFIDENCE_PASSIVE,
                                   evidence=[S.Evidence(tool="securitytrails", ref=b.refs.get("securitytrails", ""), excerpt=excerpt(str(details), 200))],
                                   domain=domain, details=details))
    uh = b.passive.get("urlhaus")
    if isinstance(uh, dict) and domain:
        comp = uh.get("compromised")
        details = {"compromised": comp if isinstance(comp, bool) else (False if uh.get("no_data") else None)}
        facts.append(S.PassiveFact(id=f"passive:urlhaus:{domain}", source="urlhaus", mode="passive",
                                   observed_at=ctx.run_time("urlhaus") or ctx.finished, confidence=S.CONFIDENCE_PASSIVE,
                                   evidence=[S.Evidence(tool="urlhaus", ref=b.refs.get("urlhaus", ""), excerpt=excerpt(uh.get("raw") or str(details), 160))],
                                   domain=domain, details=details))
    gn = b.passive.get("greynoise")
    if isinstance(gn, dict):
        for ip in sorted(gn, key=sort_key):
            e = gn[ip]
            if not isinstance(e, dict) or ip not in inv_by_ip:
                continue
            facts.append(S.PassiveFact(id=f"passive:greynoise:{ip_token(ip)}", source="greynoise", mode="passive",
                                       observed_at=ctx.run_time("greynoise") or ctx.finished, confidence=S.CONFIDENCE_PASSIVE,
                                       evidence=[S.Evidence(tool="greynoise", ref=b.refs.get("greynoise", ""), excerpt=excerpt(str(e), 160))],
                                       host_ip=ip, details={k: e.get(k) for k in ("classification", "noise", "riot") if k in e}))
    facts.sort(key=lambda f: sort_key(f.source, f.domain, f.host_ip, f.port))
    return facts


# ------------------------------------------------------------------ threats

def _testssl_verwundbar(entry: dict[str, Any]) -> bool:
    """Spricht diese testssl-Zeile ein Urteil "verwundbar" aus?

    Massgeblich ist die Severity, nicht der Text allein: das JSON nennt bei
    Treffern oft nur die Cipher-Liste. ``OK``, ``INFO``, ``DEBUG``, ``WARN`` und
    ``FATAL`` sind kein Fund. ``WARN`` heisst "nicht geprueft" und steht als
    ``not_tested`` in ``tls[].vulns``, nicht hier.
    """
    if str(entry.get("severity") or "").upper() not in TESTSSL_VULN_SEVERITIES:
        return False
    return "not vulnerable" not in str(entry.get("finding") or "").lower()


def _software_ref_for(software: list[S.SoftwareFact], services: list[S.ServiceFact],
                      host_ip: Optional[str], port: Optional[int]) -> Optional[str]:
    """Software hinter einem Dienst, oder ``None`` wenn es nicht eindeutig ist.

    ``SoftwareFact`` kennt keinen Port, die Bruecke ist der Dienst: er nennt
    Produkt und Familie an genau diesem Port, und darueber wird die Software
    desselben Hosts gesucht. Bleibt es mehrdeutig, bleibt die Zuordnung leer;
    ``cve_known_version`` haengt an diesem Feld, und lieber keine Zuordnung als
    die erstbeste. (Bis S5b stand hier ``any(p == port for p in [port])``, immer
    wahr, womit schlicht die erste Software des Hosts verlinkt wurde.)
    """
    if not host_ip or port is None:
        return None
    svc = next((s for s in services if s.host_ip == host_ip and s.port == port), None)
    if svc is None:
        return None
    schluessel = {v.lower() for v in (svc.family, svc.product) if v}
    if not schluessel:
        return None
    treffer = [s for s in software if s.host_ip == host_ip
               and ({s.family.lower(), s.product.lower()} & schluessel)]
    return treffer[0].id if len(treffer) == 1 else None


def _build_threats(ctx: _Ctx, software: list[S.SoftwareFact],
                   services: list[S.ServiceFact]) -> list[S.ThreatFact]:
    b = ctx.b
    facts: dict[str, S.ThreatFact] = {}
    cve_hosts: dict[str, list[tuple[str, Optional[int]]]] = defaultdict(list)
    for c in b.correlated_findings:
        if isinstance(c, dict) and c.get("cve_id"):
            cve_hosts[str(c["cve_id"])].append((str(c.get("host_ip") or ""), _int_or_none(c.get("port"))))
    for cve, data in sorted((b.enrichment or {}).items(), key=lambda kv: sort_key(kv[0])):
        if not isinstance(data, dict):
            continue
        nvd = data.get("nvd") if isinstance(data.get("nvd"), dict) else {}
        epss = data.get("epss") if isinstance(data.get("epss"), dict) else None
        kev = data.get("cisa_kev") if isinstance(data.get("cisa_kev"), dict) else None
        edb = data.get("exploitdb") if isinstance(data.get("exploitdb"), dict) else None
        host_ip, port = (cve_hosts.get(cve) or [(None, None)])[0]
        sw_ref = _software_ref_for(software, services, host_ip or None, port)
        facts[cve] = S.ThreatFact(
            id=f"threat:{cve}", source="enrichment", mode="passive", observed_at=ctx.run_time("phase3_correlation") or ctx.finished,
            confidence=S.CONFIDENCE_TOOL, evidence=[S.Evidence(tool="enrichment", ref=b.refs.get("enrichment", ""), excerpt=excerpt(f"{cve} nvd={nvd.get('cvss_score')} epss={(epss or {}).get('epss')} kev={bool(kev)}", 160))],
            cve_id=cve, cvss_nvd=S.CvssRef(score=_float_or_none(nvd.get("cvss_score")), vector=nvd.get("cvss_vector")) if nvd else None,
            cwes=[str(x) for x in (nvd.get("cwes") or [])], epss=S.Epss(score=_float_or_none(epss.get("epss")), percentile=_float_or_none(epss.get("percentile"))) if epss else None,
            kev=S.Kev(listed=True, date_added=kev.get("date_added"), known_ransomware=kev.get("known_ransomware")) if kev else None,
            exploitdb=S.ExploitDb(count=_int_or_none(edb.get("exploit_count")), metasploit=_bool_or_none(edb.get("metasploit_module"))) if edb else None,
            affected_software_ref=sw_ref, host_ip=host_ip or None, port=port,
        )
    # testssl nennt im Feld ``cve`` die Nummer, GEGEN die geprueft wurde, auch
    # wenn das Ergebnis "not vulnerable" lautet. Nur das Urteil entscheidet, ob
    # daraus ein Fakt wird: Severity aus VULN_SEVERITIES und ein Befundtext ohne
    # "not vulnerable". Ohne diesen Filter trug der juengste Junkerwerk-Lauf 32
    # CVE-Fakten, darunter Heartbleed, saemtlich mit ``severity: OK`` (S5b).
    for ts_ip, ts in ctx.testssl.items():
        if ts is None:
            continue
        for e in ts.entries:
            if e.get("cve") and _testssl_verwundbar(e):
                fid = f"threat:{e['cve']}:{ts.fqdn or ip_token(ts_ip)}:{ts.port}"
                if fid in facts:
                    continue
                vorhanden = facts.get(e["cve"])
                if vorhanden is not None:
                    # Dieselbe CVE, zwei Quellen: die Anreicherung traegt den
                    # Fremdwert, testssl den Hostbezug. Bis S5b entstanden daraus
                    # zwei Fakten, weil die Schluessel nie kollidierten.
                    if vorhanden.host_ip is None:
                        vorhanden.host_ip = ts_ip
                        vorhanden.port = ts.port
                    vorhanden.evidence = list(vorhanden.evidence) + [S.Evidence(
                        tool="testssl", ref=ctx.run_ref("testssl", ts_ip),
                        excerpt=excerpt(f"{e['id']}: {e['finding']}", 160))]
                    continue
                facts[fid] = S.ThreatFact(
                    id=fid, source="testssl", mode="active", observed_at=ts.started_at or ctx.finished,
                    confidence=S.CONFIDENCE_TOOL, evidence=[S.Evidence(tool="testssl", ref=ctx.run_ref("testssl", ts_ip), excerpt=excerpt(f"{e['id']}: {e['finding']}", 160))],
                    cve_id=e["cve"], host_ip=ts_ip, port=ts.port,
                )
    return sorted(facts.values(), key=lambda f: sort_key(f.cve_id, f.host_ip, f.port, f.id))


def _float_or_none(v: Any) -> Optional[float]:
    try:
        return float(v) if v is not None and not isinstance(v, bool) else None
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------ unprocessed / decisions

def _unprocessed_from_bundle(ctx: _Ctx) -> None:
    b = ctx.b
    for kind, what, host in b.unparsed:
        ctx.add_unprocessed(kind, what, host_ip=host, source="facts_builder", ref=what)
    for ip, h in sorted(b.hosts.items(), key=lambda kv: sort_key(kv[0])):
        for name in h.unparsed:
            ctx.add_unprocessed("file_unknown_or_unparsable", name, host_ip=ip, source="facts_builder", ref=name)
    for r in b.tool_runs:
        if r.tool_norm in TOOLS_WITHOUT_PARSER and (r.raw_output or "").strip() and not (r.raw_output or "").startswith(("SKIPPED", "FAILED")):
            ctx.add_unprocessed("tool_without_parser", r.tool, host_ip=r.host_ip, source=r.tool, ref=r.ref, excerpt_text=r.raw_output or "")


def _build_decisions(ctx: _Ctx, ips: list[str], inv_by_ip: dict[str, dict]) -> list[S.DecisionFact]:
    b = ctx.b
    facts: list[S.DecisionFact] = []
    hs = b.host_strategy if isinstance(b.host_strategy, dict) else None
    hs_time = ctx.run_time("ai_host_strategy") or ctx.started or ctx.finished
    if hs:
        for entry in hs.get("hosts") or []:
            if not isinstance(entry, dict) or not entry.get("ip"):
                continue
            reasoning = str(entry.get("reasoning") or "")
            note = None
            if "[AUTO-OVERRIDE]" in reasoning or "[HARD-OVERRIDE" in reasoning:
                note = "KI-Skip durch Regel verworfen"
            facts.append(S.DecisionFact(
                id=f"dec:ai_host_strategy:{ip_token(str(entry['ip']))}", source="ai_host_strategy", mode="active",
                observed_at=hs_time, confidence=S.CONFIDENCE_TOOL,
                evidence=[S.Evidence(tool="ai_host_strategy", ref=b.refs.get("host_strategy", ""), excerpt=excerpt(reasoning, 200))],
                host_ip=str(entry["ip"]), payload={"action": entry.get("action"), "priority": entry.get("priority"), "reasoning": reasoning[:1000]},
                note=note,
            ))
        if hs.get("strategy_notes") or hs.get("passive_intel_summary"):
            facts.append(S.DecisionFact(
                id="dec:ai_host_strategy:scan", source="ai_host_strategy", mode="active", observed_at=hs_time,
                confidence=S.CONFIDENCE_TOOL, evidence=[S.Evidence(tool="ai_host_strategy", ref=b.refs.get("host_strategy", ""), excerpt=excerpt(hs.get("strategy_notes"), 200))],
                payload={"strategy_notes": str(hs.get("strategy_notes") or "")[:1000], "passive_intel_summary": str(hs.get("passive_intel_summary") or "")[:1000]},
            ))
    if isinstance(b.phase3_summary, dict):
        # Protokoll der Phase-3-Korrelation: wie viele Werkzeugmeldungen
        # eingingen und wie viele mit welcher Begruendung verworfen wurden.
        # Das belegt den Abschnitt "Filterung" im Bericht; ein Befund wird
        # daraus nie. Die Bilanz kommt aus der Zeile ``phase3_correlation``,
        # die der Produktionspfad seit S5b mitliest.
        ps = b.phase3_summary
        zahlen = {k: ps.get(k) for k in ("total_findings", "false_positives", "valid_findings",
                                         "cves_enriched", "cisa_kev_matches")
                  if isinstance(ps.get(k), int)}
        gruende = ps.get("fp_by_reason") if isinstance(ps.get("fp_by_reason"), dict) else {}
        if zahlen or gruende:
            facts.append(S.DecisionFact(
                id="dec:phase3_correlation:scan", source="phase3_correlation", mode="active",
                observed_at=ctx.run_time("phase3_correlation") or ctx.finished,
                confidence=S.CONFIDENCE_TOOL,
                evidence=[S.Evidence(tool="phase3_correlation", ref=b.refs.get("phase3_summary", ""),
                                     excerpt=excerpt(dumps(zahlen), 200))],
                payload={**zahlen, "fp_by_reason": {str(k): v for k, v in sorted(gruende.items())}},
                note="Bilanz der Korrelation, kein Befund.",
            ))
    if isinstance(b.ai_prioritization, dict):
        ap = b.ai_prioritization
        facts.append(S.DecisionFact(
            id="dec:ai_prioritization:scan", source="ai_prioritization", mode="active",
            observed_at=ctx.run_time("phase3_correlation") or ctx.finished, confidence=S.CONFIDENCE_TOOL,
            evidence=[S.Evidence(tool="ai_prioritization", ref=b.refs.get("ai_prioritization", ""), excerpt=excerpt(ap.get("strategy_notes"), 200))],
            payload={"strategy_notes": str(ap.get("strategy_notes") or "")[:1000], "skipped_by_gate": bool(ap.get("_skipped_by_gate")),
                     "confidence_scores": len(ap.get("confidence_scores") or [])},
        ))
    for ip in ips:
        h = b.hosts.get(ip)
        inv = inv_by_ip.get(ip, {})
        if h is not None:
            counters: dict[str, int] = defaultdict(int)
            for r in sorted(h.ai_rows, key=lambda r: sort_key(r.tool, r.created_at, r.index)):
                counters[r.tool] += 1
                n = counters[r.tool]
                if r.is_debug:
                    data = r.json()
                    cost = data.get("cost") if isinstance(data, dict) and isinstance(data.get("cost"), dict) else {}
                    payload = {"model": cost.get("model"), "cache_hit": cost.get("cache_hit"), "status": r.status}
                else:
                    data = r.json()
                    payload = _cap_payload(data) if isinstance(data, dict) else {"raw": excerpt(r.raw_output, 500)}
                facts.append(S.DecisionFact(
                    id=f"dec:{r.tool}:{ip_token(ip)}" + (f"#{n}" if n > 1 else ""), source=r.tool, mode="active",
                    observed_at=r.created_at or ctx.finished, confidence=S.CONFIDENCE_TOOL,
                    evidence=[S.Evidence(tool=r.tool, ref=r.ref, excerpt=excerpt(r.raw_output, 160))],
                    host_ip=ip, payload=payload,
                ))
            tp = h.tech_profile if isinstance(h.tech_profile, dict) else None
            if tp and tp.get("cms"):
                details = tp.get("cms_details") if isinstance(tp.get("cms_details"), dict) else {}
                dv = details.get("version")
                note = None
                if not details:
                    note = "cms_details leer: cms/cms_version stammen aus KI#2"
                elif dv and tp.get("cms_version") and str(dv) != str(tp.get("cms_version")):
                    note = f"cms_version {tp.get('cms_version')} weicht von cms_details {dv} ab"
                facts.append(S.DecisionFact(
                    id=f"dec:cms_profile:{ip_token(ip)}", source="ai_tech_analysis", mode="active",
                    observed_at=ctx.run_time("ai_tech_analysis_debug") or ctx.finished, confidence=S.CONFIDENCE_DERIVED,
                    evidence=[S.Evidence(tool="tech_profile", ref=h.refs.get("tech_profile.json", ""), excerpt=excerpt(f"cms={tp.get('cms')} cms_version={tp.get('cms_version')} cms_confidence={tp.get('cms_confidence')}", 160))],
                    host_ip=ip, payload={"cms": tp.get("cms"), "cms_version": tp.get("cms_version"), "cms_confidence": tp.get("cms_confidence"),
                                         "cms_details_version": dv, "is_spa": tp.get("is_spa")}, note=note,
                ))
        for v in inv.get("vhosts") or []:
            if not isinstance(v, dict) or not v.get("fqdn"):
                continue
            ss = v.get("site_summary")
            if isinstance(ss, dict) and ss:
                facts.append(S.DecisionFact(
                    id=ctx.unique_id(f"dec:site_summary:{v['fqdn']}", ip_token(ip)), source="site_summary", mode="active",
                    observed_at=ctx.run_time("web_probe") or ctx.started or ctx.finished, confidence=S.CONFIDENCE_DERIVED,
                    evidence=[S.Evidence(tool="site_summary", ref=b.refs.get("host_inventory", ""), excerpt=excerpt(ss.get("description"), 160))],
                    host_ip=ip, fqdn=str(v["fqdn"]), payload={"classification": ss.get("classification"), "is_real_content": ss.get("is_real_content"),
                                                             "confidence": ss.get("confidence"), "description": str(ss.get("description") or "")[:300]},
                ))
    facts.sort(key=lambda f: sort_key(f.source, f.host_ip, f.fqdn, f.id))
    return facts


def _cap_payload(data: dict[str, Any], limit: int = 600) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, str):
            out[k] = v[:limit]
        elif isinstance(v, (int, float, bool)) or v is None:
            out[k] = v
        elif isinstance(v, list):
            out[k] = [x if isinstance(x, (int, float, bool, str)) else str(x)[:120] for x in v[:30]]
        elif isinstance(v, dict):
            out[k] = _cap_payload(v, limit)
    return out


def _run_ref(self: _Ctx, tool: str, ip: Optional[str], fqdn: Optional[str] = None) -> str:
    runs = self.runs.get((tool, ip)) or []
    if fqdn:
        for r in runs:
            if r.vhost() == fqdn:
                return r.ref
    return runs[0].ref if runs else f"scan_results:{tool}" + (f":{ip}" if ip else "")


_Ctx.run_ref = _run_ref  # type: ignore[attr-defined]

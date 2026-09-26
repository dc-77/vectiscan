"""Systeme, geteilte Adressen, Drittanbieter und Erreichbarkeit (S6b-1).

Drei Fakten je Host, die erst entstehen koennen, wenn alle anderen Entitaeten stehen:

* ``shared`` (spec/09 Q3): Liegt die Adresse auf einem geteilten System? Plattform, wenn
  ein Name des Kunden per CNAME auf eine fremde Domain zeigt oder der Scanner eine
  CDN-Kante erkannt hat. Hoster, wenn fremde Namen auf der Adresse liegen (Zertifikat,
  Shodan), das rDNS nicht zum Kunden gehoert und die Adresse kein eigener Anschluss ist.
* ``third_party`` (spec/09 Teil 2): Der Scanner hat die Adresse begruendet uebersprungen
  (``ai_host_skip``) und jeder Kundenname darauf zeigt per CNAME nach draussen.
* ``reach`` (spec/09 Q9, E4): Hat der Portscan etwas gesehen? Ohne offenen Port liegt
  kein Messergebnis vor; meldet eine Passivquelle juenger als sieben Tage Dienste, ist der
  Host vom Pruefstand aus nicht erreichbar.

IPv4 und IPv6 mit demselben rDNS sind ein System mit zwei Adressen (spec/09 Q16). Die
Einstufung "geteilt" gilt fuer das ganze System: bei heuel liegen die fremden Namen nur
auf der IPv6-Adresse von www51.your-server.de.

Nichts hier ist eine Einstufung oder ein Befund; es sind abgeleitete Fakten mit Beleg.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import Iterable, Optional

from reporter.facts import schema as S
from reporter.facts.serialize import days_between, sort_key

# Passivquellen, deren Dienstmeldung als "juenger als sieben Tage" zaehlt (E4).
PASSIVE_RECENT_DAYS = 7
# AbuseIPDB-Nutzungsart eines eigenen Anschlusses. Fremde Namen auf einer solchen
# Adresse sind eigene Zweitdomains oder alte Eintraege, kein geteiltes Hosting
# (Junkerwerk .28 mit junkerwerk-solingen.de).
OWN_LINE_USAGE = "fixed line isp"
# S6b-3 (spec/10 R13): Nutzungsarten eines Anschlusses (AbuseIPDB ``usageType``).
LINE_USAGES = frozenset({OWN_LINE_USAGE, "mobile isp", "fixed line isp/mobile isp"})
IPV6_ROUTE_REASONS = frozenset({"no_ipv6_route", "target_invalid_ipv6"})

_IP_LIKE = re.compile(r"^\d{1,3}(?:[.-]\d{1,3}){3}\b")
# Ein fremder Name muss ein DNS-Name sein. Zertifikate tragen auch Etiketten wie "plesk"
# oder "Kubernetes Ingress Controller Fake Certificate" und interne Namen (".local").
_DNS_NAME = re.compile(r"^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$")
_INTERNAL_TLDS = frozenset({"local", "localhost", "internal", "lan", "home", "arpa", "localdomain"})


# Netzbetreibernamen der Passivquelle tragen teils einen Zusatz nach einem Strich
# ("Hetzner Online AG - Rechenzentrum Haustechnik"). Im Bericht steht nur der Name.
_OPERATOR_SUFFIX = re.compile(r"\s+[-\u2013\u2014]\s+.*$")


def network_operator(isp: object) -> Optional[str]:
    """Name des Netzbetreibers ohne Zusatz nach einem Strich, None ohne Angabe."""
    text = _OPERATOR_SUFFIX.sub("", str(isp or "").strip())
    return text or None


def is_dns_name(name: object) -> bool:
    text = clean_name(name)
    return bool(_DNS_NAME.match(text)) and text.rsplit(".", 1)[-1] not in _INTERNAL_TLDS


# ---------------------------------------------------------------- Namen

def clean_name(name: object) -> str:
    text = str(name or "").strip().lower().rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    return text


def registrable(name: object) -> str:
    """Die registrierbare Domain eines Namens, vereinfacht: die letzten zwei Labels.

    Mehrteilige Endungen (``co.uk``) kommen in den Auftraegen nicht vor; fuer sie waere
    das Ergebnis zu grob, aber nie falsch herum (zwei fremde Namen blieben fremd).
    """
    parts = [p for p in clean_name(name).split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else ".".join(parts)


def under(name: object, domains: Iterable[str]) -> bool:
    n = clean_name(name)
    for d in domains:
        d = clean_name(d)
        if d and (n == d or n.endswith("." + d)):
            return True
    return False


def is_ip_like(name: object) -> bool:
    text = clean_name(name)
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return bool(_IP_LIKE.match(text))


def covers(pattern: object, name: object) -> bool:
    """Deckt ein Zertifikatsname (auch ``*.x.de``) den Namen ab?"""
    p = str(pattern or "").strip().lower().rstrip(".")
    n = clean_name(name)
    if not p or not n:
        return False
    if p == n:
        return True
    if p.startswith("*."):
        rest = p[2:]
        return n.endswith("." + rest) and n.count(".") == rest.count(".") + 1
    return False


# ---------------------------------------------------------------- Systeme

def system_key(host: S.HostFact) -> str:
    return clean_name(host.reverse) if host.reverse else host.ip


def system_groups(hosts: Iterable[S.HostFact]) -> dict[str, list[S.HostFact]]:
    """Hosts je System. Nur IPv4 und IPv6 mit identischem rDNS laufen zusammen;
    zwei IPv4-Adressen mit gleichem rDNS bleiben getrennt, weil das kein Merkmal
    desselben Systems ist."""
    by_reverse: dict[str, list[S.HostFact]] = defaultdict(list)
    out: dict[str, list[S.HostFact]] = {}
    for h in hosts:
        if h.reverse:
            by_reverse[clean_name(h.reverse)].append(h)
        else:
            out[h.ip] = [h]
    for rdns, members in by_reverse.items():
        v4 = [h for h in members if h.family == 4]
        v6 = [h for h in members if h.family == 6]
        if len(v4) == 1 and v6:
            out[rdns] = sorted(members, key=lambda h: (h.family, sort_key(h.ip)))
        else:
            for h in members:
                out[h.ip] = [h]
    return out


def system_of(hosts: Iterable[S.HostFact]) -> dict[str, list[str]]:
    """IP -> alle Adressen desselben Systems (IPv4 zuerst)."""
    out: dict[str, list[str]] = {}
    for members in system_groups(hosts).values():
        ips = [h.ip for h in members]
        for ip in ips:
            out[ip] = ips
    return out


# ---------------------------------------------------------------- Ableitung

def _foreign_cname_target(fqdn: S.FqdnFact, domains: list[str]) -> Optional[str]:
    for target in fqdn.cname:
        if not under(target, domains):
            return target
    return None


def derive(facts: S.Facts, *, finished: Optional[str]) -> None:
    """Setzt ``shared``, ``third_party`` und ``reach`` an den Hosts (in place)."""
    domains = [clean_name(d) for d in (facts.scan.domains or [facts.scan.domain]) if d]
    fq_by_ip: dict[str, list[S.FqdnFact]] = defaultdict(list)
    for fq in facts.fqdns:
        if not fq.wildcard and under(fq.name, domains):
            fq_by_ip[fq.host_ip].append(fq)
    skipped = {d.host_ip for d in facts.decisions if d.source == "ai_host_skip" and d.host_ip}

    for members in system_groups(facts.hosts).values():
        shared = _shared(facts, members, domains, fq_by_ip)
        for h in members:
            h.shared = shared
    mail_ips = _customer_mail_ips(facts, domains)
    for h in facts.hosts:
        h.third_party = _third_party(h, fq_by_ip.get(h.ip, []), domains, skipped, facts)
        h.reach = None if h.third_party else _reach(facts, h, finished)
        h.betriebsform = betriebsform(h)
        h.serves_customer_mail = h.ip in mail_ips
        h.serves_customer_web = any(fq.real_content is True and not fq.wildcard for fq in fq_by_ip.get(h.ip, []))


def _customer_mail_ips(facts: S.Facts, domains: list[str]) -> set[str]:
    """Adressen, auf die MX, ein SPF-Mechanismus oder Autodiscover des Kunden zeigen (spec/10 R9)."""
    by_name: dict[str, set[str]] = defaultdict(set)
    for fq in facts.fqdns:
        by_name[clean_name(fq.name)].add(fq.host_ip)
    out: set[str] = set()
    for d in facts.dns:
        for mx in d.mx:
            out |= by_name.get(clean_name(str(mx).split()[-1]), set())
        if d.spf:
            for mech in d.spf.mechanisms:
                if mech.kind in ("a", "mx", "ip4", "ip6"):
                    out.update(mech.ips)
        out |= by_name.get(clean_name(f"autodiscover.{d.domain}"), set())
    return out


def _names_on(facts: S.Facts, ips: set[str]) -> dict[str, tuple[str, str, str]]:
    """Fremd lesbare Namen auf den Adressen: Name -> (Werkzeug, Fundstelle, Auszug)."""
    out: dict[str, tuple[str, str, str]] = {}
    for p in facts.passive:
        if p.source == "shodan" and p.host_ip in ips:
            ref = p.evidence[0].ref if p.evidence else ""
            for name in p.hostnames:
                out.setdefault(clean_name(name), ("shodan", ref, f"Shodan-Hostnamen {p.host_ip}: "
                                                   + ", ".join(p.hostnames[:6])))
    for t in facts.tls:
        if t.host_ip not in ips or t.cert is None:
            continue
        ref = t.evidence[0].ref if t.evidence else ""
        tool = t.evidence[0].tool if t.evidence else t.source
        for name in [t.cert.cn, *t.cert.san]:
            if name:
                out.setdefault(clean_name(name), (tool, ref, f"Zertifikat {t.fqdn or t.host_ip}:{t.port}: "
                                                   + ", ".join(([t.cert.cn] if t.cert.cn else []) + t.cert.san[:5])))
    for s in facts.services:
        if s.host_ip not in ips or s.cert is None:
            continue
        ref = s.evidence[0].ref if s.evidence else ""
        for name in [s.cert.cn, *s.cert.san]:
            if name:
                out.setdefault(clean_name(name), ("nmap", ref, f"Zertifikat {s.host_ip}:{s.port}: "
                                                   + ", ".join(([s.cert.cn] if s.cert.cn else []) + s.cert.san[:5])))
    return out


def _shared(facts: S.Facts, members: list[S.HostFact], domains: list[str],
            fq_by_ip: dict[str, list[S.FqdnFact]]) -> Optional[S.SharedSystem]:
    ips = {h.ip for h in members}
    # Plattform: ein Kundenname zeigt per CNAME nach draussen, oder CDN-Kante.
    for h in members:
        for fq in sorted(fq_by_ip.get(h.ip, []), key=lambda f: sort_key(f.name)):
            target = _foreign_cname_target(fq, domains)
            if target:
                return S.SharedSystem(
                    kind="platform", operator=registrable(target), foreign_names=[],
                    signals=["cname_fremd"],
                    evidence=[S.Evidence(tool="dnsx", ref="phase0/dnsx_validation.json",
                                         excerpt=f"{fq.name} CNAME " + " > ".join(fq.cname[:4]))])
    for h in members:
        if h.cdn_provider:
            return S.SharedSystem(
                kind="platform", operator=h.cdn_provider, signals=["cdn"],
                evidence=[S.Evidence(tool="host_inventory", ref="phase0/host_inventory.json",
                                     excerpt=f"{h.ip}: CDN {h.cdn_provider}")])
    # Hoster: fremde Namen, rDNS beim Betreiber, kein eigener Anschluss.
    reverses = sorted({clean_name(h.reverse) for h in members if h.reverse})
    rdns_fremd = [r for r in reverses if not under(r, domains)]
    usages = {(h.provider.usage_type or "").strip().lower() for h in members if h.provider}
    if not rdns_fremd or OWN_LINE_USAGE in usages:
        return None
    ausgenommen = {registrable(r) for r in reverses}
    names = _names_on(facts, ips)
    fremd = sorted((n for n in names
                    if n and is_dns_name(n) and not under(n, domains) and not is_ip_like(n)
                    and registrable(n) not in ausgenommen),
                   key=sort_key)
    if not fremd:
        return None
    operator = next((network_operator(h.provider.isp) for h in members
                     if h.provider and h.provider.isp), None)
    evidence: list[S.Evidence] = []
    seen: set[str] = set()
    for n in fremd:
        tool, ref, text = names[n]
        if text not in seen:
            seen.add(text)
            evidence.append(S.Evidence(tool=tool, ref=ref, excerpt=text[:200]))
    evidence.append(S.Evidence(tool="host_inventory", ref="phase0/host_inventory.json",
                               excerpt=f"rDNS {', '.join(rdns_fremd)}"))
    usage_text = ", ".join(sorted(u for u in usages if u))
    if usage_text:
        evidence.append(S.Evidence(tool="abuseipdb", ref="phase0a/abuseipdb.json",
                                   excerpt=f"Nutzungsart {usage_text}"))
    tools = {names[n][0] for n in fremd}
    signals = sorted({"fremde_namen_zertifikat" if t != "shodan" else "fremde_namen_shodan" for t in tools}
                     | {"rdns_betreiber"})
    return S.SharedSystem(kind="hoster", operator=operator, foreign_names=fremd[:12],
                          signals=signals, evidence=evidence[:6])


def _third_party(h: S.HostFact, fqdns: list[S.FqdnFact], domains: list[str], skipped: set[str],
                 facts: S.Facts) -> Optional[S.ThirdParty]:
    if h.ip not in skipped or not fqdns:
        return None
    targets = [_foreign_cname_target(fq, domains) for fq in fqdns]
    if not all(targets):
        return None
    operator = (network_operator(h.provider.isp) if h.provider and h.provider.isp
                else None) or registrable(targets[0])
    decision = next((d for d in facts.decisions if d.source == "ai_host_skip" and d.host_ip == h.ip), None)
    evidence = [S.Evidence(tool="dnsx", ref="phase0/dnsx_validation.json",
                           excerpt=f"{fq.name} CNAME " + " > ".join(fq.cname[:3])) for fq in fqdns][:3]
    if decision is not None and decision.evidence:
        evidence.append(decision.evidence[0])
    return S.ThirdParty(operator=operator, evidence=evidence)


def _reach(facts: S.Facts, h: S.HostFact, finished: Optional[str]) -> Optional[S.Reach]:
    nmap_rows = [c for c in facts.coverage if c.tool == "nmap" and c.host_ip == h.ip]
    if any(c.status == "failed" and (c.reason or "") in IPV6_ROUTE_REASONS for c in nmap_rows):
        return S.Reach(status="no_ipv6_route")
    if h.nmap_state is None or h.ports_summary.open > 0:
        return None
    if not any(c.status in ("ok", "empty") for c in nmap_rows) and nmap_rows:
        return None
    recent = [p for p in facts.passive
              if p.host_ip == h.ip and p.port is not None and p.seen_at
              and (days_between(finished, p.seen_at) if finished else None) is not None
              and 0 <= (days_between(finished, p.seen_at) or 0) <= PASSIVE_RECENT_DAYS]
    if recent:
        seen = max(p.seen_at for p in recent if p.seen_at)
        return S.Reach(status="unreachable_from_scanner",
                       passive_ports=sorted({p.port for p in recent if p.port is not None}),
                       passive_seen_at=seen, passive_source=recent[0].source)
    # S6b-3 (spec/10 R3): ohne Hostbericht von nmap ist nicht belegt, dass der Host
    # antwortet; "kein offener Port" waere eine Aussage, die die Messung nicht traegt.
    if h.nmap_host_report is False:
        return S.Reach(status="no_response")
    return S.Reach(status="no_open_ports")


def betriebsform(h: S.HostFact) -> S.Betriebsform:
    """Betriebsform einer Adresse (spec/10 R13): wo steht das System?

    ``plattform``: geteiltes System der Art Plattform oder CDN-Kante. ``anschluss``: die
    Nutzungsart laut AbuseIPDB ist ein Festnetz- oder Mobilanschluss (eigene Leitung des
    Kunden, Junkerwerk 217.243.248.28). ``rechenzentrum``: geteilter Server beim Hoster oder
    Nutzungsart Rechenzentrum/Hosting. Sonst ``unbekannt``; dann stehen neutrale Texte.
    """
    if h.shared is not None and h.shared.kind == "platform" or h.cdn_provider:
        return "plattform"
    usage = (h.provider.usage_type or "").strip().lower() if h.provider else ""
    if usage in LINE_USAGES:
        return "anschluss"
    if h.shared is not None and h.shared.kind == "hoster":
        return "rechenzentrum"
    if any(k in usage for k in ("data center", "hosting", "content delivery")):
        return "rechenzentrum"
    return "unbekannt"


def adjust_nmap_coverage(facts: S.Facts) -> None:
    """nmap ohne offenen Port ist kein Messergebnis (spec/09 Q9): ``empty`` mit dem
    Grund aus ``reach`` statt ``ok``."""
    reach = {h.ip: h.reach.status for h in facts.hosts
             if h.reach and h.reach.status in ("no_open_ports", "no_response", "unreachable_from_scanner")}
    for c in facts.coverage:
        if c.tool == "nmap" and c.host_ip in reach and c.status == "ok":
            c.status = "empty"
            c.reason = reach[c.host_ip]


__all__ = ["PASSIVE_RECENT_DAYS", "clean_name", "registrable", "under", "is_ip_like", "is_dns_name", "covers",
           "system_key", "system_groups", "system_of", "derive", "adjust_nmap_coverage"]

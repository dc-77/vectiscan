# -*- coding: utf-8 -*-
"""Rollen der Systeme, nur mit Fakt (S6b-1, spec/09 Q2).

Bis S6b-1 entstand "Mail- und Kalenderplattform" aus offenen Mailports und "Website und
Datenbanken" aus jedem Webserver. Bei lumbeck-wolter lag der MX bei Hornetsecurity und
der Host war ein Managed Server des Hosters; der Bericht schrieb trotzdem, ueber dieses
System laufe die geschaeftliche Korrespondenz.

Belegregeln je Rolle:

* E-Mail: ein MX-Name der Kundendomain liegt auf dem Host, ein SPF-Mechanismus deckt die
  Adresse (``ip4``/``ip6``, ``a``, ``a:name``, ``mx``) oder ein Autodiscover-Name zeigt auf
  den Host. MX und Autodiscover heissen Empfang, SPF allein nur Versand.
* Kalender: zusaetzlich ein Exchange-Fakt vom eigenen Host (Software, X-FEServer, OWA im
  Banner der Passivquelle).
* Mail-Webzugang, Passwortverwaltung, Kollaboration, Anmeldeportal: Titel oder Software an
  einem Namen des Kunden auf diesem Host.
* Website: ein Name des Kunden liefert eine eigene Seite (Status 200, keine Fehler-,
  Weiterleitungs- oder Standardseite, keine Weiterleitung auf einen anderen Host).
* Datenbank nur mit offenem Datenbankport, Fernzugang nur mit SSH, RDP, VPN oder
  Verwaltungsoberflaeche als Dienst, Dateiaustausch nur mit FTP-Dienst. Auf geteilten
  Systemen entfallen diese Server-Rollen: sie gehoeren dem Betreiber, nicht dem Kunden.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from reporter.facts import schema as FS
from reporter.facts import systems as SYS
from reporter.facts.serialize import sort_key
from reporter.v3 import tables as T

MAX_ROLES = 3

TITLE_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("passwort", re.compile(r"bitwarden|vaultwarden|passbolt|psono", re.I)),
    ("kollaboration", re.compile(r"nextcloud|owncloud|sharepoint|confluence|jitsi|mattermost|rocket\.chat|"
                                 r"onlyoffice|seafile", re.I)),
    ("webmail", re.compile(r"^\s*outlook\s*$|outlook web|roundcube|\bsogo\b|\bhorde\b|rainloop|zimbra|webmail", re.I)),
    ("anmeldeportal", re.compile(r"web applications portal|\blog ?in\b|\banmeld|\bsign ?in\b|single sign|\badfs\b|"
                                 r"keycloak|citrix gateway", re.I)),
]
SOFTWARE_ROLES: dict[str, str] = {"bitwarden": "passwort", "nextcloud": "kollaboration",
                                  "owncloud": "kollaboration", "roundcube": "webmail"}
NOT_WEBSITE = re.compile(
    r"^\s*(\d{3}\b|iis windows server|redirector|just a moment|vercel security checkpoint|welcome to nginx|"
    r"apache2 .*default|default (web )?page|index of|error\b|access denied|forbidden)", re.I)
REMOTE_SERVICES = frozenset({"ssh", "ms-wbt-server", "rdp", "vnc", "openvpn", "pptp", "ipsec"})
REMOTE_PRODUCTS = re.compile(r"fortinet|fortigate|sonicwall|pulse secure|globalprotect|openvpn|citrix|"
                             r"rd ?gateway|webmin|miniserv|plesk|sw-cp-server|cpanel|proxmox", re.I)
EXCHANGE_PASSIVE = re.compile(r"/owa\b|x-owa-version|x-feserver", re.I)


@dataclass(frozen=True)
class Role:
    key: str
    evidence: tuple[str, ...] = ()
    # S6b-3 (spec/10 R9): HTTP-Status, wenn der Name nur eine Fehlerseite liefert
    # (castenow mailstore, Nextcloud mit 400 "Access through untrusted domain").
    status: Optional[int] = None

    @property
    def label(self) -> str:
        return T.ROLE_DEFS[self.key][0]

    @property
    def meaning(self) -> str:
        text = T.ROLE_DEFS[self.key][1]
        if self.status and self.status >= 400:
            text += (f" Unter dem geprüften Namen liefert der Dienst nur eine Fehlerseite "
                     f"({self.status}).")
        return text


def _customer_names(facts: FS.Facts, host: FS.HostFact) -> list[FS.FqdnFact]:
    domains = list(facts.scan.domains) or [facts.scan.domain]
    return [f for f in facts.fqdns if f.host_ip == host.ip and not f.wildcard and SYS.under(f.name, domains)]


def _in_net(ip: str, value: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False


def mail_evidence(facts: FS.Facts, host: FS.HostFact) -> tuple[list[str], list[str]]:
    """(Empfang, Versand): Belege aus MX, Autodiscover und SPF der Kundendomains."""
    names = {SYS.clean_name(n) for n in host.fqdns}
    if host.reverse:
        names.add(SYS.clean_name(host.reverse))
    empfang: list[str] = []
    versand: list[str] = []
    for dns in facts.dns:
        for mx in dns.mx:
            if SYS.clean_name(mx) in names:
                empfang.append(f"MX-Eintrag von {dns.domain}: {mx}")
        if dns.spf is None:
            continue
        for m in dns.spf.mechanisms:
            if m.qualifier != "+":
                continue
            beleg = f"SPF-Eintrag von {dns.domain}: {m.kind}" + (f":{m.value}" if m.value else "")
            if m.kind in ("ip4", "ip6") and m.value and _in_net(host.ip, m.value):
                versand.append(beleg)
            elif m.kind == "a" and SYS.clean_name(m.value or dns.domain) in names:
                versand.append(beleg)
            elif m.kind == "mx" and not m.value and any(SYS.clean_name(x) in names for x in dns.mx):
                versand.append(beleg)
    for name in sorted(host.fqdns, key=sort_key):
        if SYS.clean_name(name).startswith("autodiscover."):
            empfang.append(f"Autodiscover-Name {name}")
    return empfang, versand


def exchange_evidence(facts: FS.Facts, host: FS.HostFact) -> list[str]:
    out = [f"{s.product} {s.version_norm or ''}".strip() + f" ({', '.join(s.detection_sources)})"
           for s in facts.software if s.host_ip == host.ip and s.family == "exchange"]
    out += [f"X-FEServer an {h.fqdn}" for h in facts.http if h.host_ip == host.ip and h.x_feserver]
    out += [f"Passivquelle Port {p.port}: Outlook im Web" for p in facts.passive
            if p.host_ip == host.ip and p.banner_excerpt and EXCHANGE_PASSIVE.search(p.banner_excerpt)]
    return out[:3]


def _redirects_away(facts: FS.Facts, fq: FS.FqdnFact) -> bool:
    final = SYS.clean_name(urlsplit(fq.final_url or "").hostname or "")
    if not final or final == SYS.clean_name(fq.name):
        return False
    return not any(f.host_ip == fq.host_ip and SYS.clean_name(f.name) == final for f in facts.fqdns)


def host_roles(facts: FS.Facts, host: FS.HostFact) -> list[Role]:
    """Belegte Rollen eines Hosts, spezifische zuerst, hoechstens ``MAX_ROLES``."""
    if host.third_party is not None:
        return []
    found: dict[str, list[str]] = {}
    fehlerseite: dict[str, list[int]] = {}
    wordpress = {h.fqdn for h in facts.http if h.host_ip == host.ip and h.wordpress is not None}

    def add(key: str, beleg: str) -> None:
        found.setdefault(key, [])
        if beleg not in found[key]:
            found[key].append(beleg)

    empfang, versand = mail_evidence(facts, host)
    if empfang:
        exchange = exchange_evidence(facts, host)
        key = "mail_kalender" if exchange else "mail"
        for b in empfang + versand + exchange:
            add(key, b)
    elif versand:
        for b in versand:
            add("mail_versand", b)
    for fq in sorted(_customer_names(facts, host), key=lambda f: sort_key(f.name)):
        title = (fq.title or "").strip()
        if _redirects_away(facts, fq):
            continue
        rolle = next((key for key, rx in TITLE_RULES if title and rx.search(title)), None)
        if rolle == "anmeldeportal" and fq.name in wordpress:
            rolle = "redaktion"
        if rolle:
            add(rolle, f"{fq.name}: Titel „{title[:60]}“")
            status = fq.http_status if isinstance(fq.http_status, int) else None
            fehlerseite.setdefault(rolle, []).append(status if status and status >= 400 else 0)
            continue
        if fq.http_status == 200 and title and not NOT_WEBSITE.search(title):
            add("website", f"{fq.name}: Seite „{title[:60]}“")
    for sw in facts.software:
        if sw.host_ip == host.ip and sw.family in SOFTWARE_ROLES:
            add(SOFTWARE_ROLES[sw.family], f"{sw.product} ({', '.join(sw.detection_sources)})")
    if host.shared is None:
        for s in facts.services:
            if s.host_ip != host.ip or s.state != "open":
                continue
            beleg = f"{s.port}/{s.proto} {s.service or ''} {s.product or ''}".strip()
            if s.port in T.DB_PORTS:
                add("datenbank", beleg)
            elif (s.service or "") in REMOTE_SERVICES or s.port == 3389 \
                    or REMOTE_PRODUCTS.search(f"{s.product or ''} {s.service or ''}"):
                add("fernzugang", beleg)
            elif (s.service or "") == "ftp" or s.port == 21:
                add("dateiaustausch", beleg)
    order = {k: i for i, k in enumerate(T.ROLE_ORDER)}
    keys = sorted(found, key=lambda k: order.get(k, len(order)))
    def status_of(key: str) -> Optional[int]:
        # Nur wenn jeder Titelbeleg der Rolle eine Fehlerseite ist; die Softwareerkennung liest
        # dieselbe Seite und aendert daran nichts.
        werte = fehlerseite.get(key) or []
        return werte[0] if werte and all(werte) else None

    return [Role(key=k, evidence=tuple(found[k][:3]), status=status_of(k)) for k in keys[:MAX_ROLES]]


def role_label(roles: list[Role]) -> str:
    return ", ".join(r.label for r in roles) if roles else T.ROLE_FALLBACK


def role_meaning(roles: list[Role]) -> str:
    return roles[0].meaning if roles else T.ROLE_FALLBACK_MEANING


def allowed_categories(role_keys) -> set[str]:
    out: set[str] = set()
    for k in role_keys:
        out |= set(T.ROLE_CATEGORIES.get(k, ()))
    return out


def role_words_without_fact(text: str, role_keys, reference: str = "") -> list[str]:
    """Rollenwoerter im Text, deren Kategorie keine belegte Rolle traegt.

    Ein Wort, das schon im deterministischen Bezugstext steht (Katalogtext des Befunds),
    ist keine neue Behauptung; es darf bleiben.
    """
    low = (text or "").lower()
    ref = (reference or "").lower()
    erlaubt = allowed_categories(role_keys)
    out: list[str] = []
    for kategorie, woerter in T.ROLE_WORDS.items():
        if kategorie in erlaubt:
            continue
        for w in woerter:
            if re.search(rf"\b{re.escape(w)}", low) and w not in ref:
                out.append(w)
    return sorted(set(out))


__all__ = ["Role", "MAX_ROLES", "host_roles", "role_label", "role_meaning", "mail_evidence",
           "exchange_evidence", "allowed_categories", "role_words_without_fact"]

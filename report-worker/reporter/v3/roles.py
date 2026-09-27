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
  Systemen entfaellt der Fernzugang: er gehoert dem Betreiber, nicht dem Kunden.
* S6b-4n (spec/11 N4, N14): Mailabruf und Einlieferung aus aktiv bestaetigten Mailports,
  Datenbanken und Dateiaustausch auch auf geteilten Systemen (die Dienste sind von aussen
  erreichbar, zustaendig bleibt der Hoster); "Mail-Webzugang laut Passivquelle" aus dem Pfad
  /owa/ der Passivquelle; Seitentitel an weiteren Webports ("Web Applications Portal" auf 444);
  ein Name, der auf einen anderen Host weiterleitet, macht die Rolle "Weiterleitung auf <Ziel>".
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

MAX_ROLES = 5
# S6b-4n (spec/11 N14): Mailports mit Abruf (POP3, IMAP) und Einlieferung (Submission).
MAIL_FETCH_PORTS = frozenset({110, 143, 993, 995})
MAIL_SUBMIT_PORTS = frozenset({465, 587})
MAIL_SERVICES = re.compile(r"^(?:pop3s?|imaps?|smtps?|submission|ssl/(?:imap|pop3|smtp))\??$", re.I)

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
    # S6b-4 (spec/11 T10): Bedeutung nach Fakt (T.ROLE_VARIANTS), leer fuer den Standardtext.
    variant: str = ""
    # S6b-4 (spec/11 Teil 3): Zusatz im Namen ("Dateiaustausch (FTP, SFTP)") oder ein eigener
    # Name ("Umfrageplattform (umfrageonline.com), leitet auf die Website weiter").
    detail: str = ""
    name: str = ""

    @property
    def label(self) -> str:
        if self.name:
            return self.name
        base = T.ROLE_DEFS[self.key][0]
        return f"{base} ({self.detail})" if self.detail else base

    @property
    def meaning(self) -> str:
        text = T.ROLE_VARIANTS.get((self.key, self.variant)) or T.ROLE_DEFS[self.key][1]
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


def redirect_target(facts: FS.Facts, fq: FS.FqdnFact) -> Optional[str]:
    """Ziel einer Weiterleitung auf einen anderen Host, laut Inventar oder Weiterleitungspruefung
    (S6b-4n, spec/11 N4: heuel online endet im Inventar auf sich selbst, die Probe auf www)."""
    for url in (fq.final_url, getattr(fq, "probe_final_url", None)):
        final = SYS.clean_name(urlsplit(url or "").hostname or "")
        if not final or final == SYS.clean_name(fq.name):
            continue
        if not any(f.host_ip == fq.host_ip and SYS.clean_name(f.name) == final for f in facts.fqdns):
            return final
    return None


def _redirects_away(facts: FS.Facts, fq: FS.FqdnFact) -> bool:
    return redirect_target(facts, fq) is not None


def _mail_services(facts: FS.Facts, host: FS.HostFact) -> tuple[list[str], list[str]]:
    """(Abruf, Einlieferung): aktiv bestaetigte Maildienste des Hosts (spec/11 N14)."""
    abruf: list[str] = []
    einlieferung: list[str] = []
    for s in facts.services:
        if s.host_ip != host.ip or s.state != "open" or s.foreign:
            continue
        erkannt = bool(s.product or s.kennung) and not s.unidentified
        if not erkannt:
            continue
        beleg = f"{s.port}/{s.proto} {s.kennung or s.product or s.service or ''}".strip()
        if s.port in MAIL_FETCH_PORTS or re.match(r"^(?:ssl/)?(?:pop3|imap)", s.service or "", re.I):
            abruf.append(beleg)
        elif s.port in MAIL_SUBMIT_PORTS or re.match(r"^(?:smtps|submission)", s.service or "", re.I):
            einlieferung.append(beleg)
    return abruf, einlieferung


def _passive_webmail(facts: FS.Facts, host: FS.HostFact) -> list[str]:
    """Pfad /owa/ laut Passivquelle (bergersysteme 62.217.52.166, vom Pruefstand nicht erreichbar)."""
    out: list[str] = []
    for p in facts.passive:
        if p.host_ip != host.ip or p.port is None:
            continue
        ort = str((p.details or {}).get("location") or "")
        if re.search(r"/owa\b", ort, re.I) or (p.banner_excerpt and re.search(r"/owa\b", p.banner_excerpt, re.I)):
            out.append(f"Passivquelle Port {p.port}: {ort or 'Pfad /owa/'}")
    return out


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

    namen: dict[str, str] = {}
    details: dict[str, list[str]] = {}
    domains = list(facts.scan.domains) or [facts.scan.domain]
    weiterleitungsziele: list[str] = []

    empfang, versand = mail_evidence(facts, host)
    if empfang:
        exchange = exchange_evidence(facts, host)
        key = "mail_kalender" if exchange else "mail"
        for b in empfang + versand + exchange:
            add(key, b)
    elif versand:
        for b in versand:
            add("mail_versand", b)
    # S6b-4n (spec/11 N14): Abruf und Einlieferung aus aktiv bestaetigten Mailports, auch ohne MX
    # (dortmund-beach und junkerwerk: Dovecot und Exim auf dem gemieteten Server).
    if not empfang:
        abruf, einlieferung = _mail_services(facts, host)
        for b in abruf + einlieferung:
            add("mail_dienste", b)
        teile = (["Mailabruf"] if abruf else []) + (["Einlieferung"] if einlieferung else [])
        if teile:
            namen["mail_dienste"] = " und ".join(teile)
    # S6b-4n (spec/11 N14): Mail-Webzugang allein laut Passivquelle (Host vom Pruefstand nicht erreichbar).
    passiv_owa = _passive_webmail(facts, host)
    if passiv_owa and host.reach is not None and host.reach.status == "unreachable_from_scanner":
        for b in passiv_owa:
            add("webmail", b)
        namen["webmail"] = "Mail-Webzugang laut Passivquelle"
    for fq in sorted(_customer_names(facts, host), key=lambda f: sort_key(f.name)):
        title = (fq.title or "").strip()
        ziel = next((t for t in fq.cname if not SYS.under(t, domains)), None)
        # Liefert der Name die eigene Website (huendgen www auf der Mandantenplattform), bleibt es
        # bei "Website"; ein Plattformdienst ist ein Name, der weiterleitet oder dessen Anbieter
        # einen bekannten Dienst betreibt (castenow umfrage).
        anbieter_bekannt = bool(ziel) and SYS.registrable(ziel) in T.PLATFORM_SERVICES
        if ziel and host.shared is not None and host.shared.kind == "platform" \
                and (anbieter_bekannt or _redirects_away(facts, fq)):
            # S6b-4 (spec/11 Teil 3 CA umfrage): Rolle aus dem CNAME, nicht aus der Zielseite.
            anbieter = SYS.registrable(ziel)
            art = T.PLATFORM_SERVICES.get(anbieter)
            weiter = ", leitet auf die Website weiter" if _redirects_to_customer(fq, domains) else ""
            add("plattform", f"{fq.name}: CNAME {ziel}")
            if art:
                namen.setdefault("plattform", f"{art} ({anbieter}){weiter}")
            elif weiter:
                # S6b-4n (spec/11 N4): heuel online leitet laut Weiterleitungspruefung auf www weiter.
                namen.setdefault("plattform", f"{T.ROLE_DEFS['plattform'][0]} ({anbieter}){weiter}")
            continue
        ziel_host = redirect_target(facts, fq)
        if ziel_host:
            # S6b-4n (spec/11 N4): Rolle aus der Antwort dieses Hosts, nicht aus der Zielseite.
            add("weiterleitung", f"{fq.name}: leitet auf {ziel_host} weiter")
            weiterleitungsziele.append(ziel_host)
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
    # S6b-4n (spec/11 N14): Seitentitel an weiteren Webports (huendgen 444 "Web Applications Portal").
    for s in facts.services:
        if s.host_ip != host.ip or s.state != "open" or s.port in (80, 443) or not s.fp_title or s.foreign:
            continue
        rolle = next((key for key, rx in TITLE_RULES if rx.search(s.fp_title)), None)
        if rolle:
            add(rolle, f"Port {s.port}: Titel „{s.fp_title[:60]}“")
            fehlerseite.setdefault(rolle, []).append(0)
            details.setdefault(rolle, []).append(f"Port {s.port}")
    # Server-Rollen aus den Diensten. S6b-4n (spec/11 N4, N14): auf geteilten Systemen nur die
    # Dienste, die der Kunde nutzt (Datenbanken, Dateiaustausch); der Fernzugang gehoert dem Betreiber.
    for s in facts.services:
        if s.host_ip != host.ip or s.state != "open" or s.foreign:
            continue
        beleg = f"{s.port}/{s.proto} {s.service or ''} {s.product or ''}".strip()
        if s.port in T.DB_PORTS:
            add("datenbank", beleg)
        elif _sftp_of_ftp_server(facts, s):
            # S6b-4 (spec/11 Teil 3 HL): SSH eines FTP-Servers ist SFTP, kein Fernzugang
            # (20.79.218.75: nmap FortiSSH, Passivquelle SSH-2.0-WingFTPServer).
            add("dateiaustausch", beleg)
            details.setdefault("dateiaustausch", []).append("SFTP")
        elif ((s.service or "") in REMOTE_SERVICES or s.port == 3389
              or REMOTE_PRODUCTS.search(f"{s.product or ''} {s.service or ''}")):
            if host.shared is None:
                add("fernzugang", beleg)
        elif (s.service or "") == "ftp" or s.port == 21:
            add("dateiaustausch", beleg)
            details.setdefault("dateiaustausch", []).insert(0, "FTP")
    # S6b-4n (spec/11 N14): Abruf, Einlieferung und Versand laut SPF sind eine Mailrolle; sonst
    # verdraengt die zweite die uebrigen Rollen (dortmund-beach: SPF a und Dovecot auf demselben Server).
    if "mail_dienste" in found and "mail_versand" in found:
        for b in found.pop("mail_versand"):
            add("mail_dienste", b)
        teile = namen.get("mail_dienste", T.ROLE_DEFS["mail_dienste"][0]).split(" und ")
        namen["mail_dienste"] = ", ".join(teile) + " und Versand laut SPF"
    if weiterleitungsziele and "website" not in found:
        ziele = list(dict.fromkeys(weiterleitungsziele))
        namen["weiterleitung"] = "Weiterleitung auf " + (ziele[0] if len(ziele) == 1
                                                          else ", ".join(ziele[:-1]) + " und " + ziele[-1])
    else:
        found.pop("weiterleitung", None)
    # S6b-4 (spec/11 Teil 3 HL ose): eine Anmeldemaske laut Webanalyse ohne Portal- oder
    # Redaktionstitel ist eine Webanwendung mit Anmeldung.
    mit_anmeldung = sorted(h.fqdn for h in facts.http if h.host_ip == host.ip and h.login_form and h.fqdn)
    if mit_anmeldung and not set(found) & {"anmeldeportal", "redaktion", "webmail", "passwort", "kollaboration",
                                           "mail_kalender"}:
        add("webanwendung", f"{mit_anmeldung[0]}: Anmeldeformular laut Webanalyse")
    order = {k: i for i, k in enumerate(T.ROLE_ORDER)}
    keys = sorted(found, key=lambda k: order.get(k, len(order)))
    def status_of(key: str) -> Optional[int]:
        # Nur wenn jeder Titelbeleg der Rolle eine Fehlerseite ist; die Softwareerkennung liest
        # dieselbe Seite und aendert daran nichts.
        werte = fehlerseite.get(key) or []
        return werte[0] if werte and all(werte) else None

    def variant_of(key: str) -> str:
        if key == "website" and not web_analysis_ran(facts, host):
            return "ohne_webanalyse"
        if key == "fernzugang" and host.betriebsform in ("rechenzentrum", "plattform"):
            return str(host.betriebsform)
        return ""

    def detail_of(key: str) -> str:
        teile = [d for d in dict.fromkeys(details.get(key) or [])]
        # Ein einzelner Zusatz sagt nichts, was der Name nicht schon sagt ("Dateiaustausch (FTP)");
        # ein Port schon ("Anmeldeportal (Port 444)").
        return ", ".join(teile) if len(teile) > 1 or teile == ["SFTP"] or \
            (teile and teile[0].startswith("Port ")) else ""

    return [Role(key=k, evidence=tuple(found[k][:3]), status=status_of(k), variant=variant_of(k),
                 detail=detail_of(k), name=namen.get(k, ""))
            for k in keys[:MAX_ROLES]]


def _redirects_to_customer(fq: FS.FqdnFact, domains: list[str]) -> bool:
    for url in (fq.final_url, getattr(fq, "probe_final_url", None)):
        ziel = SYS.clean_name(urlsplit(url or "").hostname or "")
        if ziel and ziel != SYS.clean_name(fq.name) and SYS.under(ziel, domains):
            return True
    return False


_FTP_SERVER = re.compile(r"ftp", re.I)


def _sftp_of_ftp_server(facts: FS.Facts, s: FS.ServiceFact) -> bool:
    """SSH-Dienst, den ein FTP-Server stellt: Produkt (ProFTPD mod_sftp) oder Passivbanner
    (SSH-2.0-WingFTPServer) nennt FTP."""
    if (s.service or "") != "ssh":
        return False
    if _FTP_SERVER.search(s.product or ""):
        return True
    return any(p.host_ip == s.host_ip and p.port == s.port and _FTP_SERVER.search(p.banner_excerpt or "")
               for p in facts.passive)


def web_analysis_ran(facts: FS.Facts, host: FS.HostFact) -> bool:
    """Lief die aktive Webanalyse an diesem Host (spec/11 T10)?"""
    return any(c.tool == "zap_active" and c.status == "ok" and c.host_ip == host.ip for c in facts.coverage)


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

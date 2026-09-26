# -*- coding: utf-8 -*-
"""Abdeckung je Host und Einschraenkungen dieses Laufs (S6b-1, spec/09 Q9, Q10, Q16, E4, E5).

Ein Modell fuer Kapitel 2.1 (Abdeckung je Host), 2.2 (Einschraenkungen), den Hinweis auf
Seite 3, die Zaehlungen und die Posture. Bis S6b-1 rechneten ``host_coverage`` und
``hosts_ohne_leitwerkzeug`` mit verschiedenen Werkzeugen und Status, und ein Host ohne
einen einzigen offenen Port galt als "Portscan und Tiefenpruefung vollstaendig".

Regeln:

* Abdeckung nur aus nmap (mindestens ein offener Port), testssl und ZAP des Pakets
  (``tables.LEAD_TOOLS``). Ohne offenen Port gibt es kein Messergebnis, nie "vollstaendig".
* Meldet eine Passivquelle juenger als sieben Tage Dienste, ist der Host "vom Pruefstand
  aus nicht erreichbar" (``facts.hosts[].reach``, E4).
* Eine Wurzelursache je Host (nicht erreichbar, kein offener Port, keine IPv6-Route,
  Blockade, von der Scan-Steuerung ausgelassen) unterdrueckt alle Folgezeilen dieses
  Hosts. Die ZAP-Kette (Spider scheitert, danach ``no_zap_context``) ist eine Ursache.
* Eine Zeile je Ursache, mit den betroffenen Pruefungen in Kundensprache; kein
  Werkzeugname im Kundentext.
* Drittanbieter-Adressen (``third_party``) sind kein Host des Kunden: sie stehen in 2.1
  als "Drittanbieter, nicht geprueft" und sonst nirgends.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from reporter.catalog import families as FAM
from reporter.catalog import scope as CS
from reporter.catalog import tables as CT
from reporter.catalog.schema import CatalogOutput
from reporter.facts import schema as FS
from reporter.facts import systems as SYS
from reporter.facts.serialize import sort_key
from reporter.v3 import tables as T
from reporter.v3.findings import aufzaehlung, kurz_label
from reporter.v3.models import Limitation

# Hostweite Wurzelursachen: Kundentext der Einschraenkung und die Pruefungen, die dadurch
# ausfallen. Die Reihenfolge ist die der Tabelle 2.2.
HOST_CAUSES: dict[str, tuple[str, tuple[str, ...]]] = {
    "unreachable_from_scanner": (
        "Vom Prüfstand aus nicht erreichbar",
        ("Portscan und Diensterkennung", "Transportverschlüsselung", "Sicherheits-Header", "Webanalyse")),
    "no_open_ports": (
        "Portscan ohne offenen Port",
        ("Diensterkennung", "Transportverschlüsselung", "Sicherheits-Header", "Webanalyse")),
    # S6b-3 (spec/10 R3): nmap ohne Hostbericht; ob der Host antwortet, ist nicht belegt.
    "no_response": (
        "Ohne Antwort, vom Prüfstand aus nicht erreichbar",
        ("Portscan und Diensterkennung", "Transportverschlüsselung", "Sicherheits-Header", "Webanalyse")),
    "no_ipv6_route": (
        "IPv6-Adresse vom Prüfstand aus nicht erreichbar",
        ("Portscan und Diensterkennung über IPv6", "Transportverschlüsselung über IPv6", "Webanalyse über IPv6")),
    "blocked": (
        "Verbindungen nach dem Portscan abgewiesen",
        ("Transportverschlüsselung", "Sicherheits-Header", "Webanalyse", "Suche nach nicht verlinkten Pfaden")),
    "ai_skip_host": (
        "Von der Scan-Steuerung ausgelassen",
        ("Portscan und Diensterkennung", "Transportverschlüsselung", "Webanalyse")),
    "no_tool_runs": (
        "Zu diesem Host liegt kein Laufprotokoll vor",
        ("Portscan und Diensterkennung", "Transportverschlüsselung", "Webanalyse")),
    "nmap_failed": (
        "Portscan ohne Ergebnis",
        ("Portscan und Diensterkennung", "Transportverschlüsselung", "Webanalyse")),
}

# Werkzeugursachen (normalisierter Code) in Kundensprache. Ein Code ohne Eintrag bekommt
# den Text aus catalog/tables.COVERAGE_REASONS; ohne Text dort ist er keine Einschraenkung.
TOOL_CAUSES: dict[str, str] = {
    "timeout": "Zeitlimit der Prüfung überschritten",
    "no_output": "Prüfung ohne auswertbare Ausgabe",
    "zap_unreachable": "Komponente der Webanalyse war nicht erreichbar",
    "zap_api_error": "Webanalyse im Scanner fehlgeschlagen",
    "does_not_exist": "Webanalyse im Scanner fehlgeschlagen",
    "zap_no_alerts": "Webanalyse ohne Meldungen, Ergebnis nicht belastbar",
    "no_urls_spidered": "Webanalyse ohne erfasste Seiten",
    "no_zap_context": "Webanalyse ohne erfasste Seiten",
    "wordlist_missing": "Wortliste im Scanner fehlte",
    "connect": "Keine Verbindung zum Dienst",
    "unreachable": "Webdienst antwortete nicht",
    "ai_skip": "Von der Scan-Steuerung übersprungen",
    "rohtext_nicht_geladen": "Ausgabe zu groß, nicht ausgewertet",
    "coverage_unknown": "Lauf der Prüfung nicht belegt",
    "no_coverage_rows": "Lauf der Prüfung nicht belegt",
    "whois_unavailable": "Registrierungsdaten der Domain nicht abrufbar",
    "no_enrichment": "Keine Fremdbewertung aus Schwachstellendatenbanken zu den erkannten Versionen",
    "second_target_unlabeled": "Für diese weitere Domain liegen keine eigenen DNS-Abfragen vor",
    "no_dns_facts": "Keine DNS-Angaben zu dieser Domain",
    "no_api_key": "Quelle nicht abgefragt",
    "nmap_no_runstats": "Portscan ohne Bilanz, Ergebnis nicht belastbar",
    "target_skipped": "Ziel vom Portscan übersprungen",
    "host_unreachable": "Host war während des Scans nicht erreichbar",
    "tls_protocols_partial": "Transportverschlüsselung nur über die ausgehandelte Verbindung belegt",
    "tls_ciphers_partial": "Transportverschlüsselung nur über die ausgehandelte Verbindung belegt",
    "tls_protocols_unknown": "Liste der TLS-Protokolle nicht verfügbar",
    "tls_ciphers_unknown": "Liste der Verschlüsselungsverfahren nicht verfügbar",
    "cert_unknown": "Zertifikatsdetails nicht verfügbar",
    "version_unknown": "Version von außen nicht bestimmbar",
    "wordpress_unknown": "Angaben zur WordPress-Installation fehlen",
    "mail_capabilities_unknown": "Maildienst nannte keine Fähigkeiten",
    "insufficient_facts": "Werkzeugdaten reichen für eine Aussage nicht aus",
    "testssl_nicht_getestet": "Einzelne TLS-Schwachstellen nicht geprüft",
    # S6b-3 (spec/10 R4, R7)
    "parked_name": "Nicht eingerichteter Name, keine Web- und Header-Analyse",
    "cert_chain_unknown": "Vertrauenskette des Zertifikats nicht geprüft",
    "mail_tls_unknown": "Ablehnung einer Anmeldung vor STARTTLS nicht belegt",
}

# S6b-3 (spec/10 R1, Entscheidung DC 4): Messung der Sicherheits-Header an einer Antwort, die
# keine Endseite ist; der Statuscode kommt aus dem Fakt.
HEADER_REASONS: dict[str, str] = {
    "headers_redirect_only": "Weiterleitung",
    "headers_error_only": "Fehlerseite",
    "headers_challenge_only": "Sicherheitsabfrage der Plattform",
}
TLS_PARTIAL_CAUSE = "Transportverschlüsselung nur für einen Teil der TLS-Dienste geprüft"
ZAP_PARTIAL_CAUSE = "Aktive Webanalyse nur teilweise"
DISCOVERED_CAUSE = "Gefunden, nicht geprüft"
# Ports mit TLS von Anfang an (implizit), dazu Dienste mit STARTTLS oder Zertifikat im Portscan.
TLS_IMPLICIT_PORTS = frozenset({443, 465, 636, 853, 990, 993, 995, 8443})

# Werkzeuge, deren leeres Ergebnis keine Einschraenkung ist: ein Webauftritt ohne
# erkennbare Technologie oder ohne vorgelagerte Schutzsysteme ist ein Ergebnis.
NO_LIMITATION_TOOLS = frozenset({"webtech", "wafw00f", "whois"})
NO_LIMITATION_CODES = frozenset({"no_tech_signals", "whois_unavailable"})
# S6b-2 (spec/08 Punkt 21): whois lieferte in keinem der 21 Golden-Auftraege Daten (der
# Scanner meldet "ok" mit "no_data"). Solange das Werkzeug nicht repariert ist (Scanner,
# S6c), nimmt der Bericht die Registrierungsdaten ganz heraus: keine Einschraenkungszeile,
# kein Befund zur Laufzeit der Domain.
REPORT_SUPPRESSED_CHECKS = frozenset({"domain_expiring"})
ZAP_TOOLS = ("zap", "zap_spider", "zap_ajax_spider", "zap_active")
WEB_SERVICES = frozenset({"http", "https", "http-alt", "https-alt", "http-proxy", "ssl/http", "ssl/https"})
E5_CAUSE = "SMTP auf Port 25 vom Prüfstand aus nicht prüfbar"
E5_CHECK = "Mailserver auf Port 25 (Verschlüsselung, Anmeldung)"

COV_DOT = {"voll": "gruen", "teil": "gelb", "keine": "rot", "unerreichbar": "rot", "extern": "grau"}


@dataclass
class HostCoverage:
    ip: str
    cov: str                      # voll | teil | keine | unerreichbar | extern
    text: str
    cause: Optional[str] = None   # Wurzelursache (HOST_CAUSES) oder None
    missing: list[str] = field(default_factory=list)   # fehlende Leitpruefungen
    # S6b-3 (spec/10 R3): TLS-Dienste ohne Pruefung der Transportverschluesselung und die
    # Namen mit Inhalt, die die aktive Webanalyse nicht erreicht hat.
    tls_untested: list[int] = field(default_factory=list)
    tls_tested: list[str] = field(default_factory=list)
    zap_note: str = ""
    apps_untested: list[str] = field(default_factory=list)


@dataclass
class Model:
    hosts: dict[str, HostCoverage]
    systems: dict[str, list[str]]           # IP -> Adressen desselben Systems
    third_party: list[str]

    @property
    def counted(self) -> list[HostCoverage]:
        return [h for h in self.hosts.values() if h.cov != "extern"]

    def gaps(self) -> list[str]:
        """Hosts ohne vollstaendige Leitpruefung (Hinweis auf Seite 3), IPv4 vor IPv6."""
        return [h.ip for h in sorted(self.counted, key=lambda h: (":" in h.ip, sort_key(h.ip)))
                if h.cov != "voll"]

    def system_status(self, ips: list[str]) -> str:
        """Abdeckung eines Systems (IPv4 und IPv6 mit gleichem rDNS, spec/09 Q16).

        Voll nur, wenn jede Adresse voll ist; gemischt ist teilweise; sonst gilt der
        Stand der ersten Adresse (keine oder nicht erreichbar)."""
        stati = [self.hosts[ip].cov for ip in ips if ip in self.hosts]
        if not stati:
            return "keine"
        if all(s == "voll" for s in stati):
            return "voll"
        if any(s in ("voll", "teil") for s in stati):
            return "teil"
        return stati[0]

    def system_gaps(self) -> list[list[str]]:
        """Adressen je System ohne vollstaendige Leitpruefung, IPv4-Systeme zuerst.

        Nachtrag 3 (Entscheidung DC 25.09.): Einheit im Hinweis auf Seite 2 und im
        Einleitungssatz von Kapitel 2 ist das System, die Adressen stehen dabei."""
        rows = [ips for ips in self.system_rows() if self.system_status(ips) != "voll"]
        return sorted(rows, key=lambda ips: (":" in ips[0], sort_key(ips[0])))

    def system_rows(self) -> list[list[str]]:
        """Adressen je System, ohne Drittanbieter, in stabiler Reihenfolge."""
        rows: dict[tuple[str, ...], None] = {}
        for ip in self.hosts:
            if self.hosts[ip].cov == "extern":
                continue
            rows.setdefault(tuple(self.systems.get(ip, [ip])), None)
        return [list(r) for r in rows]


# ---------------------------------------------------------------- Werkzeugnamen

def passive_module_name(pv: FS.PassiveFact) -> str:
    """Dienstname aus dem Modul der Passivquelle ("smtp" wird "SMTP"), leer ohne Modul."""
    module = (pv.service or "").lower().replace("-simple-new", "")
    if not module or module == "auto":
        return ""
    return T.PASSIVE_SERVICES.get(module, module.upper())


def check_name(tool: str) -> str:
    return T.TOOL_CHECKS.get(tool, T.TOOL_CHECKS_FALLBACK)


def family_check_name(family: str) -> str:
    return T.FAMILY_CHECKS.get(family, T.TOOL_CHECKS_FALLBACK)


# ---------------------------------------------------------------- Abdeckung je Host

def _code(row: FS.CoverageFact) -> str:
    return CS.normalize_reason(row.reason, row.raw_status) or "insufficient_facts"


def _status_of(code: str) -> str:
    return CT.COVERAGE_REASONS.get(code, ("not_testable", ""))[0]


def _has_web(facts: FS.Facts, ip: str) -> bool:
    if any(s.host_ip == ip and s.state == "open" and ((s.service or "") in WEB_SERVICES or s.port in (80, 443, 8080, 8443))
           for s in facts.services):
        return True
    return any(f.host_ip == ip and f.http_status for f in facts.fqdns)


def tls_service_ports(facts: FS.Facts, ip: str) -> list[int]:
    """Offene Dienste mit TLS: impliziter TLS-Port, STARTTLS oder Zertifikat im Portscan."""
    return sorted({s.port for s in facts.services
                   if s.host_ip == ip and s.state == "open"
                   and (s.tunnel_ssl or s.starttls is True or s.cert is not None or s.port in TLS_IMPLICIT_PORTS)})


def tls_tested(facts: FS.Facts, ip: str) -> dict[int, list[str]]:
    """Port -> Namen, fuer die testssl die Transportverschluesselung geprueft hat."""
    out: dict[int, list[str]] = defaultdict(list)
    for t in facts.tls:
        if t.host_ip == ip and (t.source == "testssl" or t.assigned_from):
            name = t.fqdn or ip
            if t.source == "testssl" and name not in out[t.port]:
                out[t.port].insert(0, name)
            elif name not in out[t.port]:
                out[t.port].append(name)
    return dict(out)


def tls_untested_ports(facts: FS.Facts) -> dict[str, list[int]]:
    """Je Adresse die TLS-Dienste, deren Transportverschluesselung nicht geprueft ist
    (spec/10 R3). Grundlage fuer Abdeckung, Posture und Positivbefunde."""
    out: dict[str, list[int]] = {}
    for h in facts.hosts:
        tested = tls_tested(facts, h.ip)
        if not tested:
            continue
        offen = [p for p in tls_service_ports(facts, h.ip) if p not in tested]
        if offen:
            out[h.ip] = offen
    return out


def _zap_active_state(facts: FS.Facts, ip: str, rows: list[FS.CoverageFact]) -> tuple[str, list[str]]:
    """(Einschraenkung, ungepruefte Anwendungen) der aktiven Webanalyse (spec/10 R3).

    Vollstaendig nur, wenn das Ziel ein Name mit Seiteninhalt ist und die passive Analyse
    Meldungen lieferte. Ziel ohne Inhalt (403-Seite, Sicherheitsabfrage) oder ZAP ohne jede
    Meldung ergibt "teilweise".
    """
    za = [c for c in rows if c.tool == "zap_active" and c.status in ("ok", "empty")]
    if not za:
        return "", []
    notes: list[str] = []
    target = (urlsplit(za[0].target).hostname or "").lower() if za[0].target else ""
    names = [f for f in facts.fqdns if f.host_ip == ip and not f.wildcard]
    ziel = next((f for f in names if f.name.lower() == target), None)
    apps = sorted({f.name for f in names if f.real_content is True and f.name.lower() != target}, key=sort_key)
    if target and (ziel is None or ziel.real_content is not True):
        status = f" (Status {ziel.http_status})" if ziel is not None and ziel.http_status else ""
        notes.append(f"aktive Webanalyse nur an {target} ohne Seiteninhalt{status}")
    else:
        apps = []
    if any(c.tool == "zap" and c.status == "empty" and _code(c) == "zap_no_alerts" for c in rows):
        notes.append("Webanalyse ohne Meldungen, Ergebnis nicht belastbar")
    return "; ".join(notes), apps


def _datum(ts: Optional[str]) -> str:
    if not ts:
        return "unbekannt"
    y, m, d = ts[:10].split("-")
    return f"{d}.{m}.{y}"


# Leitpruefungen im Satz ("Portscan, Transportverschluesselung und aktive Webanalyse
# vollstaendig"); die Tabellennamen aus TOOL_CHECKS sind Ueberschriften.
LEAD_IN_SENTENCE: dict[str, str] = {
    "testssl": "Transportverschlüsselung",
    "zap_active": "aktive Webanalyse",
    "zap": "Webanalyse",
}


def _lead_checks(package: str) -> list[tuple[str, str]]:
    """(Werkzeug, Pruefungsname im Satz) der Leitpruefungen ausser nmap."""
    return [(t, LEAD_IN_SENTENCE.get(t, check_name(t))) for t in T.lead_tools(package) if t != "nmap"]


def host_coverage(facts: FS.Facts, host: FS.HostFact) -> HostCoverage:
    ip = host.ip
    if host.third_party is not None:
        return HostCoverage(ip=ip, cov="extern", text="Drittanbieter, nicht geprüft", cause="third_party")
    rows = [c for c in facts.coverage if c.host_ip == ip]
    reach = host.reach.status if host.reach else None
    if reach == "unreachable_from_scanner":
        ports = ", ".join(str(p) for p in host.reach.passive_ports)
        return HostCoverage(ip=ip, cov="unerreichbar", cause=reach, text=(
            "Vom Prüfstand aus nicht erreichbar: der Portscan fand keinen offenen Port, eine "
            f"Passivquelle meldet dort Dienste (Port {ports}, gesehen am "
            f"{_datum(host.reach.passive_seen_at)})."))
    if reach == "no_ipv6_route":
        return HostCoverage(ip=ip, cov="keine", cause=reach,
                            text="Über IPv6 vom Prüfstand aus nicht erreichbar; nicht geprüft.")
    if reach == "no_open_ports":
        return HostCoverage(ip=ip, cov="keine", cause=reach,
                            text="Der Portscan fand keinen offenen Port; weitere Prüfungen entfielen.")
    if reach == "no_response":
        return HostCoverage(ip=ip, cov="keine", cause=reach,
                            text="Ohne Antwort, vom Prüfstand aus nicht erreichbar; weitere Prüfungen entfielen.")
    nmap = [c for c in rows if c.tool == "nmap"]
    if not nmap:
        skipped = any(d.source == "ai_host_skip" and d.host_ip == ip for d in facts.decisions)
        if skipped:
            return HostCoverage(ip=ip, cov="keine", cause="ai_skip_host",
                                text="Von der Scan-Steuerung ausgelassen; nicht geprüft.")
        return HostCoverage(ip=ip, cov="keine", cause="no_tool_runs",
                            text="Zu diesem Host liegt kein Laufprotokoll vor; welche Prüfungen stattgefunden haben, ist nicht belegt.")
    if not any(c.status in ("ok", "empty") for c in nmap):
        return HostCoverage(ip=ip, cov="keine", cause="nmap_failed", text="Portscan ohne Ergebnis; nicht geprüft.")
    if host.blocked.detected:
        return HostCoverage(ip=ip, cov="teil", cause="blocked", missing=[n for _, n in _lead_checks(facts.scan.package)],
                            text="Portscan vollständig; danach hat der Host weitere Verbindungen abgewiesen, "
                                 "Transportverschlüsselung und Webanalyse waren nicht möglich.")
    done: list[str] = ["Portscan"]
    missing: list[str] = []
    web = _has_web(facts, ip)
    tls = any(s.host_ip == ip and s.state == "open" and (s.tunnel_ssl or s.port == 443) for s in facts.services)
    for tool, name in _lead_checks(facts.scan.package):
        je = [c for c in rows if c.tool == tool]
        if any(c.status in ("ok", "empty") for c in je):
            done.append(name)
            continue
        zutreffend = (tool == "testssl" and tls) or (tool.startswith("zap") and web)
        if not je:
            if zutreffend:
                missing.append(name)
            continue
        codes = {_code(c) for c in je}
        # Ein Webdienst ist da, aber ZAP hatte keinen Kontext: das ist eine Folge des
        # gescheiterten Spiders, kein "entfaellt" (castenow www, ZAP nicht erreichbar).
        ohne_kontext = tool.startswith("zap") and web and bool(codes & {"no_zap_context", "no_web"})
        if not ohne_kontext and all(_status_of(code) in ("ok", "not_applicable") for code in codes):
            continue
        missing.append(name)
    # S6b-3 (spec/10 R3): "vollstaendig" nur fuer das, was tatsaechlich geprueft ist.
    teilweise: list[str] = []
    tested = tls_tested(facts, ip)
    offen = [p for p in tls_service_ports(facts, ip) if p not in tested] if tested else []
    tls_name = LEAD_IN_SENTENCE["testssl"]
    if offen and tls_name in done:
        done.remove(tls_name)
        geprueft = ", ".join(f"{p} (SNI {', '.join(n for n in tested[p][:2])})" for p in sorted(tested))
        teilweise.append(f"Transportverschlüsselung nur für {geprueft} geprüft, nicht für "
                         f"{'Port' if len(offen) == 1 else 'Port'} {', '.join(str(p) for p in offen)}")
    zap_note, apps = _zap_active_state(facts, ip, rows)
    zap_name = LEAD_IN_SENTENCE["zap_active"]
    if zap_note and zap_name in done:
        done.remove(zap_name)
        teilweise.append(zap_note + (f"; Anwendung {aufzaehlung(apps)} nicht aktiv geprüft" if apps else ""))
    teile = ([f"{aufzaehlung(done)} vollständig"] if done else []) + teilweise
    if missing:
        teile.append(f"nicht geprüft: {aufzaehlung(missing)}")
    extra = dict(tls_untested=offen, tls_tested=[f"{p}" for p in sorted(tested)], zap_note=zap_note,
                 apps_untested=apps)
    if missing or teilweise:
        return HostCoverage(ip=ip, cov="teil", missing=missing, text="; ".join(teile) + ".", **extra)
    if len(done) == 1:
        return HostCoverage(ip=ip, cov="voll",
                            text="Portscan vollständig; ohne TLS- und Webdienst entfielen die weiteren Prüfungen.",
                            **extra)
    return HostCoverage(ip=ip, cov="voll", text=f"{aufzaehlung(done)} vollständig.", **extra)


def build_model(facts: FS.Facts) -> Model:
    hosts = {h.ip: host_coverage(facts, h) for h in facts.hosts}
    return Model(hosts=hosts, systems=SYS.system_of(h for h in facts.hosts if h.third_party is None),
                 third_party=[h.ip for h in facts.hosts if h.third_party is not None])


def names_checked(facts: FS.Facts) -> int:
    """Gepruefte Namen: Hostnamen im Inventar auf eigenen Adressen (wie ``Counts.fqdns_total``)."""
    eigene = {h.ip for h in facts.hosts if h.third_party is None}
    return len({f.name.lower() for f in facts.fqdns if not f.wildcard and f.host_ip in eigene})


def names_found(facts: FS.Facts) -> int:
    """Ermittelte Namen (spec/10 R5): geprueft plus die Namen der Hostsuche mit Adresse, die
    nicht ins Inventar kamen. Altnamen aus crt.sh zaehlen nicht, sie haben keine Adresse."""
    return names_checked(facts) + len({d.fqdn.lower() for t in facts.targets for d in t.discovered if d.ips})


# ---------------------------------------------------------------- Einschraenkungen

@dataclass
class _Row:
    what: str
    checks: set[str] = field(default_factory=set)
    orte: dict[str, str] = field(default_factory=dict)
    zusatz: list[str] = field(default_factory=list)
    code: str = ""
    refs: set[str] = field(default_factory=set)
    subjects: set[str] = field(default_factory=set)

    def ort(self, key: str, label: str) -> None:
        vorhanden = self.orte.get(key)
        if vorhanden is None or len(label) > len(vorhanden):
            self.orte[key] = label
        self.subjects.add(key)


def _host_label(facts: FS.Facts, ip: str) -> str:
    host = next((h for h in facts.hosts if h.ip == ip), None)
    # S6b-2: ein Wildcard-Eintrag ist kein Hostname (spec/09 Teil 2 DB).
    names = sorted((n for n in host.fqdns if not n.startswith("*.")), key=sort_key) if host else []
    return kurz_label(f"{ip} ({', '.join(names)})") if names else ip


def limitations(facts: FS.Facts, output: CatalogOutput, model: Model,
                dkim_text=None) -> list[Limitation]:
    """Eine Zeile je Ursache, mit Pruefungsnamen und Betroffenen (spec/09 Q10)."""
    rows: dict[str, _Row] = {}

    def row(what: str, code: str = "") -> _Row:
        r = rows.setdefault(what, _Row(what=what, code=code))
        r.code = r.code or code
        return r

    host_cause = {ip: h.cause for ip, h in model.hosts.items() if h.cause}
    # 1 Hostweite Ursachen
    for ip, h in sorted(model.hosts.items(), key=lambda kv: sort_key(kv[0])):
        if h.cause in (None, "third_party"):
            continue
        what, checks = HOST_CAUSES[h.cause]
        r = row(what, h.cause)
        r.checks.update(checks)
        r.ort(ip, _host_label(facts, ip))
    unerreichbar = [h for h in facts.hosts if h.reach and h.reach.status == "unreachable_from_scanner"
                    and h.third_party is None]
    if unerreichbar:
        seen = sorted({h.reach.passive_seen_at[:10] for h in unerreichbar if h.reach.passive_seen_at})
        spanne = _datum(seen[0]) if len(seen) == 1 else f"{_datum(seen[0])} bis {_datum(seen[-1])}"
        row(HOST_CAUSES["unreachable_from_scanner"][0]).zusatz.append(
            "Eine Passivquelle meldet dort Dienste (gesehen " + ("am " if len(seen) == 1 else "vom ")
            + spanne + "); der Portscan fand keinen offenen Port. Ergebnisse zu diesen Hosts liegen "
            "deshalb nicht vor.")
    ipv6 = [h for h in facts.hosts if h.reach and h.reach.status == "no_ipv6_route"]
    for h in ipv6:
        partner = [ip for ip in model.systems.get(h.ip, []) if ip != h.ip]
        if partner:
            row(HOST_CAUSES["no_ipv6_route"][0]).zusatz.append(
                f"Geprüft wurde die IPv4-Adresse desselben Systems ({', '.join(partner)}).")

    # 2 Werkzeugzeilen ohne hostweite Ursache
    spider_cause: dict[str, str] = {}
    for c in facts.coverage:
        if c.tool in ("zap_spider", "zap_ajax_spider") and c.host_ip and c.status in ("failed", "blocked"):
            spider_cause[c.host_ip] = _code(c)
    # S6b-3 (spec/10 R4): header_check ohne Antwort ist keine Einschraenkung, wenn eine
    # andere Quelle die Endseite geliefert hat (castenow bitwarden ueber testssl).
    ersetzt = {(h.host_ip, h.fqdn) for h in facts.http
               if h.header_eval is not None and h.header_eval.evaluated is not None}
    for c in facts.coverage:
        if c.status not in ("failed", "blocked", "empty", "skipped"):
            continue
        if c.tool in T.OUT_OF_PRODUCT_TOOLS or c.tool in NO_LIMITATION_TOOLS or c.tool == "nmap":
            continue
        if c.host_ip and host_cause.get(c.host_ip):
            continue
        if c.tool == "header_check" and (c.host_ip, c.fqdn) in ersetzt:
            continue
        if c.tool in ZAP_TOOLS and c.host_ip and model.hosts.get(c.host_ip) is not None \
                and model.hosts[c.host_ip].zap_note and _code(c) == "zap_no_alerts":
            # Steht als "aktive Webanalyse nur teilweise" (Abschnitt 5); eine Ursache, eine Zeile.
            continue
        code = _code(c)
        if code in NO_LIMITATION_CODES:
            continue
        erzwungen = False
        if c.tool in ZAP_TOOLS and code in ("no_zap_context", "no_urls_spidered", "no_web") \
                and c.host_ip and _has_web(facts, c.host_ip):
            # Webdienst vorhanden, ZAP ohne Kontext: Folge des Spiders (eine Ursache).
            code = spider_cause.get(c.host_ip, "no_zap_context")
            erzwungen = True
        status, text = CT.COVERAGE_REASONS.get(code, ("not_testable", ""))
        if status in ("ok", "not_applicable") and not erzwungen:
            continue
        what = TOOL_CAUSES.get(code) or text.rstrip(".") or "Prüfung ohne auswertbares Ergebnis"
        r = row(what, code)
        r.checks.add(check_name(c.tool))
        key = c.host_ip or c.fqdn or c.domain or "scanweit"
        r.ort(key, (_host_label(facts, c.host_ip) if c.host_ip else (c.fqdn or c.domain or "scanweit")))

    # 3 Pruefungen ohne Aussage (Katalog). S6b-3 (spec/10 R4): eine "nicht pruefbar"-Zeile
    # entfaellt, wenn dasselbe Subjekt fuer dieselbe Faktenfamilie gemessen ist.
    checks = {ci.id: ci for ci in output.checks}
    gemessen = FAM.measured(output.results)
    abgleich = any(sw.vulnerabilities for sw in facts.software)
    http_by = {(h.host_ip, h.fqdn): h for h in facts.http}
    header_rows: dict[str, dict] = {}
    for res in output.results:
        if res.status != "not_testable" or not res.reason_code:
            continue
        if res.check_id in REPORT_SUPPRESSED_CHECKS:
            continue
        if FAM.suppressed(res, gemessen):
            continue
        code = res.reason_code.split(":", 1)[-1]
        status, text = CT.COVERAGE_REASONS.get(code, ("not_testable", ""))
        if status != "not_testable" or not text:
            continue
        ip = str(res.vars.get("host_ip") or "")
        if ip and host_cause.get(ip):
            continue
        if code in HOST_CAUSES:
            continue
        if code == "no_enrichment" and abgleich:
            # S6b-3 (spec/10 R14): nur ohne jeden Abgleich; wpscan hat Kennungen geliefert.
            continue
        info = checks.get(res.check_id)
        name = family_check_name(info.family if info else res.family)
        key = ip or str(res.vars.get("domain") or "") or res.group_key
        if code in HEADER_REASONS:
            fq = str(res.vars.get("fqdn_names") and res.group_label or res.group_label)
            # Gruppe "name@adresse": exakt der Name, nicht als Teilstring (ftp.bergersysteme.com
            # enthaelt bergersysteme.com).
            name = res.group_key.split("@", 1)[0]
            hf = http_by.get((ip, name)) or next(
                (h for (hip, hfq), h in http_by.items() if hfq == name and (not ip or hip == ip)), None)
            first = hf.header_eval.first if hf is not None and hf.header_eval is not None else None
            entry = header_rows.setdefault(code, {"codes": set(), "orte": {}, "refs": set(), "checks": set()})
            if first is not None and first.status_code:
                entry["codes"].add(first.status_code)
            label = hf.fqdn if hf is not None and hf.fqdn else fq
            if first is not None:
                ziel = ""
                if first.location:
                    loc = urlsplit(first.location)
                    ziel = (f" auf {loc.path or '/'}" if (loc.hostname or "") == (hf.fqdn or "")
                            else f" auf {loc.hostname}")
                status_txt = str(first.status_code) if first.status_code else HEADER_REASONS[code]
                label = f"{label} ({status_txt}{ziel})"
            entry["orte"][res.group_key] = label
            entry["refs"].add(f"{res.check_id}|{res.group_key}")
            entry["checks"].add(name)
            continue
        if code == "dkim_selector_unknown" and dkim_text is not None:
            what = dkim_text(res)
        else:
            what = TOOL_CAUSES.get(code) or text.rstrip(".")
        r = row(what, code)
        r.checks.add(name)
        r.refs.add(f"{res.check_id}|{res.group_key}")
        r.ort(key, res.group_label)
    for code, entry in sorted(header_rows.items()):
        codes = ", ".join(str(c) for c in sorted(entry["codes"]))
        art = HEADER_REASONS[code]
        what = (f"Sicherheits-Header nur an einer {art}" + (f" ({codes})" if codes else "")
                + " gemessen, Endseite nicht bewertet")
        r = row(what, code)
        r.checks.update(entry["checks"])
        r.refs.update(entry["refs"])
        for key, label in entry["orte"].items():
            r.ort(key, label)

    # 4 E5: Port 25 laut Passivquelle, vom Portscan nicht gesehen. S6b-3 (spec/10 R10): je
    # Adresse, unabhaengig von anderen Ursachen (der Portscan lief vor einer Sperre); nur
    # Drittanbieter und Adressen, deren eigene Zeile die Passivports nennt (E4, IPv6), nicht.
    ohne_e5 = {ip for ip, c in host_cause.items() if c in ("third_party", "unreachable_from_scanner", "no_ipv6_route")}
    e5 = [p for p in facts.passive if p.source == "shodan" and p.port == 25 and p.verified is False
          and p.host_ip and p.host_ip not in ohne_e5]
    if e5:
        r = row(E5_CAUSE, "e5")
        r.checks.add(E5_CHECK)
        for p in e5:
            r.ort(p.host_ip, _host_label(facts, p.host_ip))
        seen = sorted({(p.seen_at or "")[:10] for p in e5 if p.seen_at})
        dienst = sorted({name for p in e5 if (name := passive_module_name(p))})
        r.zusatz.append(
            f"Laut Passivquelle nimmt dort der Dienst {aufzaehlung(dienst) or 'auf Port 25'} Verbindungen an"
            + (f" (gesehen am {_datum(seen[-1])})" if seen else "")
            + "; vom Prüfstand aus ist Port 25 nicht erreichbar, der Mailserver auf diesem Port ist "
              "deshalb nicht geprüft.")

    # 5 Teilpruefungen (spec/10 R3): TLS-Dienste ohne Pruefung, aktive Webanalyse ohne Inhalt.
    for ip, h in sorted(model.hosts.items(), key=lambda kv: sort_key(kv[0])):
        if h.cause:
            continue
        if h.tls_untested:
            r = row(TLS_PARTIAL_CAUSE, "tls_partial")
            r.checks.add("Transportverschlüsselung")
            r.ort(ip, f"{ip} (Port {', '.join(str(p) for p in h.tls_untested)})")
        if h.zap_note:
            r = row(ZAP_PARTIAL_CAUSE, "zap_partial")
            r.checks.add("Aktive Webanalyse")
            label = _host_label(facts, ip)
            if h.apps_untested:
                label = f"{label}: Anwendung {aufzaehlung(h.apps_untested)} nicht aktiv geprüft"
            r.ort(ip, label)
    if any(h.tls_untested for h in model.hosts.values() if not h.cause):
        row(TLS_PARTIAL_CAUSE).zusatz.append(
            "Geprüft wurde jeweils der Webdienst auf Port 443; die übrigen TLS-Dienste sind nur per "
            "Portscan erfasst, ihre Verschlüsselung und ihr Zertifikat sind nicht bewertet.")

    # 6 Gefunden, nicht geprueft (spec/10 R5, bis S6c die Hostsuche repariert)
    gefunden = [(t.domain, d) for t in facts.targets for d in t.discovered]
    if gefunden:
        r = row(DISCOVERED_CAUSE, "discovered")
        r.checks.add("Ermittlung der Hostnamen")
        for _dom, d in gefunden:
            adressen = ", ".join(d.ips[:2]) + (" und weitere" if len(d.ips) > 2 else "")
            zusatz = f"Drittanbieter {d.third_party}, " if d.third_party else ""
            r.ort(d.fqdn, f"{d.fqdn} ({zusatz}{adressen})" if adressen or zusatz else d.fqdn)
        r.zusatz.append("Die Hostsuche hat diese Namen gefunden, sie sind aber nicht in die Prüfung "
                        "übernommen worden; Ergebnisse zu ihnen liegen nicht vor.")

    out: list[Limitation] = []
    order = [v[0] for v in HOST_CAUSES.values()] + [E5_CAUSE]
    for what in sorted(rows, key=lambda w: (order.index(w) if w in order else len(order), w)):
        r = rows[what]
        where = sorted(r.orte.values(), key=sort_key)
        # S6b-3 (spec/10 R6): sechs Namen und "und n weitere", Zahl und Namen aus derselben Liste.
        shown = ", ".join(where[:6]) + (f" und {len(where) - 6} weitere" if len(where) > 6 else "")
        detail = f"Betroffen: {shown}." if shown else ""
        if r.zusatz:
            detail = (detail + " " + " ".join(r.zusatz)).strip()
        out.append(Limitation(what=r.what.rstrip("."), checks=sorted(r.checks), detail=detail,
                              code=r.code, refs=sorted(r.refs), subjects=sorted(r.subjects, key=sort_key)))
    return out


# ---------------------------------------------------------------- Pruefumfang je Domain

def domain_scope(facts: FS.Facts) -> list[tuple[str, str]]:
    """Was je Zieldomain geprueft wurde (spec/09 Q16). junkerwerk.hu hatte nur DNS."""
    out: list[tuple[str, str]] = []
    domains = list(facts.scan.domains) or [facts.scan.domain]
    for dom in domains:
        names = [f for f in facts.fqdns if not f.wildcard and SYS.under(f.name, [dom])
                 and next((h for h in facts.hosts if h.ip == f.host_ip and h.third_party is None), None)]
        dns = any(d.domain == dom for d in facts.dns)
        if names:
            n = len({f.name for f in names})
            out.append((dom, f"Hostermittlung, Portscan und Tiefenprüfung ({n} "
                             f"{'Hostname' if n == 1 else 'Hostnamen'}), DNS- und E-Mail-Einträge"))
        elif dns:
            out.append((dom, "nur DNS- und E-Mail-Einträge; für diese Domain wurden keine eigenen Hosts ermittelt"))
        else:
            out.append((dom, "keine eigenen Ergebnisse"))
    return out


__all__ = ["HostCoverage", "Model", "COV_DOT", "HOST_CAUSES", "TOOL_CAUSES", "E5_CAUSE", "E5_CHECK",
           "check_name", "family_check_name", "host_coverage", "build_model", "limitations", "domain_scope",
           "tls_service_ports", "tls_tested", "tls_untested_ports", "HEADER_REASONS", "DISCOVERED_CAUSE"]

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

import re
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
    # S6b-4 (spec/11 T7): AAAA-Eintrag laut DNS, vom Scanner nicht ins Inventar uebernommen.
    "ipv6_not_scanned": (
        "IPv6-Adresse vom Prüfstand aus nicht geprüft",
        ("Portscan und Diensterkennung über IPv6", "Transportverschlüsselung über IPv6", "Webanalyse über IPv6")),
    # S6b-4n (spec/11 N5, Entscheidung DC 27.09.): weiterer A-Eintrag derselben Namen, vom Scanner
    # nicht ins Inventar uebernommen; Messungen am Namen koennen dort gelaufen sein.
    "dns_not_scanned": (
        "Weitere Adresse laut DNS, nicht geprüft",
        ("Portscan und Diensterkennung",)),
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
# S6b-4 (spec/11 T7, T8, T13): Ursachen dieser Session.
ROTATION_CAUSE = "Messung an einer anderen Adresse desselben Namens (DNS-Rotation)"
PATH_UNRELIABLE_CAUSE = ("Suche nach nicht verlinkten Pfaden nur gegen Weiterleitung, Fehlerseite oder "
                         "Sicherheitsabfrage, nicht belastbar")
PATH_ABORTED_CAUSE = "Suche nach nicht verlinkten Pfaden abgebrochen"
# S6b-4n (spec/11 N13): die Suche war belastbar, ein Werkzeug brach aber ab, lief ohne Statistik
# oder eine Anwendung desselben Hosts wurde nie angefragt (dortmund-beach, castenow bitwarden,
# junkerwerk .29, heuel ose).
PATH_PARTIAL_CAUSE = "Suche nach nicht verlinkten Pfaden nur teilweise"
ZAP_NO_ALERTS_CAUSE = "Webanalyse ohne Meldungen, Ergebnis nicht belastbar"
# S6b-4n (spec/11 N3): an der Endseite belegen nur einzelne Meldungen der Webanalyse einzelne
# Header; die uebrigen sind dort nicht gemessen (heuel ose, castenow mail und mail2).
HEADER_PARTIAL_CAUSE = "Sicherheits-Header an der Endseite nur einzeln belegt"
# Kurzlauf der aktiven Webanalyse (junkerwerk .28 und castenow .4: rund 10 Sekunden).
ZAP_SHORT_MS = 60_000
WEBPORT_CAUSE = "Webdienst auf weiterem Port ohne Web- und Header-Analyse"
PATH_TOOLS = frozenset({"feroxbuster", "ffuf_sensitive"})
PATH_FAMILIES = frozenset({"sensitive_path_exposed", "directory_listing"})
STEUERUNG_CODES = frozenset({"zap_no_alerts", "passive_only_policy", "no_zap_context", "no_urls_spidered"})
PATH_ABORT_TEXT = {"timeout": "Zeitlimit", "connect": "keine Verbindung", "waf_body_marker": "Abwehrmerkmal der Seite",
                   "blocked": "Abwehrmerkmal der Seite"}
PATH_TOOL_NAMES = {"feroxbuster": "Verzeichnissuche", "ffuf_sensitive": "Suche nach sensiblen Dateien"}


def path_abort_text(reason: str) -> str:
    """Abbruchgrund der Pfadsuche in Kundensprache ("timeout_after_180s" -> "Zeitlimit")."""
    grund = PATH_ABORT_TEXT.get(reason or "", "")
    if not grund and (reason or "").startswith("timeout"):
        grund = "Zeitlimit"
    return grund


def steuerung_text(regel: str) -> str:
    """Ursache aus dem skipReason der Scan-Steuerung (spec/11 T13)."""
    return ("Von der Scan-Steuerung übersprungen: aktive Webanalyse"
            + (f", Regel {regel}" if regel else ""))
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
    # S6b-4n (spec/11 N13): Webanalyse ohne jede Meldung, mit Ursache ("aktive Pruefung
    # abgeschlossen, ohne Meldungen").
    zap_no_alerts: str = ""


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


def tls_sni(facts: FS.Facts, ip: str) -> dict[int, list[str]]:
    """Port -> Namen, die testssl selbst geprueft hat (spec/11 T13); ohne die zugeordneten VHosts."""
    out: dict[int, list[str]] = defaultdict(list)
    for t in facts.tls:
        if t.host_ip == ip and t.source == "testssl" and t.fqdn and t.fqdn not in out[t.port]:
            out[t.port].append(t.fqdn)
    return dict(out)


def measured_elsewhere(facts: FS.Facts, ip: str) -> dict[str, list[str]]:
    """Adressen ausserhalb des Systems, an denen testssl ("tls") und httpx ("http") fuer die Namen
    dieses Hosts gemessen haben (spec/11 T7, DNS-Rotation)."""
    system = set(SYS.system_of(facts.hosts).get(ip, [ip]))
    tls = sorted({t.measured_ip for t in facts.tls if t.host_ip == ip and t.measured_ip
                  and t.measured_ip not in system}, key=sort_key)
    http = sorted({h.measured_ip for h in facts.http if h.host_ip == ip and h.measured_ip
                   and h.measured_ip not in system and h.measured_ip not in tls}, key=sort_key)
    out: dict[str, list[str]] = {}
    if tls:
        out["tls"] = tls
    if http:
        out["http"] = http
    return out


_RULE_RE = re.compile(r"rule:([\w.-]+)")


def scan_control_skip(facts: FS.Facts, ip: str, rows: list[FS.CoverageFact]) -> Optional[str]:
    """Regel der Scan-Steuerung, die die aktive Webanalyse ausgelassen hat (spec/11 T13).

    None: nicht ausgelassen; "": ausgelassen ohne benannte Regel."""
    za = [c for c in rows if c.tool == "zap_active" and c.status == "skipped"
          and _code(c) in ("passive_only_policy", "ai_skip")]
    if not za:
        return None
    for d in facts.decisions:
        if d.host_ip == ip and d.source in ("ai_phase2_config", "ai_phase2_config_rule_based"):
            m = _RULE_RE.search(str((d.payload or {}).get("reasoning") or ""))
            if m:
                return m.group(1)
    return ""


_REGEL_WORTE = frozenset({"hosted", "cms", "rule", "regel", "site", "passive", "only"})


def steuerung_grund(facts: FS.Facts, ip: str, regel: Optional[str]) -> str:
    """Grund einer Regel der Scan-Steuerung, wenn sie aus einem Weiterleitungsziel stammt (spec/11 N4).

    bergersysteme 92.205.224.174: die Regel hosted-cms-webflow griff auf dem Plesk-Server, weil
    bergersysteme.com auf www (Webflow, 198.202.211.1) weiterleitet. Der Bericht nennt das."""
    if not regel:
        return ""
    worte = [w for w in re.split(r"[-_.]", regel.lower()) if w and w not in _REGEL_WORTE]
    if not worte:
        return ""
    for h in facts.http:
        he = h.header_eval
        if h.host_ip != ip or he is None or he.first is None or not he.first.location:
            continue
        ziel = (urlsplit(he.first.location).hostname or "").lower()
        if not ziel or ziel == (h.fqdn or "").lower():
            continue
        ziel_ips = {f.host_ip for f in facts.fqdns if f.name.lower() == ziel} - {ip}
        if not ziel_ips:
            continue
        for sw in facts.software:
            if sw.host_ip in ziel_ips and any(w in sw.product.lower() for w in worte):
                return f"wegen Weiterleitung auf die {sw.product}-Seite {ziel}"
        for host in facts.hosts:
            op = (host.shared.operator or "") if host.shared else ""
            if host.ip in ziel_ips and any(w in op.lower() for w in worte):
                name = next(w for w in worte if w in op.lower())
                return f"wegen Weiterleitung auf die {name.capitalize()}-Seite {ziel}"
    return ""


def _zap_active_state(facts: FS.Facts, ip: str, rows: list[FS.CoverageFact]) -> tuple[str, list[str]]:
    """(Einschraenkung, ungepruefte Anwendungen) der aktiven Webanalyse (spec/10 R3).

    Vollstaendig nur, wenn das Ziel ein Name mit Seiteninhalt ist. Ziel ohne Inhalt (403-Seite,
    Sicherheitsabfrage), weitere Namen mit Inhalt ohne aktive Pruefung oder ein Lauf unter einer
    Minute ergeben "teilweise". S6b-4n (spec/11 N13): ZAP ohne jede Meldung steht als eigene Zeile
    mit Ursache (``zap_no_alerts_note``), nicht mehr als "nur teilweise".
    """
    za = [c for c in rows if c.tool == "zap_active" and c.status in ("ok", "empty")]
    if not za:
        return "", []
    notes: list[str] = []
    target = (urlsplit(za[0].target).hostname or "").lower() if za[0].target else ""
    names = [f for f in facts.fqdns if f.host_ip == ip and not f.wildcard]
    ziel = next((f for f in names if f.name.lower() == target), None)
    apps = sorted({f.name for f in names if f.real_content is True and f.name.lower() != target}, key=sort_key)
    # S6b-4 (spec/11 R3-Rest): das Ziel ist eine reine Weiterleitung (castenow umfrage: 301 auf www);
    # der Inhalt dahinter liegt auf einem anderen Host und ist nicht dieses Ziel.
    ziel_http = next((h for h in facts.http if h.host_ip == ip and (h.fqdn or "").lower() == target), None)
    he = ziel_http.header_eval if ziel_http is not None else None
    weiterleitung = he is not None and he.basis == "redirect" and he.evaluated is None \
        and he.first is not None and he.first.location \
        and (urlsplit(he.first.location).hostname or target).lower() != target
    if target and weiterleitung:
        status = f" (Status {he.first.status_code})" if he.first.status_code else ""
        notes.append(f"aktive Webanalyse nur an {target}, einer Weiterleitung auf einen anderen Namen{status}")
    elif target and (ziel is None or ziel.real_content is not True):
        # S6b-4n (spec/11 N13): "ohne Seiteninhalt (Status 200)" war unverständlich (junkerwerk
        # cloud, IIS-Standardseite); die Art der Antwort steht jetzt da.
        code = ziel.http_status if ziel is not None else None
        waf = bool(ziel is not None and ziel.waf is not None and ziel.waf.detected)
        if code == 429 or (waf and code and code >= 400):
            art, zusatz = "einer Sicherheitsabfrage", ""
        elif code and code >= 400:
            art, zusatz = "einer Fehlerseite", ""
        else:
            art = "einer Seite ohne eigenen Inhalt"
            zusatz = f"Titel „{ziel.title}“, " if ziel is not None and ziel.title else ""
        status = f" ({zusatz}Status {code})" if code else ""
        notes.append(f"aktive Webanalyse nur an {target}, {art}{status}")
    elif target and apps:
        # S6b-4n (spec/11 N13): nur einer von mehreren Namen mit Inhalt (junkerwerk .28: outlook,
        # nicht autodiscover; castenow .4: mail2, nicht mail und owa) ist nicht vollstaendig.
        notes.append(f"aktive Webanalyse nur an {target}")
    dauer = za[0].duration_ms
    if target and dauer is not None and 0 < dauer < ZAP_SHORT_MS:
        notes.append(f"aktive Webanalyse als Kurzlauf ({max(1, round(dauer / 1000))} Sekunden)")
    return "; ".join(notes), apps


def zap_no_alerts_note(facts: FS.Facts, ip: str, rows: list[FS.CoverageFact]) -> str:
    """Webanalyse ohne jede Meldung (Issue #13), mit dem Stand der aktiven Pruefung (spec/11 N13).

    huendgen: die passive Analyse lieferte keine Meldung, die aktive Pruefung lief bis zum Ende
    ("status: complete") und fand nichts; das steht jetzt da, statt "nur teilweise"."""
    if not any(c.tool == "zap" and c.status == "empty" and _code(c) == "zap_no_alerts" for c in rows):
        return ""
    za = [c for c in rows if c.tool == "zap_active" and c.status in ("ok", "empty")]
    aktiv_meldungen = any(a.run == "active" for h in facts.http if h.host_ip == ip for a in h.alerts)
    if za and (za[0].run_status or "").lower() == "complete" and not aktiv_meldungen:
        return "passive Webanalyse ohne Meldungen, aktive Prüfung abgeschlossen und ohne Meldungen"
    return "passive Webanalyse ohne Meldungen"


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
        # S6b-4 (spec/11 T11): ohne Hostbericht von nmap heisst es "ohne Antwort", auch wenn die
        # Passivquelle Dienste meldet (bergersysteme 62.217.52.162, .166, .171).
        portscan = ("der Portscan erhielt keine Antwort" if host.nmap_host_report is False
                    else "der Portscan fand keinen offenen Port")
        return HostCoverage(ip=ip, cov="unerreichbar", cause=reach, text=(
            f"Vom Prüfstand aus nicht erreichbar: {portscan}, eine "
            f"Passivquelle meldet dort Dienste (Port {ports}, Hosteintrag der Passivquelle aktualisiert am "
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
    # S6b-4 (spec/11 T7): testssl und httpx haben bei DNS-Rotation eine andere Adresse desselben
    # Namens gemessen (huendgen 52.59.120.70 statt 18.197.248.23); der Text nennt sie.
    gemessen = measured_elsewhere(facts, ip)
    # S6b-4n (spec/11 N5): lief testssl fuer die Namen dieser Adresse nur an einer anderen Adresse
    # (DNS-Rotation, zweiter A-Eintrag), ist diese Adresse nicht "vollstaendig" geprueft.
    nur_anderswo = bool(tls_only_elsewhere(facts, ip))
    if gemessen.get("tls") and tls_name in done and not nur_anderswo:
        tls_label = f"{tls_name} (auch an {aufzaehlung(gemessen['tls'])})"
        done[done.index(tls_name)] = tls_label
        tls_name = tls_label
    if tls_name in done and (offen or nur_anderswo):
        done.remove(tls_name)
        if offen:
            # S6b-4 (spec/11 T13): SNI nur fuer Namen, die testssl selbst geprueft hat.
            sni = tls_sni(facts, ip)
            geprueft = ", ".join((f"{p} (SNI {', '.join(sni[p][:2])})" if sni.get(p) else str(p))
                                 for p in sorted(tested))
            an = f" am Namen, gemessen an {aufzaehlung(gemessen['tls'])}," if nur_anderswo else ""
            teilweise.append(f"Transportverschlüsselung nur für {geprueft}{an} geprüft, nicht für "
                             f"Port {', '.join(str(p) for p in offen)}")
        else:
            teilweise.append(f"Transportverschlüsselung am Namen gemessen an {aufzaehlung(gemessen['tls'])}, "
                             "nicht an dieser Adresse")
    if gemessen.get("http"):
        teilweise.append(f"Webabruf und Technologie-Erkennung am Namen gemessen an {aufzaehlung(gemessen['http'])}")
    zap_note, apps = _zap_active_state(facts, ip, rows)
    ohne_meldungen = zap_no_alerts_note(facts, ip, rows)
    zap_name = LEAD_IN_SENTENCE["zap_active"]
    if (zap_note or ohne_meldungen) and zap_name in done:
        done.remove(zap_name)
    if zap_note:
        teilweise.append(zap_note + (f"; Anwendung {aufzaehlung(apps)} nicht aktiv geprüft" if apps else ""))
    if ohne_meldungen:
        teilweise.append(f"{ohne_meldungen}, Ergebnis nicht belastbar")
    # S6b-4 (spec/11 T13): die Scan-Steuerung hat die aktive Webanalyse ausgelassen (bergersysteme:
    # Regel hosted-cms-webflow, nur passive Analyse); 2.1 sagt das statt zu schweigen.
    regel = scan_control_skip(facts, ip, rows)
    if regel is not None and web:
        grund = steuerung_grund(facts, ip, regel)
        teilweise.append("aktive Webanalyse von der Scan-Steuerung übersprungen"
                         + (f" (Regel {regel})" if regel else "") + (f", {grund}" if grund else ""))
    teile = ([f"{aufzaehlung(done)} vollständig"] if done else []) + teilweise
    if missing:
        teile.append(f"nicht geprüft: {aufzaehlung(missing)}")
    extra = dict(tls_untested=offen, tls_tested=[f"{p}" for p in sorted(tested)], zap_note=zap_note,
                 apps_untested=apps, zap_no_alerts=ohne_meldungen)
    if missing or teilweise:
        return HostCoverage(ip=ip, cov="teil", missing=missing, text="; ".join(teile) + ".", **extra)
    if len(done) == 1:
        return HostCoverage(ip=ip, cov="voll",
                            text="Portscan vollständig; ohne TLS- und Webdienst entfielen die weiteren Prüfungen.",
                            **extra)
    return HostCoverage(ip=ip, cov="voll", text=f"{aufzaehlung(done)} vollständig.", **extra)


def build_model(facts: FS.Facts) -> Model:
    hosts = {h.ip: host_coverage(facts, h) for h in facts.hosts}
    systems = SYS.system_of(h for h in facts.hosts if h.third_party is None)
    # S6b-4 (spec/11 T7): AAAA-Adressen derselben Namen gehoeren zum System ihrer IPv4-Adresse
    # und zaehlen mit; geprueft sind sie nicht.
    for h in facts.hosts:
        if h.third_party is not None:
            continue
        for extra in h.additional_ips:
            if extra.ip in hosts:
                continue
            if extra.family == 4:
                # S6b-4n (spec/11 N5): weiterer A-Eintrag; testssl oder httpx koennen dort gemessen
                # haben (huendgen 52.59.120.70), einen Portscan gab es nicht.
                dort = measured_at(facts, extra.ip)
                text = "Weitere Adresse laut DNS, nicht geprüft (kein Portscan)"
                if dort:
                    text += f"; dort am Namen gemessen: {aufzaehlung(dort)}"
                hosts[extra.ip] = HostCoverage(ip=extra.ip, cov="teil" if dort else "keine",
                                               cause="dns_not_scanned", text=text + ".")
            else:
                hosts[extra.ip] = HostCoverage(ip=extra.ip, cov="keine", cause="ipv6_not_scanned",
                                               text="IPv6-Adresse laut DNS, vom Prüfstand aus nicht geprüft.")
            mitglieder = systems.get(h.ip, [h.ip]) + [extra.ip]
            for ip in mitglieder:
                systems[ip] = mitglieder
    return Model(hosts=hosts, systems=systems,
                 third_party=[h.ip for h in facts.hosts if h.third_party is not None])


def additional_ips(facts: FS.Facts) -> dict[str, FS.AdditionalIp]:
    """Adressen laut DNS ohne Inventareintrag (AAAA und weitere A-Eintraege), je Adresse (spec/11 T7, N5)."""
    return {a.ip: a for h in facts.hosts if h.third_party is None for a in h.additional_ips}


def tls_only_elsewhere(facts: FS.Facts, ip: str) -> list[str]:
    """Adressen, an denen testssl fuer die Namen dieser Inventaradresse gemessen hat, wenn es an
    der Inventaradresse selbst keinen Lauf gab (spec/11 N5: huendgen .23 nur an .70)."""
    system = set(SYS.system_of(facts.hosts).get(ip, [ip]))
    laeufe = [t for t in facts.tls if t.host_ip == ip and t.source == "testssl"]
    if not laeufe or any(not t.measured_ip or t.measured_ip in system for t in laeufe):
        return []
    return sorted({t.measured_ip for t in laeufe if t.measured_ip}, key=sort_key)


def measured_at(facts: FS.Facts, ip: str) -> list[str]:
    """Pruefungen, die an einer Adresse ausserhalb des Inventars gemessen haben (spec/11 N5)."""
    out: list[str] = []
    if any(t.measured_ip == ip for t in facts.tls):
        out.append("Transportverschlüsselung")
    if any(h.measured_ip == ip for h in facts.http):
        out.append("Webabruf und Technologie-Erkennung")
    return out


def measured_names(facts: FS.Facts, ip: str) -> dict[str, list[str]]:
    """Name -> Adressen ausserhalb des Systems von ``ip``, an denen testssl oder httpx fuer diesen
    Namen gemessen haben (spec/11 N5: "gemessen an <Adresse>" je Name)."""
    system = set(SYS.system_of(facts.hosts).get(ip, [ip]))
    out: dict[str, list[str]] = {}
    for fact in list(facts.tls) + list(facts.http):
        if fact.host_ip != ip or not fact.measured_ip or fact.measured_ip in system or not fact.fqdn:
            continue
        orte = out.setdefault(fact.fqdn, [])
        if fact.measured_ip not in orte:
            orte.append(fact.measured_ip)
    return {k: sorted(v, key=sort_key) for k, v in out.items()}


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
    if host is None:
        # S6b-4 (spec/11 T7): AAAA-Adresse ohne Inventareintrag, mit den Namen aus dem DNS.
        extra = additional_ips(facts).get(ip)
        names = list(extra.names) if extra is not None else []
    return kurz_label(f"{ip} ({', '.join(names)})") if names else ip


def limitations(facts: FS.Facts, output: CatalogOutput, model: Model,
                dkim_text=None, passive_ids: Optional[list[str]] = None) -> list[Limitation]:
    """Eine Zeile je Ursache, mit Pruefungsnamen und Betroffenen (spec/09 Q10).

    ``passive_ids`` (S6b-4n, spec/11 N13): Befunde, die allein auf der Passivquelle zu nicht
    erreichbaren Hosts beruhen; die E4-Zeile nennt sie."""
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
        # S6b-4 (spec/11 T11): ohne Hostbericht "keine Antwort", nicht "kein offener Port".
        ohne_bericht = [h for h in unerreichbar if h.nmap_host_report is False]
        if len(ohne_bericht) == len(unerreichbar):
            portscan = "der Portscan erhielt keine Antwort"
        elif ohne_bericht:
            portscan = "der Portscan erhielt keine Antwort oder fand keinen offenen Port"
        else:
            portscan = "der Portscan fand keinen offenen Port"
        # S6b-4n (spec/11 N13): die Passivbefunde zu diesen Hosts stehen trotzdem im Bericht.
        ids = sorted(set(passive_ids or []))
        folge = ("Ergebnisse eigener Messungen liegen nicht vor; "
                 + (f"{aufzaehlung(ids)} {'beruht' if len(ids) == 1 else 'beruhen'} allein auf der Passivquelle."
                    if ids else "Aussagen zu diesen Hosts stammen allein aus der Passivquelle."))
        # S6b-4n (spec/11 N15): das Datum ist die Aktualisierung des Hosteintrags bei der Quelle.
        row(HOST_CAUSES["unreachable_from_scanner"][0]).zusatz.append(
            "Eine Passivquelle meldet dort Dienste (Hosteintrag der Passivquelle aktualisiert "
            + ("am " if len(seen) == 1 else "vom ") + spanne + f"); {portscan}. " + folge)
    v6_neu = [h for h in model.hosts.values() if h.cause == "ipv6_not_scanned"]
    if v6_neu:
        # S6b-4n (spec/11 N13): Numerus bei einer Adresse.
        row(HOST_CAUSES["ipv6_not_scanned"][0]).zusatz.append(
            ("Die Adresse steht als AAAA-Eintrag derselben Namen im DNS; der Scanner hat sie nicht in "
             "die Prüfung übernommen." if len(v6_neu) == 1 else
             "Die Adressen stehen als AAAA-Eintrag derselben Namen im DNS; der Scanner hat sie nicht in "
             "die Prüfung übernommen.") + " Geprüft wurde die IPv4-Adresse desselben Systems.")
    v4_neu = [h for h in model.hosts.values() if h.cause == "dns_not_scanned"]
    if v4_neu:
        # S6b-4n (spec/11 N5): weitere A-Eintraege; was dort am Namen gemessen wurde, steht je Adresse.
        r = row(HOST_CAUSES["dns_not_scanned"][0], "dns_not_scanned")
        for h in v4_neu:
            dort = measured_at(facts, h.ip)
            if dort:
                r.ort(h.ip, f"{_host_label(facts, h.ip)}: dort am Namen gemessen {aufzaehlung(dort)}")
        r.zusatz.append(
            ("Die Adresse steht als weiterer A-Eintrag derselben Namen im DNS; der Scanner hat sie nicht"
             if len(v4_neu) == 1 else
             "Die Adressen stehen als weitere A-Einträge derselben Namen im DNS; der Scanner hat sie nicht")
            + " in den Portscan übernommen. Messungen am Namen gelten für den Namen, nicht für die Adresse.")
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
    # S6b-4 (spec/11 T8, T13): Pfadsuche und Scan-Steuerung haben eigene Zeilen (Abschnitt 7).
    pfade = {p.host_ip: p for p in facts.path_search if p.verdict != "skipped"}
    steuerung = {ip: regel for ip in model.hosts
                 if (regel := scan_control_skip(facts, ip, [c for c in facts.coverage if c.host_ip == ip]))
                 is not None and not host_cause.get(ip)}
    for c in facts.coverage:
        if c.status not in ("failed", "blocked", "empty", "skipped"):
            continue
        if c.tool in T.OUT_OF_PRODUCT_TOOLS or c.tool == "nmap":
            continue
        # S6b-4n (spec/11 N13): ohne Schutzsystem ist kein Mangel, ein abgebrochener Lauf schon
        # (huendgen wafw00f nach 60 Sekunden).
        if c.tool in NO_LIMITATION_TOOLS and not (c.tool == "wafw00f" and c.status == "failed"):
            continue
        if c.host_ip and host_cause.get(c.host_ip):
            continue
        if c.tool in PATH_TOOLS and c.host_ip in pfade:
            continue
        if c.tool in ZAP_TOOLS and c.host_ip in steuerung:
            continue
        if c.tool == "header_check" and (c.host_ip, c.fqdn) in ersetzt:
            continue
        if c.tool in ZAP_TOOLS and c.host_ip and model.hosts.get(c.host_ip) is not None \
                and model.hosts[c.host_ip].zap_no_alerts and _code(c) == "zap_no_alerts":
            # Steht als eigene Zeile mit Ursache (Abschnitt 5); eine Ursache, eine Zeile.
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
    http_by = {(h.host_ip, h.fqdn): h for h in facts.http}
    header_rows: dict[str, dict] = {}
    zusatz_checks: dict[str, set[str]] = {}
    for ip, regel in steuerung.items():
        r = row(steuerung_text(regel), "scan_control")
        r.checks.add("Aktive Webanalyse")
        # S6b-4n (spec/11 N4): Grund der Regel, wenn sie aus einem Weiterleitungsziel stammt.
        grund = steuerung_grund(facts, ip, regel)
        r.ort(ip, f"{_host_label(facts, ip)}: {grund}" if grund else _host_label(facts, ip))
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
        if code == "no_enrichment":
            # S6b-4 (spec/11 T13): je Host mit erkannter Version und ohne Abgleich (Abschnitt 7).
            continue
        if ip and host_cause.get(ip):
            continue
        if code in HOST_CAUSES:
            continue
        info = checks.get(res.check_id)
        name = family_check_name(info.family if info else res.family)
        if ip in pfade and (info.family if info else res.family) in PATH_FAMILIES:
            # S6b-4 (spec/11 T8): die Pfadsuche hat eine eigene Zeile mit ihrem Urteil.
            continue
        if ip in steuerung and code in STEUERUNG_CODES:
            r = row(steuerung_text(steuerung[ip]), "scan_control")
            r.checks.add(name)
            r.refs.add(f"{res.check_id}|{res.group_key}")
            r.ort(ip, _host_label(facts, ip))
            continue
        if code == "zap_no_alerts" and ip and model.hosts.get(ip) is not None and model.hosts[ip].zap_no_alerts:
            # S6b-4 (spec/11 T13): eine Ursache, eine Zeile; die Pruefungen stehen in der Zeile
            # "Aktive Webanalyse nur teilweise" (huendgen: zwei Zeilen fuer ZAP ohne Meldung).
            zusatz_checks.setdefault(ip, set()).add(name)
            continue
        key = ip or str(res.vars.get("domain") or "") or res.group_key
        if code in HEADER_REASONS:
            fq = str(res.vars.get("fqdn_names") and res.group_label or res.group_label)
            # Gruppe "name@adresse": exakt der Name, nicht als Teilstring (ftp.bergersysteme.com
            # enthaelt bergersysteme.com). S6b-4: eigener Name der Variablen; vorher stand der
            # Hostname unter "Betroffene Pruefungen".
            vhost = res.group_key.split("@", 1)[0]
            hf = http_by.get((ip, vhost)) or next(
                (h for (hip, hfq), h in http_by.items() if hfq == vhost and (not ip or hip == ip)), None)
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
        elif code == "unreachable" and (ip, res.group_key.split("@", 1)[0]) in ersetzt:
            # S6b-4 (spec/11 R4-Rest): castenow bitwarden antwortete, nur die erste Header-Messung
            # nicht; die Seite ist ueber die TLS-Pruefung bewertet.
            what = ("Erste Header-Messung ohne Antwort; Seite über die TLS-Prüfung bewertet, "
                    "Cookie-Attribute nicht bewertet")
        else:
            what = TOOL_CAUSES.get(code) or text.rstrip(".")
        r = row(what, code)
        r.checks.add(name)
        r.refs.add(f"{res.check_id}|{res.group_key}")
        if code == "cert_chain_unknown" and res.group_by == "fqdn":
            # S6b-4 (spec/11 T13): nur der Name mit eigenem, ungeprueftem Zertifikat, nicht seine
            # Aliasnamen (heuel: heuel.com hat testssl geprueft, jobs ist nur Weiterleitung).
            r.ort(res.group_key, res.group_key.split("@", 1)[0])
            continue
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

    # 3b S6b-4n (spec/11 N3): an der Endseite belegt die Webanalyse nur einzelne Header; die
    # uebrigen sind dort nicht gemessen und gelten weder als gesetzt noch als fehlend.
    from reporter.catalog.render import header_names
    for h in facts.http:
        he = h.header_eval
        if he is None or he.evaluated is None or he.complete or not he.unknown or not h.fqdn:
            continue
        if h.host_ip and host_cause.get(h.host_ip):
            continue
        namen = aufzaehlung(header_names(list(he.unknown)))
        wo = ("nur an der Weiterleitungsseite gemessen" if he.client_redirect
              else "an der Endseite nicht gemessen")
        r = row(HEADER_PARTIAL_CAUSE, "headers_partial")
        r.checks.add("Sicherheits-Header")
        r.ort(f"{h.fqdn}@{h.host_ip}", f"{h.fqdn} ({namen} {wo})")

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
        dienst = sorted({name for p in e5 if (name := passive_module_name(p))})
        # S6b-4 (spec/11 T6): das Datum je Adresse, der Zeitstempel des Dienstes vor dem der
        # letzten Aktualisierung des Hosts (junkerwerk: .130 am 23.09., .28 am 19.09.).
        gesehen = {}
        for p in sorted(e5, key=lambda p: sort_key(p.host_ip)):
            # S6b-4n (spec/11 N15): "gesehen am" nur mit dem Zeitstempel des Dienstes.
            if p.host_ip in gesehen:
                continue
            if p.service_seen_at:
                gesehen[p.host_ip] = f"gesehen am {_datum(p.service_seen_at)}"
            elif p.seen_at:
                gesehen[p.host_ip] = f"Hosteintrag der Passivquelle aktualisiert am {_datum(p.seen_at)}"
        if len(set(gesehen.values())) == 1 and len(gesehen) == len({p.host_ip for p in e5}):
            wann = f" ({next(iter(gesehen.values()))})"
        elif gesehen:
            wann = " (" + ", ".join(f"{ip} {d}" for ip, d in gesehen.items()) + ")"
        else:
            wann = ""
        r.zusatz.append(
            f"Laut Passivquelle nimmt dort der Dienst {aufzaehlung(dienst) or 'auf Port 25'} Verbindungen an"
            + wann
            + "; vom Prüfstand aus ist Port 25 nicht erreichbar, der Mailserver auf diesem Port ist "
              "deshalb nicht geprüft.")

    # 5 Teilpruefungen (spec/10 R3): TLS-Dienste ohne Pruefung, aktive Webanalyse ohne Inhalt.
    for ip, h in sorted(model.hosts.items(), key=lambda kv: sort_key(kv[0])):
        if h.cause:
            continue
        if h.tls_untested:
            r = row(TLS_PARTIAL_CAUSE, "tls_partial")
            r.checks.add("Transportverschlüsselung")
            # S6b-4n (spec/11 N13): das Zertifikat las der Portscan (bergersysteme 110 bis 995, heuel 21);
            # nicht bewertet sind dort Protokolle und Verfahren.
            mit_zert = {s_.port for s_ in facts.services if s_.host_ip == ip and s_.cert is not None}
            teile = []
            z = [p for p in h.tls_untested if p in mit_zert]
            o = [p for p in h.tls_untested if p not in mit_zert]
            if z:
                teile.append(f"{'Port' if len(z) == 1 else 'Ports'} {', '.join(str(p) for p in z)}: Protokolle und "
                             "Verfahren nicht bewertet, Zertifikat aus dem Portscan")
            if o:
                teile.append(f"{'Port' if len(o) == 1 else 'Ports'} {', '.join(str(p) for p in o)}: Protokolle, "
                             "Verfahren und Zertifikat nicht bewertet")
            r.ort(ip, f"{ip} ({'; '.join(teile)})")
        if h.zap_note:
            r = row(ZAP_PARTIAL_CAUSE, "zap_partial")
            r.checks.add("Aktive Webanalyse")
            # S6b-4n (spec/11 N13): die Zeile nennt die Ursache je Host.
            label = f"{_host_label(facts, ip)}: {h.zap_note}"
            if h.apps_untested:
                label = f"{label}; Anwendung {aufzaehlung(h.apps_untested)} nicht aktiv geprüft"
            r.ort(ip, label)
        if h.zap_no_alerts and ip not in steuerung:
            r = row(ZAP_NO_ALERTS_CAUSE, "zap_no_alerts")
            r.checks.add("Webanalyse")
            r.checks.update(zusatz_checks.get(ip, set()))
            r.ort(ip, f"{_host_label(facts, ip)}: {h.zap_no_alerts}")
    if any(h.tls_untested for h in model.hosts.values() if not h.cause):
        row(TLS_PARTIAL_CAUSE).zusatz.append(
            "Geprüft wurde jeweils der Webdienst auf Port 443; die übrigen TLS-Dienste sind nur per "
            "Portscan erfasst.")

    # 6 Gefunden, nicht geprueft (spec/10 R5, bis S6c die Hostsuche repariert)
    gefunden = [(t.domain, d) for t in facts.targets for d in t.discovered]
    if gefunden:
        r = row(DISCOVERED_CAUSE, "discovered")
        r.checks.add("Ermittlung der Hostnamen")
        for _dom, d in gefunden:
            adressen = ", ".join(d.ips[:2]) + (" und weitere" if len(d.ips) > 2 else "")
            zusatz = f"Drittanbieter {d.third_party}, " if d.third_party else ""
            r.ort(d.fqdn, f"{d.fqdn} ({zusatz}{adressen})" if adressen or zusatz else d.fqdn)
        # S6b-4 (spec/11 Teil 1 R5): Numerus bei einem Namen (junkerwerk archiv).
        if len({d.fqdn for _dom, d in gefunden}) == 1:
            r.zusatz.append("Die Hostsuche hat diesen Namen gefunden, er ist aber nicht in die Prüfung "
                            "übernommen worden; Ergebnisse zu ihm liegen nicht vor.")
        else:
            r.zusatz.append("Die Hostsuche hat diese Namen gefunden, sie sind aber nicht in die Prüfung "
                            "übernommen worden; Ergebnisse zu ihnen liegen nicht vor.")

    # 7 S6b-4 (spec/11 T7): Messung an einer anderen Adresse desselben Namens.
    for ip, h in sorted(model.hosts.items(), key=lambda kv: sort_key(kv[0])):
        if h.cause:
            continue
        anders = measured_elsewhere(facts, ip)
        if not anders:
            continue
        teile = []
        if anders.get("tls"):
            teile.append(f"Transportverschlüsselung an {aufzaehlung(anders['tls'])}")
        if anders.get("http"):
            teile.append(f"Webabruf und Technologie-Erkennung an {aufzaehlung(anders['http'])}")
        r = row(ROTATION_CAUSE, "dns_rotation")
        r.checks.update(["Transportverschlüsselung"] if anders.get("tls") else [])
        # S6b-4n (spec/11 N5): auch die Technik der Seite stammt aus dieser Messung.
        r.checks.update(["Webabruf und Technologie-Erkennung"] if anders.get("http") else [])
        r.ort(ip, f"{_host_label(facts, ip)}: {'; '.join(teile)}")
        r.zusatz.append(f"Das Ergebnis gilt für den Namen, nicht für die Inventaradresse {ip}.")

    # 8 S6b-4 (spec/11 T8): Pfadsuche je Host aus feroxbuster-Statistik und ffuf-Treffern.
    # S6b-4n (spec/11 N13): auch neben einer belastbaren Suche, wenn ein Werkzeug abbrach, ohne
    # Statistik endete oder eine Anwendung desselben Hosts nie angefragt wurde.
    for p in facts.path_search:
        ziel = (urlsplit(p.target_url).hostname if p.target_url else None) or p.host_ip
        if host_cause.get(p.host_ip):
            if host_cause[p.host_ip] == "blocked" and p.tool_reasons:
                gruende = sorted({path_abort_text(g) for g in p.tool_reasons.values() if path_abort_text(g)})
                if gruende:
                    row(HOST_CAUSES["blocked"][0]).zusatz.append(
                        f"Die Suche nach nicht verlinkten Pfaden an {ziel} brach ab ({', '.join(gruende)}).")
            continue
        teil = _path_partial(facts, p, ziel)
        if teil and p.verdict == "reliable":
            r = row(PATH_PARTIAL_CAUSE, "path_partial")
            r.checks.add("Suche nach nicht verlinkten Pfaden")
            r.ort(f"{p.host_ip}#teil", f"{ziel}: {teil}")
        if p.verdict not in ("unreliable", "aborted"):
            continue
        if p.verdict == "unreliable":
            arten = []
            weiter = [c for c in p.status_codes if 300 <= c < 400]
            fehler = [c for c in p.status_codes if c in (401, 403)]
            if weiter:
                arten.append(f"Weiterleitung {', '.join(str(c) for c in weiter)}")
            if p.challenge:
                arten.append("Sicherheitsabfrage der Plattform")
            elif fehler:
                arten.append(f"Fehlerseite {', '.join(str(c) for c in fehler)}")
            if 429 in p.status_codes and not p.challenge:
                arten.append("Sicherheitsabfrage 429")
            r = row(PATH_UNRELIABLE_CAUSE, "path_unreliable")
            r.checks.add("Suche nach nicht verlinkten Pfaden")
            r.ort(p.host_ip, f"{ziel} ({', '.join(arten) or 'ohne Inhaltsantwort'})" + (f"; {teil}" if teil else ""))
        else:
            r = row(PATH_ABORTED_CAUSE, "path_aborted")
            r.checks.add("Suche nach nicht verlinkten Pfaden")
            if (p.abort_reason or "") in ("waf_body_marker", "blocked"):
                # S6b-4n (spec/11 N13): bergersysteme www lieferte eine normale Seite (200).
                status = next((f.http_status for f in facts.fqdns if f.name.lower() == ziel.lower()
                               and f.http_status), None)
                r.ort(p.host_ip, f"{ziel}: abgebrochen, der Scanner vermutete in der Startseite"
                                 + (f" ({status})" if status else "") + " ein Abwehrmerkmal")
                continue
            gruende = [f"{PATH_TOOL_NAMES.get(t, t)}: {path_abort_text(g)}" for t, g in sorted(p.tool_reasons.items())
                       if path_abort_text(g)]
            grund = "; ".join(gruende) if len(gruende) > 1 else path_abort_text(p.abort_reason or "")
            r.ort(p.host_ip, (f"{ziel} ({grund})" if grund else ziel) + (f"; {teil}" if teil else ""))

    # 9 S6b-4 (spec/11 T13): Webdienste auf weiteren Ports ohne Web- und Header-Analyse (huendgen 444).
    for ip, ports in sorted(web_ports_unanalysed(facts).items(), key=lambda kv: sort_key(kv[0])):
        if host_cause.get(ip):
            continue
        r = row(WEBPORT_CAUSE, "webport_unanalysed")
        r.checks.update(("Sicherheits-Header", "Webanalyse"))
        r.ort(ip, f"{ip} (Port {', '.join(str(x) for x in ports)})")

    # 10 S6b-4 (spec/11 T13): Fremdbewertung je Host mit erkannter Version und ohne jeden Abgleich,
    # unabhaengig von Folgeausfaellen (junkerwerk .130 dazu, castenow .53 mit wpscan-Abgleich nicht).
    for ip in sorted(hosts_without_lookup(facts), key=sort_key):
        r = row(TOOL_CAUSES["no_enrichment"], "no_enrichment")
        r.checks.add("Abgleich mit Schwachstellendatenbanken")
        r.ort(ip, _host_label(facts, ip))

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
        out.append(Limitation(what=r.what.rstrip("."), checks=sammelbegriffe(r.checks), detail=detail,
                              code=r.code, refs=sorted(r.refs), subjects=sorted(r.subjects, key=sort_key)))
    return out


def _path_partial(facts: FS.Facts, p: FS.PathSearchFact, ziel: str) -> str:
    """Teilausfaelle einer sonst gelaufenen Pfadsuche (spec/11 N13), leer ohne Teilausfall."""
    teile: list[str] = []
    for tool, verdict in sorted(p.tools.items()):
        if verdict == "aborted" and p.verdict != "aborted":
            grund = path_abort_text(p.tool_reasons.get(tool, ""))
            teile.append(f"{PATH_TOOL_NAMES.get(tool, tool)} abgebrochen" + (f" ({grund})" if grund else ""))
    if p.tools.get("feroxbuster") == "reliable" and p.statistics is False:
        teile.append("Verzeichnissuche ohne Abschlussstatistik beendet")
    host = (ziel or "").lower()
    apps = sorted({f.name for f in facts.fqdns if f.host_ip == p.host_ip and not f.wildcard
                   and f.real_content is True and f.name.lower() != host}, key=sort_key)
    if apps and p.target_url:
        teile.append(f"Anwendung {aufzaehlung(apps)} nicht durchsucht")
    return "; ".join(teile)


# S6b-4 (spec/11 T13): Pruefnamen zu Sammelbegriffen, wenn eine Zeile mehr als drei Pruefungen
# nennt (dortmund-beach pflege: 24 Pruefnamen unter "Betroffene Pruefungen").
SAMMEL_MAX = 3
SAMMELBEGRIFFE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Web", ("web", "cookie", "pfad", "wordpress", "anmelde", "formular", "cms", "bibliothek", "skript",
             "technik", "verzeichnis", "entwicklung", "standardseite", "sitzung", "cors", "trace", "http",
             "preisgegeben", "angaben", "version")),
    ("Header", ("header", "content-security", "inhaltsrichtlinie", "hsts", "strict-transport", "sicherheits-header")),
    ("TLS", ("tls", "zertifikat", "verschlüsselung", "vertrauenskette", "protokoll", "cipher", "verfahren")),
    ("Mail", ("mail", "smtp", "spf", "dkim", "dmarc", "mta-sts", "dane", "imap", "pop3")),
    ("DNS", ("dns", "caa", "zone", "cname", "domain")),
    ("Dienst", ("dienst", "port", "portscan", "verwaltung", "datenbank", "fernwartung", "ftp", "ssh")),
)
SAMMEL_NAMEN = {"Web": "Web-", "Header": "Header-", "TLS": "TLS-", "Mail": "Mail-", "DNS": "DNS-",
                "Dienst": "Dienst-"}


def sammelbegriffe(checks: set[str] | list[str]) -> list[str]:
    """Bis zu drei Pruefnamen wie bisher, darueber Sammelbegriffe ("Web-, Header- und TLS-Pruefungen")."""
    namen = sorted(checks)
    if len(namen) <= SAMMEL_MAX:
        return namen
    gruppen: list[str] = []
    rest: list[str] = []
    for name in namen:
        low = name.lower()
        gruppe = next((g for g, stichworte in SAMMELBEGRIFFE if any(s in low for s in stichworte)), None)
        if gruppe is None:
            rest.append(name)
        elif gruppe not in gruppen:
            gruppen.append(gruppe)
    reihenfolge = [g for g, _ in SAMMELBEGRIFFE if g in gruppen]
    teile = [SAMMEL_NAMEN[g] for g in reihenfolge]
    if teile:
        teile[-1] = teile[-1].rstrip("-") + "-Prüfungen" if len(teile) == 1 else teile[-1] + "Prüfungen"
        text = teile[0] if len(teile) == 1 else ", ".join(teile[:-1]) + " und " + teile[-1]
        return [text] + rest
    return namen


def web_ports_unanalysed(facts: FS.Facts) -> dict[str, list[int]]:
    """Offene Webdienste auf weiteren Ports, an denen keine Header- und Webanalyse lief (spec/11 T13).

    Header-Messung und Webanalyse laufen je Name auf dem Standardport; ein Webdienst auf 444
    (huendgen "Web Applications Portal") blieb ohne beides. Plattformen und CDN-Kanten
    (Standardports der Anbieter) und Dienste anderer Nutzer eines geteilten Servers zaehlen nicht."""
    gemessen: set[tuple[str, int]] = set()
    for h in facts.http:
        # Die Adresse der Messung und die Adressen der ZAP-Meldungen (zusaetzliche URLs der
        # Webanalyse) zaehlen als analysiert.
        for url in [h.url, *[a.url for a in h.alerts], *[u for a in h.alerts for u in a.urls_sample]]:
            try:
                parts = urlsplit(url or "")
                port = parts.port or (443 if parts.scheme == "https" else 80)
            except ValueError:
                continue
            if url:
                gemessen.add((h.host_ip, port))
    plattform = {h.ip for h in facts.hosts if h.cdn_provider or (h.shared is not None and h.shared.kind == "platform")
                 or h.third_party is not None}
    out: dict[str, list[int]] = defaultdict(list)
    for s in facts.services:
        if s.state != "open" or s.port in (80, 443) or s.host_ip in plattform or s.foreign:
            continue
        webdienst = (s.service or "") in WEB_SERVICES or (s.service or "").startswith(("http", "https"))
        if not webdienst or (s.host_ip, s.port) in gemessen:
            continue
        out[s.host_ip].append(s.port)
    return {ip: sorted(set(p)) for ip, p in out.items()}


def hosts_without_lookup(facts: FS.Facts) -> list[str]:
    """Eigene Hosts mit erkannter Version, zu denen kein Abgleich mit Schwachstellendaten vorliegt.

    Ein Abgleich ist eine Fremdbewertung aus der Anreicherung oder der Lauf von wpscan (auch mit
    null Treffern); ohne erkannte Version gibt es nichts abzugleichen (spec/11 T13)."""
    eigene = {h.ip for h in facts.hosts if h.third_party is None}
    mit_version = {sw.host_ip for sw in facts.software if sw.host_ip in eigene and sw.version_norm}
    abgleich = {sw.host_ip for sw in facts.software if sw.vulnerabilities or sw.vulnerabilities_count is not None}
    abgleich |= {t.host_ip for t in facts.threats if t.host_ip and (
        (t.cvss_nvd is not None and t.cvss_nvd.score is not None) or (t.kev is not None and t.kev.listed))}
    return sorted(mit_version - abgleich, key=sort_key)


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

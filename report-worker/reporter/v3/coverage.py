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
}

# Werkzeuge, deren leeres Ergebnis keine Einschraenkung ist: ein Webauftritt ohne
# erkennbare Technologie oder ohne vorgelagerte Schutzsysteme ist ein Ergebnis.
NO_LIMITATION_TOOLS = frozenset({"webtech", "wafw00f"})
NO_LIMITATION_CODES = frozenset({"no_tech_signals"})
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
    if missing:
        return HostCoverage(ip=ip, cov="teil", missing=missing,
                            text=f"{aufzaehlung(done)} vollständig; nicht geprüft: {aufzaehlung(missing)}.")
    if len(done) == 1:
        return HostCoverage(ip=ip, cov="voll",
                            text="Portscan vollständig; ohne TLS- und Webdienst entfielen die weiteren Prüfungen.")
    return HostCoverage(ip=ip, cov="voll", text=f"{aufzaehlung(done)} vollständig.")


def build_model(facts: FS.Facts) -> Model:
    hosts = {h.ip: host_coverage(facts, h) for h in facts.hosts}
    return Model(hosts=hosts, systems=SYS.system_of(h for h in facts.hosts if h.third_party is None),
                 third_party=[h.ip for h in facts.hosts if h.third_party is not None])


# ---------------------------------------------------------------- Einschraenkungen

@dataclass
class _Row:
    what: str
    checks: set[str] = field(default_factory=set)
    orte: dict[str, str] = field(default_factory=dict)
    zusatz: list[str] = field(default_factory=list)

    def ort(self, key: str, label: str) -> None:
        vorhanden = self.orte.get(key)
        if vorhanden is None or len(label) > len(vorhanden):
            self.orte[key] = label


def _host_label(facts: FS.Facts, ip: str) -> str:
    host = next((h for h in facts.hosts if h.ip == ip), None)
    names = sorted(host.fqdns, key=sort_key) if host else []
    return kurz_label(f"{ip} ({', '.join(names)})") if names else ip


def limitations(facts: FS.Facts, output: CatalogOutput, model: Model,
                dkim_text=None) -> list[Limitation]:
    """Eine Zeile je Ursache, mit Pruefungsnamen und Betroffenen (spec/09 Q10)."""
    rows: dict[str, _Row] = {}

    def row(what: str) -> _Row:
        return rows.setdefault(what, _Row(what=what))

    host_cause = {ip: h.cause for ip, h in model.hosts.items() if h.cause}
    # 1 Hostweite Ursachen
    for ip, h in sorted(model.hosts.items(), key=lambda kv: sort_key(kv[0])):
        if h.cause in (None, "third_party"):
            continue
        what, checks = HOST_CAUSES[h.cause]
        r = row(what)
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
    for c in facts.coverage:
        if c.status not in ("failed", "blocked", "empty", "skipped"):
            continue
        if c.tool in T.OUT_OF_PRODUCT_TOOLS or c.tool in NO_LIMITATION_TOOLS or c.tool == "nmap":
            continue
        if c.host_ip and host_cause.get(c.host_ip):
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
        r = row(what)
        r.checks.add(check_name(c.tool))
        key = c.host_ip or c.fqdn or c.domain or "scanweit"
        r.ort(key, (_host_label(facts, c.host_ip) if c.host_ip else (c.fqdn or c.domain or "scanweit")))

    # 3 Pruefungen ohne Aussage (Katalog)
    checks = {ci.id: ci for ci in output.checks}
    for res in output.results:
        if res.status != "not_testable" or not res.reason_code:
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
        info = checks.get(res.check_id)
        name = family_check_name(info.family if info else res.family)
        if code == "dkim_selector_unknown" and dkim_text is not None:
            what = dkim_text(res)
        else:
            what = TOOL_CAUSES.get(code) or text.rstrip(".")
        r = row(what)
        r.checks.add(name)
        key = ip or str(res.vars.get("domain") or "") or res.group_key
        r.ort(key, res.group_label)

    # 4 E5: Port 25 laut Passivquelle, vom Portscan nicht gesehen
    e5 = [p for p in facts.passive if p.source == "shodan" and p.port == 25 and p.verified is False
          and p.host_ip and not host_cause.get(p.host_ip)]
    if e5:
        r = row(E5_CAUSE)
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

    out: list[Limitation] = []
    order = [v[0] for v in HOST_CAUSES.values()] + [E5_CAUSE]
    for what in sorted(rows, key=lambda w: (order.index(w) if w in order else len(order), w)):
        r = rows[what]
        where = sorted(r.orte.values(), key=sort_key)
        shown = ", ".join(where[:6]) + (" und weitere" if len(where) > 6 else "")
        detail = f"Betroffen: {shown}." if shown else ""
        if r.zusatz:
            detail = (detail + " " + " ".join(r.zusatz)).strip()
        out.append(Limitation(what=r.what.rstrip("."), checks=sorted(r.checks), detail=detail))
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
           "check_name", "family_check_name", "host_coverage", "build_model", "limitations", "domain_scope"]

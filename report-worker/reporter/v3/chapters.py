# -*- coding: utf-8 -*-
"""Kapitel 1 bis 3 des Reports aus Fakten und Prüfergebnis.

Alles hier ist abgeleitet, nichts geschätzt: Zahlen kommen aus ``facts``, Status aus dem
Katalogergebnis, Texte aus ``narrative.py``. Ein Wert, den die Fakten nicht hergeben,
wird als unbekannt ausgewiesen und nicht geraten.

S6b-1: Abdeckung und Einschränkungen stehen in ``coverage.py``, Rollen in ``roles.py``.
"""
from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

from reporter.catalog.schema import CATEGORY_NAMES, CatalogOutput, CheckResult
from reporter.catalog import tables as CT
from reporter.facts import schema as FS
from reporter.facts import systems as SYS
from reporter.facts.serialize import sort_key
from reporter.v3 import coverage as COV
from reporter.v3 import levels as L
from reporter.v3 import narrative as N
from reporter.v3 import roles as R
from reporter.v3 import tables as T
from reporter.v3.bundles import Consolidated
from reporter.v3.findings import kurz_label
from reporter.v3.orthography import clean_foreign_text
from reporter.v3.models import (Architecture, Business, CanCannot, DomainScope, Finding, Glance,
                                GlanceCategory, Limitation, MethodPhase, NumberTile, ObservedSystem,
                                PostureBlock, PostureItem, Scope, ScopeHost, Screenshot, ServiceCard,
                                ServicePort, TechBlock, TechRow)

LOCAL_TZ = "Europe/Berlin"
UNKNOWN = "unbekannt"


# ---------------------------------------------------------------- Zeit

def _local(ts: Optional[str]) -> tuple[Optional[datetime], str]:
    """UTC-Zeitstempel in Ortszeit, dazu die Bezeichnung der Zone.

    Fehlt die Zeitzonendatenbank im Image, bleibt es bei UTC und der Bericht sagt das.
    """
    if not ts:
        return None, "UTC"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None, "UTC"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        from zoneinfo import ZoneInfo

        local = dt.astimezone(ZoneInfo(LOCAL_TZ))
        return local, local.tzname() or "UTC"
    except Exception:  # pragma: no cover - nur ohne tzdata im Image
        return dt.astimezone(timezone.utc), "UTC"


def format_date(ts: Optional[str]) -> str:
    dt, _ = _local(ts)
    return dt.strftime("%d.%m.%Y") if dt else UNKNOWN


def format_window(started: Optional[str], finished: Optional[str]) -> str:
    start, zone = _local(started)
    end, _ = _local(finished)
    if not start and not end:
        return UNKNOWN
    if start and end:
        if start.date() == end.date():
            return f"{start:%d.%m.%Y}, {start:%H:%M} bis {end:%H:%M} Uhr ({zone})"
        return f"{start:%d.%m.%Y, %H:%M} Uhr bis {end:%d.%m.%Y, %H:%M} Uhr ({zone})"
    dt = start or end
    return f"{dt:%d.%m.%Y, %H:%M} Uhr ({zone})"


def today() -> str:
    override = os.environ.get("VECTISCAN_REPORT_DATE")
    if override:
        return override
    return datetime.now(timezone.utc).strftime("%d.%m.%Y")


# ---------------------------------------------------------------- Abdeckung
# S6b-1 (spec/09 Q9, Q10, E4, E5): ein Modell fuer 2.1, 2.2, den Hinweis auf Seite 3,
# die Zaehlungen und die Posture, siehe reporter/v3/coverage.py.

def coverage_model(facts: FS.Facts) -> COV.Model:
    return COV.build_model(facts)


def hosts_ohne_leitwerkzeug(facts: FS.Facts) -> list[str]:
    """Hosts ohne vollstaendige Leitpruefung (nmap mit Port, testssl, ZAP des Pakets).

    Massstab fuer den Abdeckungshinweis auf Seite 3 (spec/08 Punkt 10). Seit S6b-1
    dieselbe Regel wie die Abdeckung in Kapitel 2.1; Drittanbieter zaehlen nicht.
    """
    return COV.build_model(facts).gaps()


# Maschinenwerte aus dem Scanner in Kundensprache. Ein Wert ohne Eintrag wird
# weggelassen; ein Rohtoken wie "parking" gehoert nicht in den Bericht
# (Entscheidung DC, spec/08 Punkt 13).
OUT_OF_SCOPE_REASONS: dict[str, str] = {
    "parking": "geparkte Domain ohne eigenen Inhalt",
    "vhost_skipped": "nicht beauftragt",
    "not_in_scope": "ausserhalb des beauftragten Umfangs",
    "wildcard": "Wildcard-Eintrag",
    "out_of_scope": "ausserhalb des beauftragten Umfangs",
}


def _unbeauftragt(facts: FS.Facts, output: CatalogOutput) -> set[str]:
    """Namen, die im Bericht sonst nirgends vorkommen.

    S6 (spec/08 Punkt 13, Entscheidung DC): "Sichtbar, aber nicht beauftragt"
    gilt nur fuer Hosts ausserhalb aller Umfangstabellen und Befunde.
    pflege.dortmund-beach.com stand in beiden Listen gleichzeitig.
    """
    bekannt = {f.name.lower() for f in facts.fqdns if not f.wildcard}
    bekannt |= {(r.group_label or "").lower() for r in output.results if r.status == "fail"}
    bekannt |= {a.lower() for r in output.results if r.status == "fail" for a in r.affected}
    out: set[str] = set()
    for target in facts.targets:
        for oos in target.out_of_scope:
            wert = (oos.value or "").strip()
            if not wert or wert.lower() in bekannt:
                continue
            if any(wert.lower() in eintrag for eintrag in bekannt):
                continue
            grund = OUT_OF_SCOPE_REASONS.get((oos.reason or "").strip().lower(), "")
            out.add(f"{wert} ({grund})" if grund else wert)
    return out


def wildcard_hinweise(facts: FS.Facts) -> list[str]:
    """Ein Satz je Wildcard-Eintrag fuer Kapitel 2.1."""
    namen = sorted({f.name for f in facts.fqdns if f.wildcard})
    return [f"Wildcard-Eintrag {name}: er verweist alle nicht einzeln benannten Namen "
            "auf denselben Host und ist selbst kein geprüfter Hostname."
            for name in namen]


def blockade_belegt(facts: FS.Facts) -> bool:
    """Hat ein Ziel den Scanner nachweislich abgewiesen? (spec/08 Punkt 9)

    Der Satz zur Freischaltung der Scanner-Adresse stand bisher in jedem Bericht
    mit irgendeiner Luecke, auch wenn nichts blockiert hat. Beleg ist entweder
    ein Host mit erkannter Blockade oder eine Abdeckungszeile mit dem Status
    ``blocked``.
    """
    if any(h.blocked.detected for h in facts.hosts):
        return True
    return any(c.status == "blocked" for c in facts.coverage)


# Werkzeuge, die bewusst nicht Teil des Produkts sind (Entscheidung DC, spec/07).
OUT_OF_PRODUCT_TOOLS = T.OUT_OF_PRODUCT_TOOLS


# S6a (#15 Teil 2): DKIM ohne gefundenen Selektor ist nicht pruefbar. Die Einschraenkung
# nennt Anzahl und sechs Beispiele der abgefragten Selektoren, die volle Liste steht im
# Anhang bei den eingesetzten Werkzeugen (Entscheidung DC). Belegt der Lauf die Liste
# nicht (Dkim.probed leer), bleibt der allgemeine Text aus COVERAGE_REASONS.
DKIM_CODE = "dkim_selector_unknown"
DKIM_BEISPIELE = ("default", "selector1", "selector2", "google", "k1", "s1")
DKIM_WHAT = "DKIM ohne Selektor aus einer echten E-Mail nicht prüfbar"
DKIM_DETAIL_ALLGEMEIN = ("Unter den gängigen Selektoren war kein Schlüssel veröffentlicht. Ob die Domain "
                         "signiert, zeigt der Kopf einer echten E-Mail (DKIM-Signature, Angabe s=).")


def dkim_probed(facts: FS.Facts, domain: str) -> list[str]:
    for dns in facts.dns:
        if dns.domain == domain and dns.dkim is not None and dns.dkim.probed:
            return list(dns.dkim.probed)
    return []


def dkim_beispiele(probed: list[str], anzahl: int = 6) -> list[str]:
    out = [s for s in DKIM_BEISPIELE if s in probed]
    out += [s for s in sorted(probed) if s not in out]
    return out[:anzahl]


def dkim_limitation_text(probed: list[str]) -> str:
    return (f"DKIM ohne Selektor aus einer echten E-Mail nicht prüfbar: unter {len(probed)} "
            f"abgefragten gängigen Selektoren, darunter {', '.join(dkim_beispiele(probed))}, war "
            "kein Schlüssel veröffentlicht (vollständige Liste im Anhang bei den eingesetzten "
            "Werkzeugen). Ob die Domain signiert, zeigt der Kopf einer echten E-Mail "
            "(DKIM-Signature, Angabe s=).")


def dkim_limitation_detail(probed: list[str]) -> str:
    """Der erklaerende Teil fuer die Spalte Auswirkung (S6b-1: dreispaltige Tabelle)."""
    return (f"Unter {len(probed)} abgefragten gängigen Selektoren, darunter "
            f"{', '.join(dkim_beispiele(probed))}, war kein Schlüssel veröffentlicht (vollständige "
            "Liste im Anhang bei den eingesetzten Werkzeugen). Ob die Domain signiert, zeigt der "
            "Kopf einer echten E-Mail (DKIM-Signature, Angabe s=).")


def dkim_selectors_for_appendix(facts: FS.Facts, output: CatalogOutput) -> list[str]:
    """Abgefragte Selektoren fuer den Anhang, nur wenn eine Einschraenkung darauf verweist."""
    out: set[str] = set()
    for result in output.results:
        if result.status != "not_testable" or not result.reason_code:
            continue
        if result.reason_code.split(":", 1)[-1] == DKIM_CODE:
            out.update(dkim_probed(facts, str(result.vars.get("domain") or result.group_key)))
    return sorted(out)


def limitations(facts: FS.Facts, output: CatalogOutput,
                model: COV.Model | None = None) -> list[Limitation]:
    """Einschraenkungen: eine Zeile je Ursache mit Pruefungsnamen (spec/09 Q10)."""
    model = model or COV.build_model(facts)
    zusatz: list[str] = []

    def dkim(result: CheckResult) -> str:
        probed = dkim_probed(facts, str(result.vars.get("domain") or result.group_key))
        text = dkim_limitation_detail(probed) if probed else DKIM_DETAIL_ALLGEMEIN
        if text not in zusatz:
            zusatz.append(text)
        return DKIM_WHAT

    rows = COV.limitations(facts, output, model, dkim_text=dkim)
    for row in rows:
        if row.what == DKIM_WHAT and zusatz:
            row.detail = f"{row.detail} {' '.join(zusatz)}".strip()
    return rows


# Ein Host mit vielen VHosts traegt sie alle im Gruppennamen. In der
# Betroffenenliste einer Einschraenkung ist das eine Wand aus Namen: bei
# vectigal.tech sind es 31 hinter einer einzigen IP. Die Kuerzung der Liste
# selbst (sechs Eintraege) greift dort nicht, weil das Ganze ein Eintrag ist.
# S6a: dieselbe Kuerzung gilt fuer Positivbefunde, deshalb liegt sie in findings.
_kurz = kurz_label


# ---------------------------------------------------------------- Kapitel 1

def build_glance(items: list[Consolidated], findings: list[Finding], counts: N.Counts,
                 gap_systems: list[list[str]]) -> Glance:
    by_cat: dict[str, list[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.cat, []).append(f)
    categories: list[GlanceCategory] = []
    for key in ("A", "B", "C", "D", "E"):
        group = sorted(by_cat.get(key, []), key=lambda f: L.STATUS_RANK[f.status])
        status = group[0].status if group else "gruen"
        note = "; ".join(f.title for f in group[:2]) if group else "Keine Befunde in dieser Kategorie"
        categories.append(GlanceCategory(
            key=key, name=CATEGORY_NAMES[key], status=status,
            level=L.BAR_BY_STATUS[status], note=note))
    overall_status = min((c.status for c in categories), key=lambda s: L.STATUS_RANK[s])
    return Glance(
        overall=L.OVERALL_BY_STATUS[overall_status],
        overall_status=overall_status,
        overall_text=overall_text(findings),
        categories=categories,
        levers=[],
        context=N.context(counts),
        coverage_warning=N.coverage_warning(counts, gap_systems),
    )


# Wie eine Kategorie im Gesamtbewertungstext benannt wird. Die Namen aus
# CATEGORY_NAMES sind Ueberschriften ("Patch- und EOL-Status") und lesen sich im
# Fliesstext nicht; hier steht die Satzform.
CATEGORY_IN_SENTENCE: dict[str, str] = {
    "A": "die aus dem Internet erreichbaren Dienste",
    "B": "den Softwarestand der erkannten Systeme",
    "C": "die Authentizität der E-Mail",
    "D": "die Transportverschlüsselung und die Sicherheits-Header",
    "E": "die Konfiguration und die preisgegebenen Angaben",
}


def _aufzaehlung(teile: list[str]) -> str:
    # Das letzte Glied haengt mit "sowie" an, weil die Kategorienamen selbst ein
    # "und" tragen koennen und zwei "und" in einem Satz stolpern lassen.
    if len(teile) == 1:
        return teile[0]
    return ", ".join(teile[:-1]) + " sowie " + teile[-1]


def overall_text(findings: list[Finding]) -> str:
    """Zusammenfassung Seite 1 als Katalogfassung; die KI darf sie ersetzen.

    Der zweite Satz war bis S6 ein Festtext je Stufe und nannte auch dort
    Dienste, E-Mail und Transportverschluesselung, wo der Bericht gar keinen
    solchen Befund hatte (spec/08 Punkt 16). Jetzt steht dort, welche Kategorien
    tatsaechlich Befunde tragen.
    """
    red = [f for f in findings if f.status == "rot"]
    rest = [f for f in findings if f.status != "rot"]
    if red:
        head = (f"{len(red)} Befunde erfordern unverzügliches Handeln."
                if len(red) > 1 else "Ein Befund erfordert unverzügliches Handeln.")
    elif any(f.status == "gelb" for f in findings):
        head = ("Kein Befund erfordert sofortiges Handeln, es besteht aber Handlungsbedarf "
                "mit erkennbarem Angriffsweg.")
    elif findings:
        head = "Es wurde kein Befund mit erkennbarem Angriffsweg festgestellt."
    else:
        return "In dieser Prüfung ist kein Befund entstanden."

    cats = [c for c in ("A", "B", "C", "D", "E")
            if any(f.cat == c for f in (rest or findings))]
    namen = [CATEGORY_IN_SENTENCE[c] for c in cats if c in CATEGORY_IN_SENTENCE]
    if not namen:
        return head
    wort = "Die übrigen Befunde betreffen" if red else "Die Befunde betreffen"
    return f"{head} {wort} {_aufzaehlung(namen)}."


def build_business(facts: FS.Facts, observed: list[ObservedSystem]) -> Business:
    return Business(lead=N.BUSINESS_LEAD, observed=observed,
                    implication=N.BUSINESS_IMPLICATION_GENERIC)


# ---------------------------------------------------------------- Rollen und Systeme
# S6b-1 (spec/09 Q2): Rollen nur mit Fakt, siehe reporter/v3/roles.py.

def _systems(facts: FS.Facts) -> list[list[FS.HostFact]]:
    """Systeme des Kunden in Berichtsreihenfolge: IPv4 und IPv6 mit gleichem rDNS als
    ein System, Drittanbieter ausgenommen (spec/09 Q16)."""
    eigene = [h for h in facts.hosts if h.third_party is None]
    groups = list(SYS.system_groups(eigene).values())
    return sorted(groups, key=lambda g: (g[0].family, sort_key(g[0].ip)))


def system_roles(facts: FS.Facts, members: list[FS.HostFact]) -> list[R.Role]:
    """Rollen eines Systems: die der Adressen zusammen, in fester Reihenfolge."""
    by_key: dict[str, R.Role] = {}
    for h in members:
        for role in R.host_roles(facts, h):
            by_key.setdefault(role.key, role)
    order = {k: i for i, k in enumerate(T.ROLE_ORDER)}
    return sorted(by_key.values(), key=lambda r: order.get(r.key, len(order)))[:R.MAX_ROLES]


def host_roles(facts: FS.Facts, ip: str) -> list[str]:
    """Rollen eines Hosts als Anzeigenamen (Kompatibilitaet fuer Aufrufer ausserhalb)."""
    host = next((h for h in facts.hosts if h.ip == ip), None)
    return [r.label for r in R.host_roles(facts, host)] if host else []


def host_role(facts: FS.Facts, ip: str) -> str:
    roles = host_roles(facts, ip)
    return ", ".join(roles) if roles else T.ROLE_FALLBACK


def observed_systems(facts: FS.Facts) -> list[ObservedSystem]:
    """Ein Eintrag je System mit Rolle und Risikotext; Belege fuer das Prosa-Gate."""
    out: list[ObservedSystem] = []
    for members in _systems(facts):
        roles = system_roles(facts, members)
        names = sorted({n for h in members for n in h.fqdns if not n.startswith("*.")}, key=sort_key)
        label_role = R.role_label(roles)
        label = f"{label_role} ({', '.join(names[:3])})" if names else f"{label_role} ({members[0].ip})"
        out.append(ObservedSystem(
            system=label, meaning=R.role_meaning(roles),
            role_keys=[r.key for r in roles],
            evidence=[e for r in roles for e in r.evidence][:6]))
    return out


def _shared_hint(host: FS.HostFact) -> str:
    if host.shared is None:
        return ""
    if host.shared.kind == "platform":
        return f"Plattform {host.shared.operator}" if host.shared.operator else "Plattform eines Anbieters"
    return "geteiltes System beim Hoster"


# ---------------------------------------------------------------- Kapitel 2

def build_scope(facts: FS.Facts, output: CatalogOutput, counts: N.Counts,
                model: COV.Model) -> Scope:
    hosts: list[ScopeHost] = []
    for members in _systems(facts):
        lead = members[0]
        cov = model.hosts[lead.ip]
        text = cov.text
        more = [h.ip for h in members[1:]]
        for h in members[1:]:
            extra = model.hosts[h.ip]
            if extra.cov != cov.cov or extra.text != cov.text:
                text = f"{text} {h.ip}: {extra.text}"
        status = model.system_status([h.ip for h in members])
        operator = (SYS.network_operator(lead.provider.isp) if lead.provider else None) or UNKNOWN
        if lead.reverse:
            operator = f"{operator} ({lead.reverse})"
        roles = R.role_label(system_roles(facts, members))
        hint = _shared_hint(lead)
        # S6b-2 (spec/09 Teil 2 DB, Rest spec/08 Punkt 13): ein Wildcard-Eintrag ist kein
        # Hostname; die Zaehlung in 2.1 liess ihn schon aus, die Liste nannte ihn noch.
        names = sorted({n for h in members for n in h.fqdns if not n.startswith("*.")}, key=sort_key)
        hosts.append(ScopeHost(
            ip=lead.ip, more_ips=more, fqdns=", ".join(names) or UNKNOWN,
            operator=operator, role=f"{roles} · {hint}" if hint else roles,
            coverage=text, cov=status))
    for host in sorted((h for h in facts.hosts if h.third_party is not None), key=lambda h: sort_key(h.ip)):
        operator = host.third_party.operator or UNKNOWN
        hosts.append(ScopeHost(
            ip=host.ip, fqdns=", ".join(sorted((n for n in host.fqdns if not n.startswith("*.")),
                                               key=sort_key)) or UNKNOWN,
            operator=operator, role="Drittanbieter", coverage=model.hosts[host.ip].text, cov="extern"))
    out_of_scope = list(N.OUT_OF_SCOPE_BASE)
    extra = sorted(_unbeauftragt(facts, output))
    if extra:
        out_of_scope.append("Sichtbar, aber nicht beauftragt: " + "; ".join(extra) + ".")
    for hinweis in wildcard_hinweise(facts):
        out_of_scope.append(hinweis)
    domains = COV.domain_scope(facts)
    return Scope(
        lead=N.scope_lead(counts),
        hosts=hosts,
        domains=[DomainScope(domain=d, text=t) for d, t in domains] if len(domains) > 1 else [],
        out_of_scope=out_of_scope,
        limitations=limitations(facts, output, model),
        method_phases=[MethodPhase(n=n, name=name, text=text)
                       for n, name, text in N.method_phases(counts)],
        numbers=[NumberTile(v=v, l=label) for v, label in N.numbers(counts)],
        standard_note=N.STANDARD_NOTE,
        ai_note=N.AI_NOTE,
        can_cannot=CanCannot(can=list(N.CAN), cannot=list(N.CANNOT), advice=N.ADVICE),
    )


# ---------------------------------------------------------------- Kapitel 3

def _confidence_label(value: float) -> str:
    if value >= 0.9:
        return "hoch"
    if value >= 0.7:
        return "mittel"
    return "niedrig"


_EOL_STATUS = {
    "eol": ("veraltet", "rot"),
    "supported": ("aktuell", "gruen"),
    "unknown": (UNKNOWN, "grau"),
}


@dataclass(frozen=True)
class TechLine:
    """Eine Zeile der Technologietabelle, bevor sie Bericht (``TechRow``) oder
    Dashboard (``reports.tech_profiles[].tech_rows``) wird. Beide lesen dieselben
    Zeilen, damit Komponente, Version und Patch-Status nie auseinanderlaufen
    (spec/09 Q11)."""
    software: FS.SoftwareFact
    product: str
    version: str
    eol_status: str
    eol_date: Optional[str]
    note: str
    sources: str
    confidence: float
    conf_label: str


def _ohne_eigene_tabelle(host: FS.HostFact) -> bool:
    """Drittanbieter und IPv6 ohne Route bekommen keine Technologietabelle: ihre
    Eintraege stammen nicht aus einer Messung an dieser Adresse (spec/09 Q16)."""
    return host.third_party is not None or bool(host.reach and host.reach.status == "no_ipv6_route")


# S6b-2 (Entscheidung DC 25.09., spec/09 Q14 und Q11-Rest): eine Technikzeile braucht
# Konfidenz hoch oder zwei unabhaengige Quellen. Sonst steht die Meldung nur als
# Werkzeugmeldung im Anhang ("Java/Servlet" allein aus webtech bei heuel).
TECH_MIN_CONFIDENCE = 0.9
TECH_MIN_SOURCES = 2


def _tech_bestaetigt(gruppe: list[FS.SoftwareFact]) -> bool:
    quellen = {q for s in gruppe for q in s.detection_sources} or {s.source for s in gruppe}
    return max(s.confidence for s in gruppe) >= TECH_MIN_CONFIDENCE or len(quellen) >= TECH_MIN_SOURCES


def tech_lines(facts: FS.Facts, *, unconfirmed: list[TechLine] | None = None) -> dict[str, list[TechLine]]:
    """Zeilen je Host-IP in Berichtsreihenfolge; Hosts ohne Software fehlen.

    ``unconfirmed`` sammelt die Zeilen, die die Schwelle aus Konfidenz und Quellen nicht
    erreichen; sie gehen als Werkzeugmeldung in den Anhang.
    """
    by_host: dict[str, list[FS.SoftwareFact]] = {}
    for sw in facts.software:
        by_host.setdefault(sw.host_ip, []).append(sw)
    out: dict[str, list[TechLine]] = {}
    for host in sorted(facts.hosts, key=lambda h: (h.family, h.ip)):
        if _ohne_eigene_tabelle(host):
            continue
        entries = sorted(by_host.get(host.ip, []), key=lambda s: (s.kind, s.product, s.id))
        if not entries:
            continue
        # Issue #33: eine Komponente mit belegter Version steht nicht zusaetzlich als
        # "unbekannt" da (Plesk 18.0.81 aus dem nmap-Titel, Plesk ohne Version aus dem
        # Header eines VHosts).
        mit_version = {s.family for s in entries if s.version_norm}
        # Derselbe Name in anderer Schreibweise ist dieselbe Komponente ("cloudflare"
        # aus nmap, "Cloudflare" aus httpx): eine Zeile, Quellen zusammengefuehrt.
        gruppen: dict[tuple[str, str], list[FS.SoftwareFact]] = {}
        for sw in entries:
            if not sw.version_norm and sw.family in mit_version:
                continue
            gruppen.setdefault((sw.product.lower(), _tech_version(sw)), []).append(sw)
        lines: list[TechLine] = []
        for (_, version), gruppe in gruppen.items():
            sw = max(gruppe, key=lambda s: (s.confidence, s.product != s.product.lower()))
            bestaetigt = _tech_bestaetigt(gruppe)
            quellen = sorted({q for s in gruppe for q in s.detection_sources}) or [sw.source]
            note = T.tech_note(sw.note)
            if sw.eol.status == "eol" and sw.eol.date:
                note = f"Herstellerpflege endete am {sw.eol.date}"
            elif sw.eol.upstream_eol_date:
                note = f"Lifecycle prüfen, Hersteller nennt {sw.eol.upstream_eol_date}"
            line = TechLine(
                software=sw, product=sw.product, version=version, eol_status=sw.eol.status,
                eol_date=sw.eol.date, note=note, sources=", ".join(quellen),
                confidence=sw.confidence, conf_label=_confidence_label(sw.confidence))
            if not bestaetigt:
                if unconfirmed is not None:
                    unconfirmed.append(line)
                continue
            lines.append(line)
        if lines:
            out[host.ip] = lines
    return out


def tech_tool_findings(facts: FS.Facts) -> list["ToolFinding"]:
    """Nicht bestaetigte Technikzeilen als Werkzeugmeldung fuer den Anhang (S6b-2)."""
    from reporter.v3.models import ToolFinding

    offen: list[TechLine] = []
    tech_lines(facts, unconfirmed=offen)
    out: list[ToolFinding] = []
    for line in offen:
        was = line.product if line.version == UNKNOWN else f"{line.product} {line.version}"
        out.append(ToolFinding(
            what=f"Technik: {was}", where=line.software.fqdn or line.software.host_ip,
            note=(f"Nur laut {line.sources} mit Konfidenz {line.conf_label}; ohne zweite Quelle "
                  "nicht in der Technologietabelle.")))
    return out


def _tech_version(sw: FS.SoftwareFact) -> str:
    version = sw.version_norm or UNKNOWN
    if sw.build:
        return f"{version} (Build {sw.build})"
    if sw.distro:
        return f"{version} ({sw.distro})"
    return version


def build_tech(facts: FS.Facts) -> list[TechBlock]:
    hosts = {h.ip: h for h in facts.hosts}
    blocks: list[TechBlock] = []
    for ip, lines in tech_lines(facts).items():
        host = hosts[ip]
        rows: list[TechRow] = []
        for line in lines:
            status, colour = _EOL_STATUS.get(line.eol_status, (UNKNOWN, "grau"))
            rows.append(TechRow(c=line.product, v=line.version, src=line.sources, conf=line.conf_label,
                                status=status, st=colour, note=line.note))
        label = f"{host.ip} ({host.reverse})" if host.reverse else host.ip
        blocks.append(TechBlock(host=label, rows=rows))
    return blocks


# ---------------------------------------------------------------- Dienste und Befundbezug

def _member_port(facts: FS.Facts, host_ip: str, fqdn: Optional[str], port: Optional[int]) -> Optional[int]:
    """Port eines Mitglieds; VHost-Befunde ohne Port an den Port ihres Webdienstes
    (spec/09 Teil 3: 443 stand gruen trotz VHost-Befunden)."""
    if port is not None:
        return port
    if not fqdn:
        return None
    http = next((h for h in facts.http if h.host_ip == host_ip and h.fqdn == fqdn), None)
    if http is not None and http.url:
        parts = urlsplit(http.url)
        if parts.port:
            return parts.port
        return 443 if parts.scheme == "https" else 80
    if any(t.host_ip == host_ip and t.fqdn == fqdn for t in facts.tls):
        return 443
    return None


def finding_ports(facts: FS.Facts, items: list[Consolidated],
                  findings: list[Finding]) -> dict[tuple[str, int], list[Finding]]:
    """Befunde je (Host, Port), eine Zuordnung fuer Service-Karte und Anhang B."""
    out: dict[tuple[str, int], list[Finding]] = {}
    for item, finding in zip(items, findings):
        for result in item.results:
            for member in result.members:
                if member.status != "fail" or member.host_ip is None:
                    continue
                port = _member_port(facts, member.host_ip, member.fqdn, member.port)
                if port is None:
                    continue
                bucket = out.setdefault((member.host_ip, port), [])
                if finding not in bucket:
                    bucket.append(finding)
    return out


def passive_service_label(pv: FS.PassiveFact) -> str:
    """Dienstname laut Passivquelle: Produkt, sonst das Modul (E5: "SMTP" statt
    "unbekannt")."""
    if pv.product:
        return pv.product
    return COV.passive_module_name(pv) or UNKNOWN


def build_services(facts: FS.Facts, items: list[Consolidated],
                   findings: list[Finding]) -> list[ServiceCard]:
    """Service-Karte: Farbe je Port nach Ampel des schwersten Befunds (Legende nach Ampel)."""
    refs = finding_ports(facts, items, findings)
    cards: list[ServiceCard] = []
    for host in sorted(facts.hosts, key=lambda h: (h.family, h.ip)):
        if host.third_party is not None:
            continue
        ports: list[ServicePort] = []
        for svc in sorted((s for s in facts.services if s.host_ip == host.ip and s.state == "open"),
                          key=lambda s: s.port):
            label = svc.product or (svc.service or "").upper() or UNKNOWN
            befunde = refs.get((host.ip, svc.port), [])
            colour = min((f.status for f in befunde), key=lambda s: L.STATUS_RANK[s]) if befunde else "gruen"
            ports.append(ServicePort(p=str(svc.port), s=label, st=colour))
        seen = {p.p for p in ports}
        for pv in sorted((p for p in facts.passive if p.host_ip == host.ip and p.port),
                         key=lambda p: p.port or 0):
            if str(pv.port) in seen:
                continue
            seen.add(str(pv.port))
            ports.append(ServicePort(p=str(pv.port), s=passive_service_label(pv), st="grau"))
        if not ports:
            continue
        cards.append(ServiceCard(host=host.ip, label=host.reverse or "", ports=ports))
    return cards


def _result_state(results: list[CheckResult],
                  primary: list[CheckResult] | None = None) -> tuple[Optional[bool], str]:
    """Status eines Posture-Items.

    Ein Fehlschlag irgendeiner beteiligten Pruefung zieht das Item auf
    "Handlungsbedarf". Zwischen "unauffaellig" und "nicht pruefbar" entscheidet die
    leitende Pruefung; ein bestandener Nebencheck ohne gesehene Items sagt nichts aus.
    """
    if not results:
        return None, "nicht geprüft"
    if any(r.status == "fail" for r in results):
        return False, "Handlungsbedarf"
    lead = primary if primary else results
    if any(r.status == "pass" and r.items_seen > 0 for r in lead):
        return True, "unauffällig"
    if any(r.status == "not_testable" for r in lead):
        return None, "nicht prüfbar"
    if any(r.status == "pass" and r.items_seen > 0 for r in results):
        return True, "unauffällig"
    if any(r.status == "not_testable" for r in results):
        return None, "nicht prüfbar"
    return None, "entfällt"


# Posture der Hosts ohne Messergebnis (S6b-1, spec/09 Q9): immer "nicht pruefbar".
POSTURE_UNREACHABLE = frozenset({"unerreichbar", "keine"})


# S6b-2 (spec/08 Punkt 6): SPF mit ~all ist vorhanden, aber nicht hart; die Posture zeigt
# das als "softfail", nicht als fehlend und nicht als Handlungsbedarf.
POSTURE_SOFT: dict[str, tuple[str, str]] = {"SPF": ("spf_softfail", "softfail")}
# S6b-2 (spec/09 Q12): "Zertifikate unauffaellig" nur, wenn alle verschluesselten Dienste
# der Hosts geprueft sind.
POSTURE_TLS_ITEMS = frozenset({"Zertifikate"})


def build_posture(output: CatalogOutput, model: COV.Model | None = None,
                  facts: FS.Facts | None = None) -> list[PostureBlock]:
    from reporter.v3.bundles import tls_untested_hosts

    by_check: dict[str, list[CheckResult]] = {}
    for r in output.results:
        by_check.setdefault(r.check_id, []).append(r)
    tls_offen = tls_untested_hosts(facts)
    ohne_messung = sorted((h.ip for h in (model.counted if model else []) if h.cov in POSTURE_UNREACHABLE),
                          key=sort_key)
    blocks: list[PostureBlock] = []
    for spec in T.POSTURE_BLOCKS:
        items: list[PostureItem] = []
        per_host = spec.get("per_host") or ()
        if per_host:
            by_host: dict[str, list[CheckResult]] = {}
            lead_by_host: dict[str, list[CheckResult]] = {}
            for cid in per_host:
                for r in by_check.get(cid, []):
                    host = str(r.vars.get("host_ip") or r.group_key)
                    by_host.setdefault(host, []).append(r)
                    if cid == per_host[0]:
                        lead_by_host.setdefault(host, []).append(r)
            for host in sorted(set(by_host) | set(ohne_messung), key=sort_key):
                if host in ohne_messung:
                    items.append(PostureItem(l=host, ok=None, v="nicht prüfbar"))
                    continue
                ok, text = _result_state(by_host[host], lead_by_host.get(host))
                items.append(PostureItem(l=host, ok=ok, v=text))
        for label, checks in spec["items"]:  # type: ignore[index]
            results = [r for cid in checks for r in by_check.get(cid, [])]
            ok, text = _result_state(results, by_check.get(checks[0], []))
            weich = POSTURE_SOFT.get(label)
            if weich and ok is False:
                fails = {r.check_id for r in results if r.status == "fail"}
                if fails == {weich[0]}:
                    ok, text = None, weich[1]
            if label in POSTURE_TLS_ITEMS and ok is True and tls_offen:
                ok, text = None, "nur teilweise geprüft"
            items.append(PostureItem(l=label, ok=ok, v=text))
        if items:
            blocks.append(PostureBlock(name=str(spec["name"]), short=str(spec["short"]),
                                       items=items))
    return blocks


def _same_page_key(fq: FS.FqdnFact) -> Optional[str]:
    if fq.body_hash:
        return f"body:{fq.body_hash}"
    if fq.final_url:
        parts = urlsplit(fq.final_url)
        return f"url:{(parts.hostname or '').lower()}{parts.path.rstrip('/') or '/'}"
    return None


def build_screens(facts: FS.Facts) -> list[Screenshot]:
    """Sichtnachweise aus den Fakten, jede Seite einmal.

    ``screenshot_key`` zeigt auf das Objekt in MinIO; die Bilddatei selbst holt der
    Renderer (S4). Der Titel stammt von der fremden Seite und wird geglaettet, bevor er
    in den Bericht geht. S6b-1 (spec/09 Teil 3): Namen mit derselben Seite (gleicher
    Inhalt oder gleiches Weiterleitungsziel) teilen sich ein Bild; die Unterschrift nennt
    die weiteren Namen. Bevorzugt wird der Name, auf den die Weiterleitung zeigt.
    """
    def eigenes_bild(fq: FS.FqdnFact) -> bool:
        # Ein Name ohne eigene Probe erbt das Hostbild eines anderen Namens
        # (dortmund-beach: pflege und www zeigten das Bild von dortmund-beach.com).
        datei = (fq.screenshot_key or "").rsplit("/", 1)[-1]
        return datei.endswith(f"__{fq.name}.png") or fq.http_status is not None

    kandidaten = [fq for fq in facts.fqdns
                  if fq.screenshot_key and not fq.wildcard and eigenes_bild(fq)
                  and next((h for h in facts.hosts if h.ip == fq.host_ip and h.third_party is None), None)]

    def rang(fq: FS.FqdnFact) -> tuple:
        ziel = (urlsplit(fq.final_url or "").hostname or "").lower()
        return (0 if ziel == fq.name.lower() else 1, len(fq.name), fq.name)

    # Gleiche Bilddatei (Hündgen: der Apex traegt das Bild von www als Hostbild), gleicher
    # Inhalt oder gleiches Weiterleitungsziel ergeben eine Gruppe.
    groups: dict[str, list[FS.FqdnFact]] = {}
    alias: dict[str, str] = {}
    for fq in kandidaten:
        keys = [f"shot:{fq.screenshot_key}"] + ([k] if (k := _same_page_key(fq)) else [])
        ziel = next((alias[k] for k in keys if k in alias), keys[0])
        for k in keys:
            alias.setdefault(k, ziel)
        groups.setdefault(ziel, []).append(fq)
    out: list[Screenshot] = []
    for members in groups.values():
        members.sort(key=rang)
        fq = members[0]
        out.append(Screenshot(
            file=fq.screenshot_key.rsplit("/", 1)[-1],
            key=fq.screenshot_key,
            host=fq.name,
            what=clean_foreign_text(fq.title) or f"Antwort von {fq.name}",
            also=sorted({m.name for m in members[1:]} - {fq.name}, key=sort_key)))
    return sorted(out, key=lambda s: s.host)


REPUTATION_SOURCES = ["AbuseIPDB", "OTX", "URLhaus"]


def build_architecture(facts: FS.Facts, output: CatalogOutput, items: list[Consolidated],
                       findings: list[Finding], model: COV.Model | None = None) -> Architecture:
    model = model or COV.build_model(facts)
    roles = sorted({r.label for members in _systems(facts) for r in system_roles(facts, members)})
    eigene = [h for h in facts.hosts if h.third_party is None]
    # S6b-2 (spec/09 Q12): Adressen von Plattformen und Inhaltsnetzen werden nicht bewertet,
    # sondern benannt. Score 0 heisst nicht "keine Meldungen": eine Adresse auf der
    # Freigabeliste von AbuseIPDB hat Score 0 trotz Meldungen (Vercel bei heuel, 26).
    fremd = [h for h in eigene if h.cdn_provider or (h.shared is not None and h.shared.kind == "platform")]
    bewertet = [h for h in eigene if h not in fremd]
    clean = not any(
        (h.reputation and (
            (h.reputation.abuseipdb_score or 0) >= CT.ABUSEIPDB_FAIL_SCORE
            or (h.reputation.abuseipdb_total_reports or 0) > 0
            or (h.reputation.otx_pulse_count or 0) > 0
            or h.reputation.urlhaus_compromised))
        for h in bewertet)
    notes: list[str] = []
    counter = Counter(u.kind for u in output.unprocessed)
    if counter:
        total = sum(u.count for u in output.unprocessed)
        # S6 (spec/08 Punkte 11 und 19): Singular bei 1, und der Satz sagt in
        # Kundensprache, was mit der Beobachtung geschieht, statt "intern zur
        # Nachbearbeitung vorgemerkt".
        wort = "Beobachtung" if total == 1 else "Beobachtungen"
        hat = "hat" if total == 1 else "haben"
        notes.append(
            f"{total} {wort} der Werkzeuge {hat} keine Regel des Prüfkatalogs "
            "getroffen. Sie erscheinen nicht als Befund; wir prüfen sie und nehmen "
            "wiederkehrende Fälle in den Katalog auf.")
    for wert in sorted(_unbeauftragt(facts, output)):
        notes.append(f"Sichtbar, aber nicht beauftragt: {wert}.")
    # facts.warnings sind Hinweise des Faktenbauers an den Betreiber, keine Kundentexte.
    # Was davon den Kunden betrifft, steht ueber die Abdeckungsgruende in Kapitel 2.
    return Architecture(
        # S6b-2 (Nachtrag S6b-1): Kapitel 3 zaehlt in Systemen wie Kapitel 2.1.
        lead=N.architecture_lead(len(model.system_rows()), roles),
        tech=build_tech(facts),
        services=build_services(facts, items, findings),
        services_note=N.SERVICES_NOTE,
        posture=build_posture(output, model, facts),
        screens_lead=N.SCREENS_LEAD,
        screens=build_screens(facts),
        reputation=N.reputation_line(clean, REPUTATION_SOURCES,
                                     sorted((h.ip for h in fremd), key=sort_key)),
        notes=notes,
    )


__all__ = ["format_date", "format_window", "today", "coverage_model", "hosts_ohne_leitwerkzeug",
           "blockade_belegt", "limitations", "build_glance", "overall_text", "build_business",
           "observed_systems", "system_roles", "host_roles", "host_role", "build_scope", "tech_lines",
           "build_tech", "finding_ports", "passive_service_label", "build_services", "build_posture",
           "build_screens", "build_architecture", "dkim_selectors_for_appendix"]

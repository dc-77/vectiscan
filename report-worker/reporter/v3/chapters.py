# -*- coding: utf-8 -*-
"""Kapitel 1 bis 3 des Reports aus Fakten und Prüfergebnis.

Alles hier ist abgeleitet, nichts geschätzt: Zahlen kommen aus ``facts``, Status aus dem
Katalogergebnis, Texte aus ``narrative.py``. Ein Wert, den die Fakten nicht hergeben,
wird als unbekannt ausgewiesen und nicht geraten.

S6b-1: Abdeckung und Einschränkungen stehen in ``coverage.py``, Rollen in ``roles.py``.
"""
from __future__ import annotations

import re

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


def iso_date(value: Optional[str]) -> Optional[str]:
    """Berichtsdatum TT.MM.JJJJ als JJJJ-MM-TT fuer die Katalogauswertung (spec/10 R18)."""
    if not value:
        return None
    m = re.fullmatch(r"(\d{2})\.(\d{2})\.(\d{4})", value.strip())
    if m:
        return f"{m.group(3)}-{m.group(2)}-{m.group(1)}"
    return value[:10] if re.match(r"\d{4}-\d{2}-\d{2}", value) else None


def report_day(approved_at: Optional[str | datetime] = None, now: Optional[datetime] = None) -> str:
    """Berichtsdatum TT.MM.JJJJ nach E15 (spec/11 T5).

    Das Datum der Freigabe (``orders.reviewed_at``) in Europe/Berlin, ohne Freigabe der Tag der
    Erzeugung in Europe/Berlin. Vorher galt der UTC-Tag: eine Erzeugung um 01:11 Uhr Ortszeit trug
    noch das Datum des Vortags.
    """
    override = os.environ.get("VECTISCAN_REPORT_DATE")
    if override:
        return override
    moment: Optional[datetime | str] = approved_at or now or datetime.now(timezone.utc)
    if isinstance(moment, datetime):
        moment = (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).isoformat()
    local, _zone = _local(moment)
    if local is None:
        local, _zone = _local(datetime.now(timezone.utc).isoformat())
    return f"{local:%d.%m.%Y}"


def today() -> str:
    return report_day()


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


def passive_only_findings(facts: FS.Facts, findings: list[Finding] | None) -> list[str]:
    """Befunde, deren Subjekte alle auf Hosts liegen, die vom Pruefstand aus nicht erreichbar sind
    (E4); sie beruhen allein auf der Passivquelle (spec/11 N13, bergersysteme VS-004, -006, -012)."""
    e4 = {h.ip for h in facts.hosts if h.reach is not None and h.reach.status == "unreachable_from_scanner"}
    out: list[str] = []
    for f in findings or []:
        ips = set()
        for eintrag in f.subjects or []:
            sub = eintrag.partition("|")[2]
            v4 = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", sub)
            ips.add(sub.rsplit("@", 1)[1] if "@" in sub else (v4.group(0) if v4 else sub))
        if ips and ips <= e4:
            out.append(f.id)
    return out


def limitations(facts: FS.Facts, output: CatalogOutput,
                model: COV.Model | None = None, findings: list[Finding] | None = None) -> list[Limitation]:
    """Einschraenkungen: eine Zeile je Ursache mit Pruefungsnamen (spec/09 Q10)."""
    model = model or COV.build_model(facts)
    zusatz: list[str] = []

    def dkim(result: CheckResult) -> str:
        probed = dkim_probed(facts, str(result.vars.get("domain") or result.group_key))
        text = dkim_limitation_detail(probed) if probed else DKIM_DETAIL_ALLGEMEIN
        if text not in zusatz:
            zusatz.append(text)
        return DKIM_WHAT

    rows = COV.limitations(facts, output, model, dkim_text=dkim,
                           passive_ids=passive_only_findings(facts, findings))
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

def patch_bewertbar(facts: FS.Facts | None) -> bool:
    """Liegt zu mindestens einer erkannten Software eine Version mit Lebenszyklusquelle vor?

    S6b-3 (spec/10 R6): ohne eine solche Angabe ist Kategorie B nicht bewertbar (grau), nicht
    "GRÜN, keine Befunde"; ein unbekannter Patchstand ist kein guter Patchstand."""
    if facts is None:
        return True
    eigene = {h.ip for h in facts.hosts if h.third_party is None}
    return any(sw.host_ip in eigene and sw.eol.status in ("eol", "supported") and sw.eol.source
               for sw in facts.software)


# S6b-4n (spec/11 N6): Kategorien, deren Ampel eine Messung ihrer Faktenfamilie braucht, und die
# Pruefungen, die dann "nicht moeglich" waren.
MEASURED_CATEGORIES: dict[str, str] = {
    "C": "Prüfung der E-Mail-Authentizität",
    "D": "Prüfung von Transportverschlüsselung und Sicherheits-Headern",
}


def category_measured(output: CatalogOutput | None, key: str) -> bool:
    """Hat mindestens eine Regel der Kategorie gemessen (fehlgeschlagen oder Positivbedingung
    getroffen) und gehoert zu einer Faktenfamilie? Ohne Katalogausgabe gilt ja."""
    if output is None:
        return True
    from reporter.catalog.families import family_of
    return any(r.category == key and r.kind == "check" and family_of(r.check_id)
               and (r.status == "fail" or r.affirmed) for r in output.results)


def build_glance(items: list[Consolidated], findings: list[Finding], counts: N.Counts,
                 gap_systems: list[list[str]], facts: FS.Facts | None = None,
                 output: CatalogOutput | None = None) -> Glance:
    by_cat: dict[str, list[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.cat, []).append(f)
    categories: list[GlanceCategory] = []
    for key in ("A", "B", "C", "D", "E"):
        group = sorted(by_cat.get(key, []), key=lambda f: L.STATUS_RANK[f.status])
        status = group[0].status if group else "gruen"
        note = "; ".join(f.title for f in group[:2]) if group else "Keine Befunde in dieser Kategorie"
        if key == "B" and not group and not patch_bewertbar(facts):
            status = "grau"
            note = ("Nicht bewertbar: zu keiner erkannten Serversoftware liegt eine Version mit "
                    "Lebenszyklusangabe vor")
        elif key in MEASURED_CATEGORIES and not group and not category_measured(output, key):
            # S6b-4n (spec/11 N6): lumbeck-wolter Kategorie D war "GRÜN, 0 Befunde", obwohl weder
            # TLS noch Header gemessen werden konnten.
            status = "grau"
            note = f"Nicht bewertbar: {MEASURED_CATEGORIES[key]} nicht möglich, siehe 2.2"
        categories.append(GlanceCategory(
            key=key, name=CATEGORY_NAMES[key], status=status,
            level=L.BAR_BY_STATUS[status], note=note))
    overall_status = min((c.status for c in categories), key=lambda s: L.STATUS_RANK[s])
    farben = {c.status for c in categories} | {f.status for f in findings}
    gelb_kurz = any(f.status == "gelb" and f.urgency == L.URGENCY_BY_STAGE["in_kuerze"] for f in findings)
    return Glance(
        overall=L.OVERALL_BY_STATUS[overall_status],
        overall_status=overall_status,
        overall_text=overall_text(findings),
        categories=categories,
        levers=[],
        context=N.context(counts),
        coverage_warning=N.coverage_warning(counts, gap_systems),
        legend=N.glance_legend(farben, gelb_kurz),
    )


# Wie eine Kategorie im Gesamtbewertungstext benannt wird. Die Namen aus
# CATEGORY_NAMES sind Ueberschriften ("Patch- und EOL-Status") und lesen sich im
# Fliesstext nicht; hier steht die Satzform.
CATEGORY_IN_SENTENCE: dict[str, str] = {
    "A": "die aus dem Internet erreichbaren Dienste",
    "B": "den Softwarestand der erkannten Systeme",
    "C": "die Authentizität der E-Mail",
    "D": "die Transportverschlüsselung und die Sicherheits-Header",
    "E": "die Konfiguration",
}
# S6b-4 (spec/11 T10): "preisgegebene Angaben" nur, wenn eine Regel zu Offenlegung getroffen
# hat (LW, HL und BS hatten in Kategorie E nur CAA, DNSSEC oder VRFY).
DISCLOSURE_CHECKS = frozenset({"directory_listing", "http_header_disclosure", "info_disclosure",
                               "service_banner_version", "wordpress_user_enumeration"})
CATEGORY_E_DISCLOSURE = "die Konfiguration und die preisgegebenen Angaben"


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
    if any(f.cat == "E" and DISCLOSURE_CHECKS & set(f.checks) for f in (rest or findings)):
        namen = [CATEGORY_E_DISCLOSURE if n == CATEGORY_IN_SENTENCE["E"] else n for n in namen]
    if not namen:
        return head
    wort = "Die übrigen Befunde betreffen" if red else "Die Befunde betreffen"
    return f"{head} {wort} {_aufzaehlung(namen)}."


def build_business(facts: FS.Facts, observed: list[ObservedSystem]) -> Business:
    formen = sorted({h.betriebsform for h in facts.hosts if h.third_party is None and h.betriebsform})
    return Business(lead=N.BUSINESS_LEAD, observed=observed,
                    implication=N.business_implication(formen), betriebsformen=formen)


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
    # S6b-4n (spec/11 N11): Betreiber des Servers laut rDNS und Standardzertifikat und die Quelle,
    # die das Teilen belegt (castenow .80: "Server von planwerk6.de, laut Passivquelle geteilt").
    if host.shared.server_operator:
        quelle = ("Passivquelle" if "fremde_namen_shodan" in host.shared.signals else "Zertifikat")
        return f"Server von {host.shared.server_operator}, laut {quelle} geteilt"
    return "geteiltes System beim Hoster"


# ---------------------------------------------------------------- Kapitel 2

def _domain_scope(facts: FS.Facts, domains: list[tuple[str, str]]) -> list[DomainScope]:
    eintraege = [DomainScope(domain=d, text=t, search=COV.host_search(facts, d)) for d, t in domains]
    if len(eintraege) > 1 or any(e.search for e in eintraege):
        return eintraege
    return []


def build_scope(facts: FS.Facts, output: CatalogOutput, counts: N.Counts,
                model: COV.Model, findings: list[Finding] | None = None) -> Scope:
    hosts: list[ScopeHost] = []
    for members in _systems(facts):
        lead = members[0]
        cov = model.hosts[lead.ip]
        text = cov.text
        # S6b-4 (spec/11 T7): AAAA-Adressen derselben Namen ohne Inventareintrag gehoeren dazu.
        zusatz = [a.ip for h in members for a in h.additional_ips if a.ip in model.hosts]
        more = [h.ip for h in members[1:]] + zusatz
        for ip in [h.ip for h in members[1:]] + zusatz:
            extra = model.hosts[ip]
            if extra.cov != cov.cov or extra.text != cov.text:
                text = f"{text} {ip}: {extra.text}"
        status = model.system_status([h.ip for h in members] + zusatz)
        # S6b-4 (spec/11 T2, E17): Netzbetreiber laut AbuseIPDB in heutiger Firmierung, mit
        # Anschlussbetreiber oder Plattform.
        operator = SYS.network_operator_label(
            lead.provider, platform=bool(lead.cdn_provider or (lead.shared and lead.shared.kind == "platform")),
            customer_domains=list(facts.scan.domains) or [facts.scan.domain]) or UNKNOWN
        # S6d (A1, E17): Quelle je Zeile (RIR laut RDAP oder AbuseIPDB); der Kopf nennt sie, wenn
        # alle Zeilen dieselbe haben, sonst steht sie in der Zelle.
        quelle = SYS.network_operator_source(lead.provider) if operator != UNKNOWN else ""
        if lead.reverse:
            operator = f"{operator} ({lead.reverse})"
        roles = R.role_label(system_roles(facts, members))
        hint = _shared_hint(lead)
        # S6b-2 (spec/09 Teil 2 DB, Rest spec/08 Punkt 13): ein Wildcard-Eintrag ist kein
        # Hostname; die Zaehlung in 2.1 liess ihn schon aus, die Liste nannte ihn noch.
        names = sorted({n for h in members for n in h.fqdns if not n.startswith("*.")}, key=sort_key)
        hosts.append(ScopeHost(
            ip=lead.ip, more_ips=more, fqdns=", ".join(names) or UNKNOWN,
            operator=operator, operator_source=quelle or "", role=f"{roles} · {hint}" if hint else roles,
            coverage=text, cov=status))
    quellen = {h.operator_source for h in hosts if h.operator_source}
    operator_header = "Netzbetreiber (laut AbuseIPDB)"
    if len(quellen) == 1:
        operator_header = f"Netzbetreiber (laut {next(iter(quellen))})"
    elif len(quellen) > 1:
        operator_header = "Netzbetreiber"
        for h in hosts:
            if h.operator_source:
                h.operator = f"{h.operator}, laut {h.operator_source}"
    for host in sorted((h for h in facts.hosts if h.third_party is not None), key=lambda h: sort_key(h.ip)):
        operator = host.third_party.operator or UNKNOWN
        hosts.append(ScopeHost(
            ip=host.ip, fqdns=", ".join(sorted((n for n in host.fqdns if not n.startswith("*.")),
                                               key=sort_key)) or UNKNOWN,
            operator=operator, role="Drittanbieter", coverage=model.hosts[host.ip].text, cov="extern"))
    # S6b-3 (spec/10 R5): gefundene Namen eines Drittanbieters (Microsoft 365 Autodiscover),
    # die nicht ins Inventar kamen, stehen als "Drittanbieter, nicht geprüft".
    # S6b-4n (spec/11 N11): die Zuordnung stammt aus Namensaufloesung (und SPF), nicht aus AbuseIPDB;
    # die Zeile sagt das in der Betreiberspalte.
    spf_ms = any(m.kind == "include" and "outlook.com" in (m.value or "")
                 for d_ in facts.dns if d_.spf for m in d_.spf.mechanisms)
    for target in facts.targets:
        for d in target.discovered:
            if d.third_party and d.ips:
                quelle = "laut Namensauflösung und SPF" if spf_ms and "microsoft" in d.third_party.lower() \
                    else "laut Namensauflösung"
                hosts.append(ScopeHost(ip=d.ips[0], more_ips=[], fqdns=d.fqdn,
                                       operator=f"{d.third_party} ({quelle})",
                                       role="Drittanbieter", coverage="Drittanbieter, nicht geprüft",
                                       cov="extern"))
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
        operator_header=operator_header,
        # S7a Punkt 7: je Zieldomain die Hostsuche, auch bei Einzelzielen; ohne Hostsuche-Angabe
        # (Auftraege vor S6c) weiter nur bei mehreren Zieldomains.
        domains=_domain_scope(facts, domains),
        out_of_scope=out_of_scope,
        limitations=limitations(facts, output, model, findings),
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
    # S6b-4 (spec/11 T11, T15): Langzeitpflege mit Quelle, Erweiterung laut wpscan veraltet.
    # S6b-4n (spec/11 N9): die Plakette sagt nur "LTS"; Datum und Quelle stehen im Hinweis.
    "lts": ("LTS", "gruen"),
    "outdated": ("veraltet", "gelb"),
    # S7a (spec/11 N9): Plakette nur "veraltet" oder "LTS"; ein Kern mit bekannten Luecken ist
    # veraltet wie eine Erweiterung laut wpscan (gelb), die Luecken stehen im Hinweis.
    "insecure": ("veraltet", "gelb"),
}

# S6b-4 (spec/11 T15): Slug und Anzeigename derselben Komponente in einer Zeile (DB: Slider
# Revolution aus httpx, webtech und wpscan; BeTheme aus httpx und wpscan; BS: Cloudflare aus nmap
# und httpx). Schluessel ist die Softwarefamilie, Wert (gemeinsame Familie, Anzeigename).
TECH_ALIASES: dict[str, tuple[str, str]] = {
    "revslider": ("slider_revolution", "Slider Revolution"),
    "slider_revolution": ("slider_revolution", "Slider Revolution"),
    "powered_by_slider_revolution": ("slider_revolution", "Slider Revolution"),
    "betheme": ("betheme", "BeTheme"),
    # S6b-4n (spec/11 N9): das Kindtheme ist eine eigene Zeile, mit Anzeigename statt Slug.
    "betheme_child": ("betheme_child", "BeTheme Child"),
    "burst": ("burst_statistics", "Burst Statistics"),
    "burst_statistics": ("burst_statistics", "Burst Statistics"),
    "complianz": ("complianz", "Complianz"),
    "complianz_gdpr": ("complianz", "Complianz"),
    "ultimate_member": ("ultimate_member", "Ultimate Member"),
    "cloudflare": ("cloudflare", "Cloudflare"),
    "cloudflare_http_proxy": ("cloudflare", "Cloudflare"),
    # S6b-4n (spec/11 N12, N15): Neos aus CMS-Erkennung und httpx eine Zeile (heuel); ProFTPD und
    # sein SFTP-Modul eine Zeile (lumbeck-wolter).
    "neos": ("neos", "Neos"),
    "neos_cms": ("neos", "Neos"),
    "neos_flow": ("neos", "Neos"),
    "proftpd": ("proftpd", "ProFTPD"),
    "proftpd_mod_sftp": ("proftpd", "ProFTPD"),
    "proftpd_sftp": ("proftpd", "ProFTPD"),
}
# Dienste eines Anbieters, die nur eingebunden sind und nicht auf dem System laufen (huendgen:
# Cookiebot als "CMS-Plugin"). S6b-4n (spec/11 N15): Etracker ebenso.
TECH_HIDDEN = frozenset({"cookiebot", "etracker"})
# S6b-4n (spec/11 N12): Sitzungs-Cookies, die eine Technik als zweite Quelle bestaetigen.
COOKIE_TECH: dict[str, tuple[str, ...]] = {
    "jsessionid": ("java",),
    "phpsessid": ("php",),
    "asp.net_sessionid": ("asp",),
    "aspsessionid": ("asp",),
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
    # S6b-4 (spec/11 T11, T15): Patch-Status fuer Bericht und Dashboard (Schluessel in
    # ``_EOL_STATUS``) und sein Text, wenn er mehr sagt als der Schluessel ("veraltet, 12
    # bekannte Lücken, aktuell 28.5.10").
    patch: str = "unknown"
    status_text: str = ""


def _ohne_eigene_tabelle(host: FS.HostFact) -> bool:
    """Drittanbieter und IPv6 ohne Route bekommen keine Technologietabelle: ihre
    Eintraege stammen nicht aus einer Messung an dieser Adresse (spec/09 Q16)."""
    return host.third_party is not None or bool(host.reach and host.reach.status == "no_ipv6_route")


# Technikzeile oder Anhang (Entscheidung DC 26.09., ersetzt die Schwelle vom 25.09.):
# (a) eine Messung von nmap oder testssl steht in der Tabelle, auch ohne Version
#     (PostgreSQL "or later" ohne Version und ohne EOL, S6a2-Regel);
# (b) httpx- und webtech-Eintraege stehen dort mit einer Version aus dem Werkzeugbeleg
#     (Header, Skriptpfad, Banner) oder wenn eine zweite Quelle sie bestaetigt
#     (cms_fingerprint, wpscan, nmap, header_check); cms_fingerprint und wpscan pruefen die
#     Anwendung gezielt und zaehlen deshalb auch allein ("NEOS" aus cms_fingerprint bei heuel);
# (c) ein Eintrag ohne Version aus nur einer Quelle steht im Anhang ("Java/Servlet" aus
#     webtech und "Neos Flow" aus httpx bei heuel).
# Vorher (25.09.): Konfidenz ab 0,9 oder zwei Quellen; damit fielen jQuery Migrate 3.4.1,
# PHP mit Version und PostgreSQL aus der Tabelle.
TECH_MEASURED = frozenset({"nmap", "testssl", "cms_fingerprint", "wpscan"})


def _tech_quellen(gruppe: list[FS.SoftwareFact]) -> set[str]:
    return {q for s in gruppe for q in s.detection_sources} | {s.source for s in gruppe}


# Eine Ziffernfolge ohne Punkt ab sechs Stellen ist kein Versionsstand, sondern ein
# Zeitstempel aus dem Skriptpfad ("bootstrap.css?ver=1771057841", securess ae8d1d70).
_CACHE_BUSTER = re.compile(r"\d{6,}")


def _versionsangabe(sw: FS.SoftwareFact) -> bool:
    v = sw.version_norm or ""
    return bool(v) and not _CACHE_BUSTER.fullmatch(v)


def _tech_bestaetigt(gruppe: list[FS.SoftwareFact], cookies: set[str] | None = None) -> bool:
    quellen = _tech_quellen(gruppe)
    if quellen & TECH_MEASURED:
        return True
    # S6b-4n (spec/11 N12): ein Sitzungs-Cookie derselben Technik am selben Host ist eine zweite
    # Quelle (heuel JSESSIONID, castenow PHPSESSID).
    if cookies and any(any(t in s.family for c in cookies for t in COOKIE_TECH.get(c, ())) for s in gruppe):
        return True
    return any(_versionsangabe(s) for s in gruppe) or len(quellen) >= 2


def _canon(sw: FS.SoftwareFact) -> str:
    return TECH_ALIASES[sw.family][0] if sw.family in TECH_ALIASES else sw.family


def _wp_core_status(facts: FS.Facts, sw: FS.SoftwareFact) -> Optional[str]:
    """Status des WordPress-Kerns laut wpscan (``latest``, ``outdated``, ``insecure``)."""
    for h in facts.http:
        wp = h.wordpress
        if h.host_ip == sw.host_ip and wp is not None and wp.version_status \
                and (not sw.version_norm or wp.version == sw.version_norm):
            return wp.version_status
    return None


def _patch_status(facts: FS.Facts, gruppe: list[FS.SoftwareFact],
                  sw: FS.SoftwareFact) -> tuple[str, str, str]:
    """(Schluessel, Statustext, Hinweis) je Zeile (S6b-4, spec/11 T11, T15).

    Reihenfolge: Ende der Herstellerpflege mit Quelle; wpscan zur Erweiterung (``outdated``,
    Zahl der Schwachstellen, aktuelle Version) oder zum Kern (``status``); Langzeitpflege mit
    Quelle; Pflege mit Quelle. Ein Herstellerdatum ohne Beleg steht nicht mehr da ("Lifecycle
    prüfen, Hersteller nennt 16.07.2024" bei WordPress 6.5.12, das wpscan als veraltet meldet).
    """
    from reporter.catalog.render import lifecycle_text, version_parts, wpscan_directory_stale

    if sw.eol.status == "eol" and sw.eol.date:
        quelle = str(sw.eol.source or "").split(",")[0].strip()
        return "eol", "", f"Herstellerpflege endete am {_datum_de(sw.eol.date)}" + (f" laut {quelle}" if quelle else "")
    kind = next((s for s in gruppe if getattr(s, "child_of", None) and not s.latest_version), None)
    if kind is not None:
        # S6b-4n (spec/11 N9): ein eigenes Kindtheme hat keine Version im Verzeichnis; sein Stand
        # folgt dem Elterntheme (dortmund-beach betheme-child).
        return "unknown", "", f"nicht bestimmbar (eigenes Kindtheme, Elterntheme {kind.child_of})"
    wp = next((s for s in gruppe if "wpscan" in s.detection_sources and s.outdated is not None), None)
    if wp is not None:
        # S6b-4n (spec/11 N9): die Plakette sagt "veraltet"; Anzahl, Fehlerbereinigung und neueste
        # Version stehen im Hinweis, getrennt ("fehlerbereinigt ab 6.7.38", "neueste laut wpscan 6.7.35").
        teile: list[str] = []
        n = len(wp.vulnerabilities or [])
        if n:
            teile.append(f"{n} bekannte {'Lücke' if n == 1 else 'Lücken'}")
        teile.extend(version_parts(wp))
        if wpscan_directory_stale(wp):
            teile.append("Verzeichnis von wpscan veraltet")
        if wp.outdated:
            return "outdated", "", ", ".join(teile) or "laut wpscan"
        if wpscan_directory_stale(wp):
            return "unknown", "", ", ".join(teile)
        return "supported", "aktuell", "laut wpscan"
    if sw.family == "wordpress":
        status = _wp_core_status(facts, sw)
        if status == "latest":
            return "supported", "aktuell", "Kernversion laut wpscan"
        if status == "outdated":
            return "outdated", "veraltet", "Kernversion laut wpscan"
        if status == "insecure":
            return "insecure", "veraltet", "Kernversion mit bekannten Lücken laut wpscan"
    if sw.eol.status == "supported":
        if getattr(sw.eol, "lts_since", None) and sw.eol.date:
            quelle = str(sw.eol.source or "").split(",")[0].strip().replace(" LTS", "")
            return "lts", "", f"in Langzeitpflege bis {_datum_de(sw.eol.date)}" + (f" laut {quelle}" if quelle else "")
        # Kategorie B gruen nur mit sichtbarer Quelle (spec/11 T11).
        return ("supported", "", lifecycle_text(sw.eol) or "") if sw.eol.source else ("unknown", "", "")
    return "unknown", "", ""


def tech_lines(facts: FS.Facts, *, unconfirmed: list[TechLine] | None = None) -> dict[str, list[TechLine]]:
    """Zeilen je Host-IP in Berichtsreihenfolge; Hosts ohne Software fehlen.

    ``unconfirmed`` sammelt die Zeilen ohne Version und ohne bestaetigende Messung
    (``_tech_bestaetigt``); sie gehen als Werkzeugmeldung in den Anhang.

    S6b-4 (spec/11 T15): eine Zeile je Produkt ueber ``TECH_ALIASES`` (wpscan-Version hat
    Vorrang), Patch-Status aus wpscan, keine Dienste weiterer Domains (castenow Icecast) und
    keine nur eingebundenen Anbieterdienste (``TECH_HIDDEN``).
    """
    from reporter.catalog.scope import without_third_party

    facts = without_third_party(facts)
    cookies: dict[str, set[str]] = {}
    gemessen_an: dict[tuple[str, str], str] = {}
    for h in facts.http:
        for c in h.cookies:
            cookies.setdefault(h.host_ip, set()).add(c.name.lower())
        if h.fqdn and h.measured_ip:
            gemessen_an[(h.host_ip, h.fqdn)] = h.measured_ip
    systeme = {ip: set(ips) for ip, ips in SYS.system_of(facts.hosts).items()}
    by_host: dict[str, list[FS.SoftwareFact]] = {}
    for sw in facts.software:
        if sw.family in TECH_HIDDEN:
            continue
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
        mit_version = {_canon(s) for s in entries if s.version_norm}
        exponiert = {svc.product for svc in facts.services
                     if svc.host_ip == host.ip and svc.product and "http" not in (svc.service or "")}
        # Derselbe Name in anderer Schreibweise ist dieselbe Komponente ("cloudflare"
        # aus nmap, "Cloudflare" aus httpx): eine Zeile, Quellen zusammengefuehrt.
        gruppen: dict[tuple[str, str], list[FS.SoftwareFact]] = {}
        for sw in entries:
            if not sw.version_norm and _canon(sw) in mit_version:
                continue
            key = ((f"alias:{_canon(sw)}", "") if sw.family in TECH_ALIASES
                   else (sw.product.lower(), _tech_version(sw)))
            gruppen.setdefault(key, []).append(sw)
        lines: list[TechLine] = []
        for (_, version), gruppe in gruppen.items():
            alias = TECH_ALIASES.get(gruppe[0].family)
            if alias is not None:
                # wpscan prueft die Erweiterung gezielt; seine Version gilt vor httpx und webtech.
                sw = max(gruppe, key=lambda s: ("wpscan" in s.detection_sources, bool(s.version_norm),
                                                s.confidence))
                version = _tech_version(sw)
                product = alias[1]
            else:
                sw = max(gruppe, key=lambda s: (s.confidence, s.product != s.product.lower()))
                product = sw.product
            bestaetigt = _tech_bestaetigt(gruppe, cookies.get(host.ip))
            quellen = sorted({q for s in gruppe for q in s.detection_sources}) or [sw.source]
            patch, status_text, lebenszyklus = _patch_status(facts, gruppe, sw)
            note = T.tech_note(sw.note)
            if lebenszyklus:
                note = lebenszyklus if not note else f"{lebenszyklus}; {note}"
            elif (not sw.version_norm and sw.kind in VERSION_AT_OPERATOR_KINDS
                  and "nmap" in sw.detection_sources and sw.product in exponiert):
                # S6b-3 (spec/10 R19, E14): Herstellerprodukt ohne Version an einem
                # Nicht-Web-Port (heuel Wing FTP 20.79.218.75:21).
                note = "Version beim Betreiber prüfen"
            # S6b-4n (spec/11 N5): httpx hat den Namen an einer anderen Adresse gemessen (huendgen:
            # die Technikzeilen unter .23 stammen aus der Messung an 52.59.120.70).
            orte = sorted({ip_ for s in gruppe if s.fqdn and "httpx" in s.detection_sources
                           and (ip_ := gemessen_an.get((s.host_ip, s.fqdn)))
                           and ip_ not in systeme.get(s.host_ip, {s.host_ip})}, key=sort_key)
            if orte and not (_tech_quellen(gruppe) & TECH_MEASURED):
                note = (note + "; " if note else "") + f"gemessen an {', '.join(orte)}"
            conf = sw.confidence
            conflicts = [c for s in gruppe for c in s.conflicts]
            if conflicts:
                # S6b-3 (spec/10 R19): eine Passivquelle nennt am selben Port ein anderes Produkt.
                conf = min(conf, 0.7)
                note = (note + "; " if note else "") + "Passivquelle widerspricht: " + conflicts[0]
            line = TechLine(
                software=sw, product=product, version=version, eol_status=sw.eol.status,
                eol_date=sw.eol.date, note=note, sources=", ".join(quellen),
                confidence=conf, conf_label=_confidence_label(conf),
                patch=patch, status_text=status_text)
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
        was = (line.product if line.version == UNKNOWN or not _versionsangabe(line.software)
               else f"{line.product} {line.version}")
        out.append(ToolFinding(
            what=f"Technik „{was}“", where=line.software.fqdn or line.software.host_ip,
            note=(f"Nur laut {line.sources}, ohne Version und ohne zweite Quelle; nicht in der "
                  "Technologietabelle."),
            rule="technik", message=was))
    return out


# Produkte ohne eigene Softwarefamilie (Herstellerprodukte); Open-Source-Daemons (Dovecot,
# Postfix, ProFTPD) ohne Version bekommen den Satz nicht, sie stehen fast nur beim Hoster.
VERSION_AT_OPERATOR_KINDS = frozenset({"component", "control_panel"})


def _datum_de(iso: Optional[str]) -> str:
    """Deutsches Datum im Kundentext (spec/10 R14)."""
    if not iso or len(iso) < 10 or iso[4] != "-":
        return iso or ""
    return f"{iso[8:10]}.{iso[5:7]}.{iso[:4]}"


def service_display(svc: FS.ServiceFact) -> str:
    """Name eines Dienstes in Service-Karte und Anhang B (spec/10 R9, R14): MariaDB statt
    "MySQL" beim Kompatibilitaetsbanner, die Kennung statt eines geratenen nmap-Portnamens.

    S6b-4 (spec/11 T1): "nicht identifiziert (Port n)" nur mit dem Kennzeichen, an dem die Regel
    ``service_unidentified`` haengt; die Kennung aus Protokollskript, Banner, Zertifikat oder
    Passivquelle ("IMAP über TLS (Dovecot)") geht vor. Dieselbe Bedingung wie
    ``render.kennung_label`` und der Nachweis."""
    if svc.family == "mariadb":
        return f"MariaDB {svc.version_norm}".strip() if svc.version_norm else "MariaDB"
    if svc.unidentified:
        return f"nicht identifiziert (Port {svc.port})"
    if svc.product:
        return svc.product
    if svc.kennung:
        return svc.kennung
    # S6b-4n (spec/11 N15): Portnamen, die nmap ohne Kennung fuehrt, in Kundensprache.
    return SERVICE_NAMES.get((svc.service or "").lower()) or (svc.service or "").upper() or UNKNOWN


# S6b-4n (spec/11 N15): "53 DOMAIN" und "106 TCPWRAPPED" stehen als DNS und "Dienst ohne Antwort".
SERVICE_NAMES: dict[str, str] = {"domain": "DNS", "tcpwrapped": "Dienst ohne Antwort"}


def port_outside_range(facts: FS.Facts, port: Optional[int]) -> bool:
    """Lag der Port ausserhalb des Portbereichs des Portscans (spec/11 T1)?"""
    from reporter.facts.nmap_parse import in_port_range

    if port is None or facts.scan is None:
        return False
    return in_port_range(facts.scan.scanned_ports, int(port)) is False


def _tech_version(sw: FS.SoftwareFact) -> str:
    version = sw.version_norm or UNKNOWN
    if sw.build:
        return f"{version} (Build {sw.build})"
    if sw.distro:
        return f"{version} ({sw.distro})"
    return version


def _parent_finding(findings: list[Finding] | None, slug: str) -> str:
    """Befund zum Elterntheme eines Kindthemes ("siehe VS-2026-004", spec/11 N9)."""
    from reporter.catalog.tables import PRODUCT_NAMES
    name = PRODUCT_NAMES.get(slug.replace("-", "_"), slug)
    for f in findings or []:
        if "wordpress_plugin_vulnerable" in (f.checks or []) and \
                re.search(rf"\b{re.escape(name)}\b", f.affected or "", re.I):
            return f.id
    return ""


def build_tech(facts: FS.Facts, findings: list[Finding] | None = None) -> list[TechBlock]:
    hosts = {h.ip: h for h in facts.hosts}
    blocks: list[TechBlock] = []
    for ip, lines in tech_lines(facts).items():
        host = hosts[ip]
        rows: list[TechRow] = []
        for line in lines:
            status, colour = _EOL_STATUS.get(line.patch, (UNKNOWN, "grau"))
            status = line.status_text or status
            note = line.note
            eltern = getattr(line.software, "child_of", None)
            if eltern and note.startswith("nicht bestimmbar (eigenes Kindtheme"):
                fid = _parent_finding(findings, eltern)
                from reporter.catalog.tables import PRODUCT_NAMES
                name = PRODUCT_NAMES.get(eltern.replace("-", "_"), eltern)
                note = f"nicht bestimmbar (eigenes Kindtheme, Elterntheme {name}" + (f", siehe {fid})" if fid else ")")
            rows.append(TechRow(c=line.product, v=line.version, src=line.sources, conf=line.conf_label,
                                status=status, st=colour, note=note))
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
    """Befunde je (Host, Port), eine Zuordnung fuer Service-Karte und Anhang B.

    S6b-4 (spec/11 T16): ein Mitglied auf Hostebene aus einer Softwareerkennung steht am Port
    seines Belegs (dortmund-beach Debian 11 aus dem OpenSSH-Banner an 30000)."""
    software_ports: dict[str, list[int]] = {}
    for sw in facts.software:
        ports = sorted({int(m.group(1)) for e in sw.evidence
                        for m in [re.match(r"(\d+)/(?:tcp|udp)\b", e.excerpt or "")] if m})
        if ports:
            software_ports[sw.id] = ports
    out: dict[tuple[str, int], list[Finding]] = {}
    for item, finding in zip(items, findings):
        for result in item.results:
            for member in result.members:
                if member.status != "fail" or member.host_ip is None:
                    continue
                port = _member_port(facts, member.host_ip, member.fqdn, member.port)
                ports = [port] if port is not None else software_ports.get(member.key, [])
                for p in ports:
                    bucket = out.setdefault((member.host_ip, p), [])
                    if finding not in bucket:
                        bucket.append(finding)
    return out


def passive_service_label(pv: FS.PassiveFact) -> str:
    """Dienstname laut Passivquelle: Produkt, sonst die Kennung aus dem Banner (S6b-4, spec/11
    T1: "ManageSieve (Dovecot Pigeonhole)"), sonst ein Produkt im Banner (S6b-4n, spec/11 N15:
    "Server: cloudflare", "sw-cp-server" ist Plesk), sonst das Modul (E5: "SMTP" statt "unbekannt")."""
    from reporter.catalog.render import banner_product
    if pv.product:
        return pv.product
    return pv.kennung or banner_product(pv.banner_excerpt) or COV.passive_module_name(pv) or UNKNOWN


def foreign_service_label(svc: FS.ServiceFact, label: str) -> str:
    """Dienst einer weiteren Domain auf einem geteilten Server (spec/11 N11): nicht bewertet; ohne
    Domainfakt ist die Zuordnung nicht belegt (castenow 8800, Icecast)."""
    if getattr(svc, "foreign_domain", None):
        return f"{label}, Dienst einer weiteren Domain, nicht bewertet"
    return f"{label}, Zuordnung nicht belegt, nicht bewertet"


def cdn_edge_notes(facts: FS.Facts) -> list[str]:
    """Satz zur CDN-Kante (spec/11 N15): die Passivquelle meldet an einer Adresse des Anbieters dessen
    Standardports (bergersysteme 198.202.211.1: Cloudflare 2052 bis 2096, 8080, 8880)."""
    from reporter.catalog.render import banner_product
    out: list[str] = []
    for host in sorted(facts.hosts, key=lambda h: (h.family, h.ip)):
        if host.third_party is not None:
            continue
        cdn = host.cdn_provider or next((s.product for s in facts.services if s.host_ip == host.ip
                                         and CDN_PRODUCT.search(s.product or "")), None)
        if not cdn:
            continue
        offen = {s.port for s in facts.services if s.host_ip == host.ip and s.state == "open"}
        ports = sorted({p.port for p in facts.passive if p.host_ip == host.ip and p.port and p.port not in offen})
        if not ports:
            continue
        treffer = CDN_PRODUCT.search(cdn)
        name = CDN_NAMES.get(treffer.group(0).lower(), cdn) if treffer else (banner_product(cdn) or cdn)
        out.append(f"An {host.ip} meldet die Passivquelle die Ports {', '.join(str(p) for p in ports)}; es sind "
                   f"Standardports der CDN-Kante des Anbieters ({name}), sie gehören nicht zu Ihren Systemen "
                   "und sind nicht bewertet.")
    return out


CDN_PRODUCT = re.compile(r"cloudflare|akamai|fastly|cloudfront", re.I)
CDN_NAMES = {"cloudflare": "Cloudflare", "akamai": "Akamai", "fastly": "Fastly", "cloudfront": "Amazon CloudFront"}


def system_leads(facts: FS.Facts) -> dict[str, str]:
    """Adresse -> erste Adresse ihres Systems, wie Kapitel 2.1 (S7a, spec/10 R20): IPv4 und IPv6
    mit gleichem rDNS und die weiteren A- und AAAA-Eintraege derselben Namen."""
    out: dict[str, str] = {}
    for members in _systems(facts):
        lead = members[0].ip
        for h in members:
            out[h.ip] = lead
        for h in members:
            for a in h.additional_ips:
                out.setdefault(a.ip, lead)
    return out


def _worst(befunde: list[Finding]) -> Optional[Finding]:
    return min(befunde, key=lambda f: L.STATUS_RANK[f.status]) if befunde else None


def _card_ports(facts: FS.Facts, ip: str, refs: dict[tuple[str, int], list[Finding]],
                gemessen: set[tuple[str, int]]) -> list[tuple[ServicePort, bool]]:
    """(Port, nur laut Passivquelle) einer Adresse in Kartenreihenfolge."""
    out: list[tuple[ServicePort, bool]] = []
    for svc in sorted((s for s in facts.services if s.host_ip == ip and s.state == "open"),
                      key=lambda s: s.port):
        label = service_display(svc)
        schwer = _worst(refs.get((ip, svc.port), []))
        if svc.foreign:
            # S6b-4n (spec/11 N11): Dienste weiterer Domains stehen grau, nicht bewertet.
            out.append((ServicePort(p=str(svc.port), s=foreign_service_label(svc, label), st="grau"), False))
            continue
        if schwer is not None:
            # S6b-4 (spec/11 T16): die Ampel des schwersten Befunds, auch fuer service_unidentified.
            port = ServicePort(p=str(svc.port), s=label, st=schwer.status, stage=schwer.urgency)
        elif svc.unidentified:
            # S6b-3 (spec/10 R9): ein Dienst ohne Kennung ist nicht "unauffällig".
            port = ServicePort(p=str(svc.port), s=label, st="grau")
        elif (ip, svc.port) in gemessen:
            port = ServicePort(p=str(svc.port), s=label, st="gruen")
        else:
            # S7a (spec/10 R20): nur im Portscan erfasst, keine Messung am Port.
            port = ServicePort(p=str(svc.port), s=label, st="grau")
        out.append((port, False))
    seen = {p.p for p, _ in out}
    for pv in sorted((p for p in facts.passive if p.host_ip == ip and p.port), key=lambda p: p.port or 0):
        if str(pv.port) in seen:
            continue
        seen.add(str(pv.port))
        # S6b-4 (spec/11 T16): ein Passivport mit Befund traegt dessen Ampel (junkerwerk
        # SonicWall 4433 stand grau neben Gelb VS-002).
        schwer = _worst(refs.get((ip, pv.port), []))
        out.append((ServicePort(p=str(pv.port), s=passive_service_label(pv),
                                st=schwer.status if schwer else "grau",
                                stage=schwer.urgency if schwer else ""), schwer is None))
    return out


def build_services(facts: FS.Facts, items: list[Consolidated],
                   findings: list[Finding]) -> list[ServiceCard]:
    """Service-Karte: Farbe je Port nach Ampel des schwersten Befunds (Legende nach Ampel).

    S7a (spec/10 R20): ein Block je System (IPv4 und IPv6 desselben Systems zusammen, JW und HL);
    Gruen nur mit einer Messung am Port, sonst grau. Ports einer weiteren Adresse, die nur eine
    Passivquelle kennt, stehen als eine Zeile im Block statt als eigene Karte."""
    refs = finding_ports(facts, items, findings)
    gemessen = COV.measured_ports(facts)
    cards: list[ServiceCard] = []
    for members in _systems(facts):
        lead = members[0]
        ports = [p for p, _ in _card_ports(facts, lead.ip, refs, gemessen)]
        notes: list[str] = []
        for h in members[1:]:
            weitere = _card_ports(facts, h.ip, refs, gemessen)
            if not weitere:
                continue
            if all(passiv for _, passiv in weitere):
                nummern = [p.p for p, _ in weitere]
                liste = nummern[0] if len(nummern) == 1 else ", ".join(nummern[:-1]) + " und " + nummern[-1]
                dienste = ", ".join(dict.fromkeys(p.s for p, _ in weitere))
                wort = "Port" if len(nummern) == 1 else "Ports"
                notes.append(f"{h.ip}: {wort} {liste} laut Passivquelle ({dienste}), nicht geprüft")
                continue
            ports.extend(ServicePort(p=p.p, s=f"{p.s}, an {h.ip}", st=p.st, stage=p.stage) for p, _ in weitere)
        if not ports and not notes:
            continue
        cards.append(ServiceCard(host=lead.ip, label=lead.reverse or "", ports=ports,
                                 more_ips=[h.ip for h in members[1:]], notes=notes))
    return cards


def services_legend(cards: list[ServiceCard]) -> str:
    farben = {p.st for c in cards for p in c.ports} | ({"grau"} if any(c.notes for c in cards) else set())
    gelb = {p.stage for c in cards for p in c.ports if p.st == "gelb" and p.stage}
    return N.services_note(farben, gelb)


# S6b-3 (spec/10 R8): nicht anwendbar mit eigenem Grund steht als "entfällt (Grund)".
POSTURE_NA_TEXT: dict[str, str] = {
    "mx_external": "entfällt (MX beim Dienstleister)",
    "zone_unsigned": "entfällt (Zone nicht signiert)",
}


def _result_state(results: list[CheckResult],
                  primary: list[CheckResult] | None = None) -> tuple[Optional[bool], str]:
    """Status eines Posture-Items.

    Ein Fehlschlag irgendeiner beteiligten Pruefung zieht das Item auf
    "Handlungsbedarf". Zwischen "unauffaellig" und "nicht pruefbar" entscheidet die
    leitende Pruefung; ein bestandener Nebencheck ohne gesehene Items sagt nichts aus.
    S6b-3 (spec/10 R8): dieselben Regelergebnisse wie Befund und Positivbefund; eine durch
    eine Messung derselben Familie ueberholte "nicht pruefbar"-Zeile zaehlt nicht, und
    bestanden neben nicht pruefbar ist "teilweise geprüft".
    """
    if not results:
        return None, "nicht geprüft"
    from reporter.catalog import families as FAM
    gemessen = FAM.measured(results)
    results = [r for r in results if not FAM.suppressed(r, gemessen)]
    lead = [r for r in (primary if primary else results) if not FAM.suppressed(r, gemessen)] or results
    if any(r.status == "fail" for r in results):
        return False, "Handlungsbedarf"
    for r in lead:
        if r.status == "not_applicable" and r.reason_code in POSTURE_NA_TEXT:
            return None, POSTURE_NA_TEXT[r.reason_code]
    # S6b-4 (spec/11 Teil 3 JW): die DNS-Abfrage lief je Domain und fand keinen verwaisten
    # Eintrag; das ist ein Ergebnis, kein Entfallen.
    bestanden = any(r.status == "pass" and (r.items_seen > 0 or r.check_id in POSTURE_EMPTY_IS_RESULT)
                    for r in lead)
    if bestanden and any(r.status == "not_testable" for r in lead):
        return None, "teilweise geprüft"
    if bestanden:
        return True, "unauffällig"
    if any(r.status == "not_testable" for r in lead):
        return None, "nicht prüfbar"
    if any(r.status == "pass" and r.items_seen > 0 for r in results):
        return True, "unauffällig"
    if any(r.status == "not_testable" for r in results):
        return None, "nicht prüfbar"
    return None, "entfällt"


# Pruefungen, deren leere Trefferliste ein Messergebnis ist (dns_records meldet je Domain die
# verwaisten CNAME-Eintraege; keiner heisst unauffaellig).
POSTURE_EMPTY_IS_RESULT = frozenset({"dns_dangling_cname"})

# Posture der Hosts ohne Messergebnis (S6b-1, spec/09 Q9): immer "nicht pruefbar".
POSTURE_UNREACHABLE = frozenset({"unerreichbar", "keine"})


# S6b-2 (spec/08 Punkt 6): SPF mit ~all ist vorhanden, aber nicht hart; die Posture zeigt
# das als "softfail", nicht als fehlend und nicht als Handlungsbedarf.
POSTURE_SOFT: dict[str, tuple[str, str]] = {"SPF": ("spf_softfail", "softfail")}
# S6b-2 (spec/09 Q12): "Zertifikate unauffaellig" nur, wenn alle verschluesselten Dienste
# der Hosts geprueft sind.
POSTURE_TLS_ITEMS = frozenset({"Zertifikate"})


def _posture_systeme(items: list[PostureItem], leads: dict[str, str]) -> list[PostureItem]:
    """S7a (spec/10 R20, HL und JW): der Eintrag einer weiteren Adresse desselben Systems steht
    unter dem der ersten Adresse, wenn er nichts Schlechteres sagt (kein ✘); der Zustand ``v`` der
    ersten Adresse bleibt, damit das Gate ihn weiter gegen die Befunde pruefen kann."""
    by_label = {it.l: it for it in items}
    out: list[PostureItem] = []
    for it in items:
        lead = leads.get(it.l)
        haupt = by_label.get(lead) if lead and lead != it.l else None
        if haupt is not None and it.ok is not False:
            haupt.more.append(f"{it.l}: {it.v}")
            continue
        out.append(it)
    return out


def build_posture(output: CatalogOutput, model: COV.Model | None = None,
                  facts: FS.Facts | None = None,
                  findings: list[Finding] | None = None) -> list[PostureBlock]:
    """S6b-4 (spec/11 T16): jede Zelle aus denselben Regelergebnissen wie Befund und
    Positivbefund; "softfail" neutral nur, wenn der Befund dazu blau ist."""
    from reporter.v3.bundles import tls_untested_hosts

    by_check: dict[str, list[CheckResult]] = {}
    for r in output.results:
        by_check.setdefault(r.check_id, []).append(r)
    ampel: dict[str, str] = {}
    for f in findings or []:
        for cid in f.checks:
            if cid not in ampel or L.STATUS_RANK[f.status] < L.STATUS_RANK[ampel[cid]]:
                ampel[cid] = f.status
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
            item_checks = list(per_host)
            item_pulls = list(spec.get("per_host_members") or ())
            for cid in spec.get("per_host_members") or ():
                for r in by_check.get(cid, []):
                    # Zertifikatsregeln gruppieren nach Name; die Zeile gehoert jedem Host
                    # eines fehlgeschlagenen Mitglieds, sonst entsteht keine neue Zeile.
                    for host in sorted({m.host_ip for m in r.members if m.status == "fail" and m.host_ip}):
                        if host in by_host:
                            by_host[host].append(r)
            for host in sorted(set(by_host) | set(ohne_messung), key=sort_key):
                if host in ohne_messung:
                    items.append(PostureItem(l=host, ok=None, v="nicht prüfbar", checks=item_checks,
                                             subjects=[host], pulls=item_pulls))
                    continue
                ok, text = _result_state(by_host[host], lead_by_host.get(host))
                # S6b-3 (spec/10 R3): "unauffaellig" nur, wenn alle TLS-Dienste des Hosts
                # geprueft sind (Plesk-Mailports bei bergersysteme, acht Dienste bei dortmund-beach).
                if spec["name"] == "Transportverschlüsselung" and ok is True and host in tls_offen:
                    ok, text = None, "teilweise geprüft"
                # S6b-4n (spec/11 N5): gemessen hat testssl nur an einer anderen Adresse desselben
                # Namens; die Inventaradresse ist nicht "unauffaellig", der Name ist gemessen.
                anderswo = COV.tls_only_elsewhere(facts, host) if facts is not None else []
                if spec["name"] == "Transportverschlüsselung" and ok is not False and anderswo:
                    ok, text = None, f"am Namen gemessen ({', '.join(anderswo)})"
                items.append(PostureItem(l=host, ok=ok, v=text, checks=item_checks, subjects=[host],
                                         pulls=item_pulls))
            if facts is not None:
                items = _posture_systeme(items, system_leads(facts))
        for label, checks in spec["items"]:  # type: ignore[index]
            results = [r for cid in checks for r in by_check.get(cid, [])]
            ok, text = _result_state(results, by_check.get(checks[0], []))
            weich = POSTURE_SOFT.get(label)
            if weich and ok is False:
                fails = {r.check_id for r in results if r.status == "fail"}
                # S6b-4 (spec/11 T16): neben einem gelben oder roten Befund bleibt es beim ✘.
                if fails == {weich[0]} and ampel.get(weich[0]) not in ("rot", "gelb"):
                    ok, text = None, weich[1]
            if label in POSTURE_TLS_ITEMS and ok is True and tls_offen:
                ok, text = None, "nur teilweise geprüft"
            items.append(PostureItem(l=label, ok=ok, v=text, checks=list(checks),
                                     subjects=sorted({r.group_key for r in results}, key=sort_key)))
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


def screen_caption(fq: FS.FqdnFact) -> str:
    """Bildunterschrift aus der aufgenommenen Seite (S6b-4, spec/11 Teil 3 HL): Titel und
    Endadresse laut redirect_probe; heuel online zeigte www, die Unterschrift nannte die
    Sicherheitsabfrage der Plattform, ose die Anmeldemaske mit "Redirector"."""
    titel = clean_foreign_text(fq.probe_title) if fq.probe_title else ""
    if not titel:
        return clean_foreign_text(fq.title) or f"Antwort von {fq.name}"
    ende = urlsplit(fq.probe_final_url or "")
    ziel = f"{ende.hostname or ''}{ende.path if ende.path not in ('', '/') else ''}"
    if ziel and ziel.lower() != fq.name.lower():
        return f"{titel} ({ziel})"
    return titel


def _seite(fq: FS.FqdnFact) -> Optional[str]:
    """Gleiche Seite auf demselben Host trotz Namen im Inhalt (S7a, spec/10 R20): Titel und Pfad der
    Endadresse laut redirect_probe. Exchange liefert unter mail, mail2 und owa dieselbe
    Anmeldemaske mit dem jeweiligen Namen in Adresse und Inhalt; ``body_hash`` unterscheidet sich."""
    titel = " ".join((fq.probe_title or fq.title or "").split()).lower()
    ziel = urlsplit(fq.probe_final_url or fq.final_url or "")
    pfad = (ziel.path or "/").rstrip("/") or "/"
    if not titel or pfad == "/":
        return None
    return f"seite:{fq.host_ip}|{titel}|{pfad}"


def _kurznamen(namen: list[str], domains: list[str]) -> list[str]:
    """"mail", "mail2" und "owa" statt der vollen Namen, wenn alle unter derselben Zieldomain liegen."""
    for dom in domains:
        suffix = "." + dom.lower()
        if all(n.lower().endswith(suffix) for n in namen):
            return [n[: -len(suffix)] for n in namen]
    return namen


def _aufzaehlung(teile: list[str]) -> str:
    return teile[0] if len(teile) == 1 else ", ".join(teile[:-1]) + " und " + teile[-1]


def build_screens(facts: FS.Facts) -> list[Screenshot]:
    """Sichtnachweise aus den Fakten, jede Seite einmal.

    ``screenshot_key`` zeigt auf das Objekt in MinIO; die Bilddatei selbst holt der
    Renderer (S4). Der Titel stammt von der fremden Seite und wird geglaettet, bevor er
    in den Bericht geht. S6b-1 (spec/09 Teil 3): Namen mit derselben Seite (gleicher
    Inhalt oder gleiches Weiterleitungsziel) teilen sich ein Bild; die Unterschrift nennt
    die weiteren Namen. Bevorzugt wird der Name, auf den die Weiterleitung zeigt.

    S7a (spec/10 R20): dieselbe Seite unter mehreren Namen desselben Hosts ist ein Bild ("mail,
    mail2 und owa zeigen dieselbe Anmeldeseite", drei OWA-Fotos bei castenow); ein Name, der auf
    einen anderen Host mit eigenem Bild weiterleitet, steht in dessen Unterschrift ("online.heuel.com,
    weitergeleitet auf www.heuel.com") statt still zu entfallen. Werte aus redirect_probe.
    """
    def eigenes_bild(fq: FS.FqdnFact) -> bool:
        # Ein Name ohne eigene Probe erbt das Hostbild eines anderen Namens
        # (dortmund-beach: pflege und www zeigten das Bild von dortmund-beach.com).
        datei = (fq.screenshot_key or "").rsplit("/", 1)[-1]
        return datei.endswith(f"__{fq.name}.png") or fq.http_status is not None

    kandidaten = [fq for fq in facts.fqdns
                  if fq.screenshot_key and not fq.wildcard and eigenes_bild(fq)
                  and next((h for h in facts.hosts if h.ip == fq.host_ip and h.third_party is None), None)]
    # S6b-4n (spec/11 N4): ein Bild zeigt die Antwort seines Hosts. Leitet ein Name auf einen anderen
    # Host weiter und hat das Ziel ein eigenes Bild, steht die Weiterleitung nur in dessen Unterschrift
    # (S7a); ohne eigenes Bild des Ziels zeigt das Bild der Weiterleitung die Zielseite.
    mit_bild = {fq.name.lower() for fq in kandidaten}
    ziele = {fq.name: R.redirect_target(facts, fq) for fq in kandidaten}
    umgeleitet: dict[str, list[str]] = {}
    for fq in kandidaten:
        ziel = ziele[fq.name]
        if ziel and ziel in mit_bild and fq.name not in umgeleitet.setdefault(ziel, []):
            umgeleitet[ziel].append(fq.name)
    kandidaten = [fq for fq in kandidaten if not (ziele[fq.name] and ziele[fq.name] in mit_bild)]

    def rang(fq: FS.FqdnFact) -> tuple:
        ziel = (urlsplit(fq.final_url or "").hostname or "").lower()
        return (0 if ziel == fq.name.lower() else 1, len(fq.name), fq.name)

    # Gleiche Bilddatei (Hündgen: der Apex traegt das Bild von www als Hostbild), gleicher
    # Inhalt, gleiches Weiterleitungsziel oder dieselbe Seite desselben Hosts ergeben eine Gruppe.
    groups: dict[str, list[FS.FqdnFact]] = {}
    alias: dict[str, str] = {}
    for fq in kandidaten:
        keys = [f"shot:{fq.screenshot_key}"] + [k for k in (_same_page_key(fq), _seite(fq)) if k]
        ziel = next((alias[k] for k in keys if k in alias), keys[0])
        for k in keys:
            alias.setdefault(k, ziel)
        groups.setdefault(ziel, []).append(fq)
    domains = list(facts.scan.domains) or ([facts.scan.domain] if facts.scan.domain else [])
    login = {h.fqdn for h in facts.http if h.fqdn and h.login_form}
    out: list[Screenshot] = []
    for members in groups.values():
        members.sort(key=rang)
        fq = members[0]
        weitere = sorted({m.name for m in members[1:] if m.host_ip == fq.host_ip} - {fq.name}, key=sort_key)
        was = screen_caption(fq)
        kopf = ""
        if weitere:
            namen = sorted([fq.name] + weitere, key=sort_key)
            seite = "Anmeldeseite" if any(n in login for n in namen) else "Seite"
            kopf = f"{_aufzaehlung(_kurznamen(namen, domains))} zeigen dieselbe {seite}"
            titel = clean_foreign_text(fq.probe_title) if fq.probe_title else ""
            pfad = urlsplit(fq.probe_final_url or "").path
            if titel:
                was = f"{titel} ({pfad})" if pfad not in ("", "/") else titel
        if ziele.get(fq.name):
            kopf = kopf or f"{fq.name}, weitergeleitet auf {ziele[fq.name]}"
        out.append(Screenshot(
            file=fq.screenshot_key.rsplit("/", 1)[-1],
            key=fq.screenshot_key,
            host=fq.name,
            what=was,
            # S6b-4n (spec/11 N4): weitere Namen nur vom selben Host.
            also=weitere,
            head=kopf,
            redirects=[f"{n}, weitergeleitet auf {fq.name}"
                       for n in sorted(umgeleitet.get(fq.name.lower(), []), key=sort_key)]))
    return sorted(out, key=lambda s: s.host)


REPUTATION_SOURCES = ["AbuseIPDB", "OTX", "URLhaus"]


def reputation_sources(facts: FS.Facts) -> list[str]:
    """Quellen mit ausdruecklichem Ergebnis (spec/10 R6): URLhaus ohne Daten ist ein Ausfall."""
    out: list[str] = []
    if any(h.reputation is not None and h.reputation.abuseipdb_total_reports is not None for h in facts.hosts):
        out.append("AbuseIPDB")
    if any(p.source == "otx" and p.details.get("pulse_count") is not None for p in facts.passive):
        out.append("OTX")
    if any(p.source == "urlhaus" and p.details.get("compromised") is not None for p in facts.passive):
        out.append("URLhaus")
    return out


# S6b-3 (spec/10 R12, R19): Beobachtungen ohne Regeltreffer in Kundensprache. Werkzeuginterne
# Eintraege (unlesbare Datei, Werkzeug ohne Parser) sind keine Beobachtung am Kunden.
_BEOBACHTUNG_FAKTEN = {
    "smtp_auth_before_starttls": "Anmeldung vor STARTTLS angeboten",
    "wpscan_readme": "readme.html der WordPress-Installation abrufbar",
    "wpscan_wp_cron": "wp-cron.php der WordPress-Installation von außen aufrufbar",
    "resource_version": "Bibliotheksversion in einer Ressourcenadresse",
}


def unprocessed_notes(facts: FS.Facts, output: CatalogOutput) -> list[str]:
    out: list[str] = []

    def add(text: str) -> None:
        if text not in out:
            out.append(text)

    for u in output.unprocessed:
        if u.kind == "service_unknown_port":
            port = str(u.what).split("/")[0].strip()
            add(f"Port {port} auf {u.host_ip} ohne Regel" if u.host_ip else f"Port {port} ohne Regel")
        elif u.kind == "passive_port_unverified":
            # S6b-4 (spec/11 T1): ausserhalb der Top 1000 hat der Portscan den Port nicht erfasst.
            if port_outside_range(facts, u.port):
                add(f"{u.what} laut Passivquelle, außerhalb des geprüften Portbereichs")
            else:
                add(f"{u.what} laut Passivquelle, vom Portscan nicht bestätigt")
        else:
            add(f"Werkzeugmeldung {u.what}")
    # S6b-4n (spec/11 N15): ein Verwaltungsport laut Passivquelle ohne Kennung steht auch unter den
    # Beobachtungen (heuel 4433: Shodan "Server: xxxx", im Anhang C als Werkzeugmeldung).
    for r in output.results:
        if r.check_id != "admin_port_passive_unidentified" or r.status != "fail":
            continue
        for m in r.members:
            if m.status != "fail" or not m.host_ip or not m.port:
                continue
            pv = next((p for p in facts.passive if p.host_ip == m.host_ip and p.port == m.port), None)
            server = re.search(r"Server:\s*(\S+)", (pv.banner_excerpt or "") if pv else "")
            kennung = f" (Antwortkopf {server.group(0)})" if server else ""
            wo = ("außerhalb des geprüften Portbereichs" if port_outside_range(facts, m.port)
                  else "vom Portscan nicht bestätigt")
            add(f"Verwaltungsport {m.port} auf {m.host_ip} laut Passivquelle ohne Produktkennung{kennung}, {wo}")
    aktiv_auth = {str(u.what).split(" ")[0] for u in facts.unprocessed
                  if u.kind == "smtp_auth_before_starttls" and "Passivquelle" not in str(u.what)}
    for u in facts.unprocessed:
        was = _BEOBACHTUNG_FAKTEN.get(u.kind) or (
            "Hinweis der Webanalyse ohne Regel" if u.kind.startswith("wpscan_") else None)
        if not was:
            continue
        what = str(u.what)
        if u.kind == "wpscan_readme":
            # S6b-4 (spec/11 Teil 3 CA): der Dateiname aus dem Fund ("liesmich.html").
            datei = urlsplit(what.split(" ")[-1]).path.rsplit("/", 1)[-1] if "://" in what else ""
            if datei:
                was = f"{datei} der WordPress-Installation abrufbar"
        if u.kind == "smtp_auth_before_starttls":
            # S6b-4n (spec/11 N15): derselbe Port aktiv gemessen, die Passivangabe entfaellt (DB 587).
            if "Passivquelle" in what and what.split(" ")[0] in aktiv_auth:
                continue
            ort = what.split(" ")[0] + (", laut Passivquelle" if "Passivquelle" in what else "")
        elif u.kind == "resource_version":
            ort_, _, rest = what.partition(": ")
            was = f"Bibliotheksversion {rest.split(' in Ressourcen-URL')[0]} in einer Ressourcenadresse"
            ort = ort_
        else:
            ort = u.fqdn or u.host_ip or ""
        add(f"{was} ({ort})" if ort else was)
    return out


def build_architecture(facts: FS.Facts, output: CatalogOutput, items: list[Consolidated],
                       findings: list[Finding], model: COV.Model | None = None) -> Architecture:
    model = model or COV.build_model(facts)
    roles = sorted({r.label for members in _systems(facts) for r in system_roles(facts, members)})
    eigene = [h for h in facts.hosts if h.third_party is None]
    # S6b-2 (spec/09 Q12): Adressen von Plattformen und Inhaltsnetzen werden nicht bewertet,
    # sondern benannt. Score 0 heisst nicht "keine Meldungen": eine Adresse auf der
    # Freigabeliste von AbuseIPDB hat Score 0 trotz Meldungen (Vercel bei heuel, 26).
    fremd = [h for h in eigene if h.cdn_provider or (h.shared is not None and h.shared.kind == "platform")]
    # S6b-3 (spec/10 R6): "keine Meldungen" nur, wenn alle gemessenen Adressen null Meldungen
    # haben, Plattform- und CDN-Adressen eingeschlossen (heuel 216.150.1.65 mit 26 Meldungen
    # trotz Freigabeliste); sonst steht die Aussage nicht da.
    gemessen = [h for h in eigene if h.reputation is not None and h.reputation.abuseipdb_total_reports is not None]
    clean = bool(gemessen) and not any(
        (h.reputation.abuseipdb_score or 0) >= CT.ABUSEIPDB_FAIL_SCORE
        or (h.reputation.abuseipdb_total_reports or 0) > 0
        or (h.reputation.otx_pulse_count or 0) > 0
        or h.reputation.urlhaus_compromised
        for h in gemessen)
    notes: list[str] = []
    beobachtungen = unprocessed_notes(facts, output)
    if beobachtungen:
        # S6b-3 (spec/10 R12): keine Zusage ("wir prüfen sie"), sondern die Beobachtungen selbst.
        wort = "Beobachtung" if len(beobachtungen) == 1 else "Beobachtungen"
        notes.append(f"{wort} ohne Regeltreffer, nicht als Befund bewertet: " + "; ".join(beobachtungen) + ".")
    for wert in sorted(_unbeauftragt(facts, output)):
        notes.append(f"Sichtbar, aber nicht beauftragt: {wert}.")
    # S6b-4n (spec/11 N15): Standardports einer CDN-Kante laut Passivquelle.
    notes.extend(cdn_edge_notes(facts))
    # facts.warnings sind Hinweise des Faktenbauers an den Betreiber, keine Kundentexte.
    # Was davon den Kunden betrifft, steht ueber die Abdeckungsgruende in Kapitel 2.
    services = build_services(facts, items, findings)
    return Architecture(
        # S6b-2 (Nachtrag S6b-1): Kapitel 3 zaehlt in Systemen wie Kapitel 2.1.
        lead=N.architecture_lead(len(model.system_rows()), roles),
        tech=build_tech(facts, findings),
        services=services,
        services_note=services_legend(services),
        posture=build_posture(output, model, facts, findings),
        screens_lead=N.SCREENS_LEAD,
        screens=build_screens(facts),
        reputation=N.reputation_line(
            clean, reputation_sources(facts), sorted((h.ip for h in fremd), key=sort_key),
            reported=[(h.ip, int(h.reputation.abuseipdb_total_reports or 0))
                      for h in sorted(gemessen, key=lambda x: sort_key(x.ip))
                      if (h.reputation.abuseipdb_total_reports or 0) > 0]),
        notes=notes,
    )


__all__ = ["format_date", "format_window", "today", "coverage_model", "hosts_ohne_leitwerkzeug",
           "blockade_belegt", "limitations", "build_glance", "overall_text", "build_business",
           "observed_systems", "system_roles", "host_roles", "host_role", "build_scope", "tech_lines",
           "build_tech", "finding_ports", "passive_service_label", "build_services", "build_posture",
           "build_screens", "build_architecture", "dkim_selectors_for_appendix"]

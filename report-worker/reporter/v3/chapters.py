# -*- coding: utf-8 -*-
"""Kapitel 1 bis 3 des Reports aus Fakten und Prüfergebnis.

Alles hier ist abgeleitet, nichts geschätzt: Zahlen kommen aus ``facts``, Status aus dem
Katalogergebnis, Texte aus ``narrative.py``. Ein Wert, den die Fakten nicht hergeben,
wird als unbekannt ausgewiesen und nicht geraten.
"""
from __future__ import annotations

import os
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from reporter.catalog.schema import CATEGORY_NAMES, CatalogOutput, CheckResult
from reporter.catalog import scope as CS
from reporter.catalog import tables as CT
from reporter.facts import schema as FS
from reporter.v3 import levels as L
from reporter.v3 import narrative as N
from reporter.v3 import tables as T
from reporter.v3.bundles import Consolidated
from reporter.v3.findings import kurz_label
from reporter.v3.orthography import clean_foreign_text
from reporter.v3.models import (Architecture, Business, CanCannot, Finding, Glance, GlanceCategory,
                                Limitation, MethodPhase, NumberTile, ObservedSystem, PostureBlock,
                                PostureItem, Scope, ScopeHost, Screenshot, ServiceCard, ServicePort,
                                TechBlock, TechRow)

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

WEB_TOOLS = ("header_check", "httpx", "testssl", "zap", "zap_spider", "zap_active",
             "feroxbuster", "ffuf_param", "ffuf_sensitive", "wpscan")


def _reason_text(rows: list[FS.CoverageFact], fallback: str) -> str:
    """Erster Grund aus den Zeilen, der als Klartext hinterlegt ist."""
    for row in rows:
        code = row.reason or row.raw_status or ""
        if code in CT.COVERAGE_REASONS:
            return CT.COVERAGE_REASONS[code][1]
    tools = sorted({row.tool for row in rows})
    if tools:
        return f"Ohne Ergebnis blieben: {', '.join(tools)}."
    return fallback


def host_coverage(facts: FS.Facts, ip: str) -> tuple[str, str]:
    """(Kurzform voll|teil|keine, Klartext) fuer einen Host."""
    rows = [c for c in facts.coverage if c.host_ip == ip]
    nmap = [c for c in rows if c.tool == "nmap"]
    blocked = next((h for h in facts.hosts if h.ip == ip and h.blocked.detected), None)
    bad = [c for c in rows if c.status in ("failed", "blocked") and c.tool in WEB_TOOLS]
    if nmap and all(c.status not in ("ok", "empty") for c in nmap):
        return "keine", _reason_text(nmap, CT.COVERAGE_REASONS["host_unreachable"][1])
    if blocked is not None:
        code = blocked.blocked.reason or "web_unreachable_after_portscan"
        text = CT.COVERAGE_REASONS.get(code, ("", CT.GENERIC_NOT_TESTABLE))[1]
        return "teil", f"Portscan vollständig; {text}"
    if bad:
        return "teil", "Portscan vollständig; " + _reason_text(bad, CT.GENERIC_NOT_TESTABLE)
    if not rows:
        return "keine", CT.COVERAGE_REASONS["no_tool_runs"][1]
    return "voll", "Portscan und Tiefenprüfung vollständig"


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


def coverage_by_host(facts: FS.Facts) -> dict[str, tuple[str, str]]:
    """Abdeckung je Host, einmal berechnet und von allen Kapiteln geteilt."""
    return {h.ip: host_coverage(facts, h.ip) for h in facts.hosts}


def hosts_ohne_leitwerkzeug(facts: FS.Facts) -> list[str]:
    """Hosts, fuer die ein Leitwerkzeug des Pakets kein Ergebnis hat (spec/08 Punkt 10).

    Massstab fuer den Abdeckungshinweis auf Seite 3. Ein fehlendes Nebenwerkzeug
    (ffuf_sensitive) macht eine Pruefung nicht unvollstaendig; nmap, testssl und
    die Webanalyse des Pakets schon. Ein Werkzeug ausserhalb des Pakets zaehlt
    nicht, und ein Host ohne jede Abdeckungszeile zaehlt immer.
    """
    leit = set(T.lead_tools(facts.scan.package))
    out: list[str] = []
    for host in facts.hosts:
        rows = [c for c in facts.coverage if c.host_ip == host.ip and c.tool in leit]
        if not rows:
            out.append(host.ip)
            continue
        fehlt = False
        for tool in sorted(leit):
            je_tool = [c for c in rows if c.tool == tool]
            if not je_tool:
                continue
            if any(c.status in ("ok", "empty") for c in je_tool):
                continue
            # skipped mit einem Grund, der die Pruefung gar nicht vorsieht
            # (kein TLS-Dienst, nicht im Paket), ist keine Luecke.
            gruende = {CS.normalize_reason(c.reason, c.raw_status) for c in je_tool}
            if all(CT.COVERAGE_REASONS.get(g, ("not_testable", ""))[0]
                   in ("ok", "not_applicable") for g in gruende):
                continue
            fehlt = True
        if fehlt:
            out.append(host.ip)
    return out


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


# Werkzeuge, die bewusst nicht Teil des Produkts sind. Ihr Fehlen ist keine
# Einschraenkung der Pruefung, sondern eine Festlegung (Entscheidung DC, spec/07).
OUT_OF_PRODUCT_TOOLS: frozenset[str] = frozenset({"virustotal"})


# S6a (#15 Teil 2): DKIM ohne gefundenen Selektor ist nicht pruefbar. Die Einschraenkung
# nennt Anzahl und sechs Beispiele der abgefragten Selektoren, die volle Liste steht im
# Anhang bei den eingesetzten Werkzeugen (Entscheidung DC). Belegt der Lauf die Liste
# nicht (Dkim.probed leer), bleibt der allgemeine Text aus COVERAGE_REASONS.
DKIM_CODE = "dkim_selector_unknown"
DKIM_BEISPIELE = ("default", "selector1", "selector2", "google", "k1", "s1")


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


def dkim_selectors_for_appendix(facts: FS.Facts, output: CatalogOutput) -> list[str]:
    """Abgefragte Selektoren fuer den Anhang, nur wenn eine Einschraenkung darauf verweist."""
    out: set[str] = set()
    for result in output.results:
        if result.status != "not_testable" or not result.reason_code:
            continue
        if result.reason_code.split(":", 1)[-1] == DKIM_CODE:
            out.update(dkim_probed(facts, str(result.vars.get("domain") or result.group_key)))
    return sorted(out)


def limitations(facts: FS.Facts, output: CatalogOutput) -> list[Limitation]:
    """Einschraenkungen aus Abdeckungszeilen und nicht pruefbaren Pruefungen.

    Zusammengefasst wird nach dem Klartext, nicht nach dem Code: zwei Codes mit
    derselben Erklaerung ergeben eine Zeile. Ein Code ohne hinterlegte Erklaerung
    bekommt eine, die das Werkzeug nennt, statt einer nichtssagenden Sammelmeldung.
    """
    # S6 (spec/08 Punkt 12): eine Zeile je Ursache, und je Ursache ein Eintrag je
    # betroffenem Ort. Vorher standen derselbe Host einmal als Werkzeugzeile
    # ("webtech auf 62.217.52.177") und einmal als Gruppenname
    # ("62.217.52.177 (test.vectigal.tech)") in derselben Zeile; der WebCheck
    # bekam so elf Zeilen, davon drei fuer dieselbe Ursache.
    by_text: dict[str, dict[str, str]] = {}

    def merken(text: str, schluessel: str, label: str) -> None:
        orte = by_text.setdefault(text, {})
        vorhanden = orte.get(schluessel)
        # Der ausfuehrlichere Name gewinnt: die IP mit ihren Namen sagt mehr als
        # die IP allein.
        if vorhanden is None or len(label) > len(vorhanden):
            orte[schluessel] = label

    for row in facts.coverage:
        if row.status not in ("failed", "blocked", "empty", "skipped"):
            continue
        if row.tool in OUT_OF_PRODUCT_TOOLS:
            continue
        # S6: derselbe Weg wie im Katalog. Ohne Normalisierung landet ein
        # Rohgrund wie "package_webcheck" oder "ZAP API error 400: {...}" in
        # keiner Tabelle und bekommt den Sammeltext "Das Werkzeug X hat kein
        # Ergebnis geliefert" (spec/08 Punkte 9 und 11).
        code = CS.normalize_reason(row.reason, row.raw_status) or "insufficient_facts"
        status, text = CT.COVERAGE_REASONS.get(code, ("not_testable", ""))
        if status in ("ok", "not_applicable"):
            continue
        if not text:
            text = f"Das Werkzeug {row.tool} hat kein Ergebnis geliefert."
        schluessel = row.host_ip or row.fqdn or row.domain or "scanweit"
        merken(text, schluessel, row.fqdn or row.host_ip or row.domain or "scanweit")
    for result in output.results:
        if result.status != "not_testable" or not result.reason_code:
            continue
        code = result.reason_code.split(":", 1)[-1]
        status, text = CT.COVERAGE_REASONS.get(code, ("not_testable", ""))
        if status != "not_testable" or not text:
            continue
        if code == DKIM_CODE:
            probed = dkim_probed(facts, str(result.vars.get("domain") or result.group_key))
            if probed:
                text = dkim_limitation_text(probed)
        schluessel = (str(result.vars.get("host_ip") or "")
                      or str(result.vars.get("domain") or "")
                      or result.group_key)
        merken(text, schluessel, result.group_label)
    out: list[Limitation] = []
    for text in sorted(by_text):
        where = sorted(_kurz(w) for w in by_text[text].values())
        shown = ", ".join(where[:6]) + (" und weitere" if len(where) > 6 else "")
        out.append(Limitation(what=text.rstrip("."), detail=f"Betroffen: {shown}."))
    return out


# Ein Host mit vielen VHosts traegt sie alle im Gruppennamen. In der
# Betroffenenliste einer Einschraenkung ist das eine Wand aus Namen: bei
# vectigal.tech sind es 31 hinter einer einzigen IP. Die Kuerzung der Liste
# selbst (sechs Eintraege) greift dort nicht, weil das Ganze ein Eintrag ist.
# S6a: dieselbe Kuerzung gilt fuer Positivbefunde, deshalb liegt sie in findings.
_kurz = kurz_label


# ---------------------------------------------------------------- Kapitel 1

def build_glance(items: list[Consolidated], findings: list[Finding], counts: N.Counts,
                 gap_hosts: list[str]) -> Glance:
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
        coverage_warning=N.coverage_warning(counts, gap_hosts),
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


def build_business(facts: FS.Facts, roles: list[tuple[str, str]]) -> Business:
    observed = [ObservedSystem(system=label, meaning=meaning) for label, meaning in roles]
    return Business(lead=N.BUSINESS_LEAD, observed=observed,
                    implication=N.BUSINESS_IMPLICATION_GENERIC)


# ---------------------------------------------------------------- Rollen

ROLE_MEANING: dict[str, str] = {
    "Mail- und Kalenderplattform":
        "Über dieses System läuft die geschäftliche Korrespondenz. Ein Zugriff darauf trifft "
        "Vertraulichkeit und Arbeitsfähigkeit zugleich.",
    "Website und Datenbanken":
        "Außendarstellung und die dahinterliegenden Datenbestände. Betroffen wären vor allem "
        "Seiteninhalte, Formulareingaben und Kontaktdaten.",
    "Fernzugang und Verwaltung":
        "Der Weg von außen in das Unternehmensnetz. Solche Zugänge sind das bevorzugte Ziel, "
        "weil hinter ihnen alles Weitere liegt.",
    "Dateiaustausch":
        "Austausch von Dateien mit Dritten. Die Inhalte und die verwendeten Zugangsdaten sind "
        "hier das Schutzgut.",
    T.ROLE_FALLBACK:
        "Die Aufgabe dieses Systems ist von außen nicht eindeutig erkennbar; sie sollte intern "
        "geklärt werden.",
}


MAX_ROLES = 2


def host_roles(facts: FS.Facts, ip: str) -> list[str]:
    """Aufgaben eines Hosts, nach Staerke der Anhaltspunkte.

    Ein Host am Perimeter macht oft mehrere Dinge zugleich (Website und Mail-Relay auf
    demselben gemieteten Server). Eine einzelne Rolle waere in solchen Faellen schlicht
    falsch, deshalb stehen bis zu zwei Aufgaben da.
    """
    ports = {s.port for s in facts.services if s.host_ip == ip and s.state == "open"}
    families = {(s.family or "").lower() for s in facts.software if s.host_ip == ip}
    families |= {(s.product or "").lower() for s in facts.services if s.host_ip == ip and s.product}
    scored: list[tuple[int, int, str]] = []
    for order, (role, keys, role_ports) in enumerate(T.ROLE_RULES):
        hits = 2 * sum(1 for k in keys if any(k in fam for fam in families))
        hits += len(set(role_ports) & ports)
        if hits:
            scored.append((-hits, order, role))
    scored.sort()
    return [role for _, _, role in scored[:MAX_ROLES]]


def host_role(facts: FS.Facts, ip: str) -> str:
    roles = host_roles(facts, ip)
    return ", ".join(roles) if roles else T.ROLE_FALLBACK


def observed_systems(facts: FS.Facts) -> list[tuple[str, str]]:
    """Ein Eintrag je Host mit erkennbarer Aufgabe, in stabiler Reihenfolge."""
    out: list[tuple[str, str]] = []
    for host in sorted(facts.hosts, key=lambda h: (h.family, h.ip)):
        roles = host_roles(facts, host.ip)
        label_role = ", ".join(roles) if roles else T.ROLE_FALLBACK
        names = sorted(host.fqdns)
        label = f"{label_role} ({', '.join(names[:3])})" if names else f"{label_role} ({host.ip})"
        meaning = ROLE_MEANING.get(roles[0] if roles else T.ROLE_FALLBACK,
                                   ROLE_MEANING[T.ROLE_FALLBACK])
        out.append((label, meaning))
    return out


# ---------------------------------------------------------------- Kapitel 2

def build_scope(facts: FS.Facts, output: CatalogOutput, counts: N.Counts,
                coverage: dict[str, tuple[str, str]]) -> Scope:
    hosts: list[ScopeHost] = []
    for host in sorted(facts.hosts, key=lambda h: (h.family, h.ip)):
        cov, text = coverage.get(host.ip, host_coverage(facts, host.ip))
        operator = host.provider.isp if host.provider and host.provider.isp else UNKNOWN
        if host.reverse:
            operator = f"{operator} ({host.reverse})"
        hosts.append(ScopeHost(
            ip=host.ip, fqdns=", ".join(sorted(host.fqdns)) or UNKNOWN,
            operator=operator, role=host_role(facts, host.ip), coverage=text, cov=cov))
    out_of_scope = list(N.OUT_OF_SCOPE_BASE)
    extra = sorted(_unbeauftragt(facts, output))
    if extra:
        out_of_scope.append("Sichtbar, aber nicht beauftragt: " + "; ".join(extra) + ".")
    for hinweis in wildcard_hinweise(facts):
        out_of_scope.append(hinweis)
    return Scope(
        lead=N.scope_lead(counts),
        hosts=hosts,
        out_of_scope=out_of_scope,
        limitations=limitations(facts, output),
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


def tech_lines(facts: FS.Facts) -> dict[str, list[TechLine]]:
    """Zeilen je Host-IP in Berichtsreihenfolge; Hosts ohne Software fehlen."""
    by_host: dict[str, list[FS.SoftwareFact]] = {}
    for sw in facts.software:
        by_host.setdefault(sw.host_ip, []).append(sw)
    out: dict[str, list[TechLine]] = {}
    for host in sorted(facts.hosts, key=lambda h: (h.family, h.ip)):
        entries = sorted(by_host.get(host.ip, []), key=lambda s: (s.kind, s.product, s.id))
        if not entries:
            continue
        lines: list[TechLine] = []
        seen: set[tuple[str, str]] = set()
        for sw in entries:
            version = sw.version_norm or UNKNOWN
            if sw.build:
                version = f"{version} (Build {sw.build})"
            elif sw.distro:
                version = f"{version} ({sw.distro})"
            key = (sw.product, version)
            if key in seen:
                continue
            seen.add(key)
            note = T.tech_note(sw.note)
            if sw.eol.status == "eol" and sw.eol.date:
                note = f"Herstellerpflege endete am {sw.eol.date}"
            elif sw.eol.upstream_eol_date:
                note = f"Lifecycle prüfen, Hersteller nennt {sw.eol.upstream_eol_date}"
            lines.append(TechLine(
                software=sw, product=sw.product, version=version, eol_status=sw.eol.status,
                eol_date=sw.eol.date, note=note,
                sources=", ".join(sorted(sw.detection_sources)) or sw.source,
                confidence=sw.confidence, conf_label=_confidence_label(sw.confidence)))
        out[host.ip] = lines
    return out


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


def _port_colours(items: list[Consolidated], findings: list[Finding]) -> dict[tuple[str, int], str]:
    colours: dict[tuple[str, int], str] = {}
    for item, finding in zip(items, findings):
        for result in item.results:
            for member in result.members:
                if member.status != "fail" or member.host_ip is None or member.port is None:
                    continue
                key = (member.host_ip, member.port)
                current = colours.get(key)
                if current is None or L.STATUS_RANK[finding.status] < L.STATUS_RANK[current]:
                    colours[key] = finding.status
    return colours


def build_services(facts: FS.Facts, items: list[Consolidated],
                   findings: list[Finding]) -> list[ServiceCard]:
    colours = _port_colours(items, findings)
    cards: list[ServiceCard] = []
    for host in sorted(facts.hosts, key=lambda h: (h.family, h.ip)):
        ports: list[ServicePort] = []
        for svc in sorted((s for s in facts.services if s.host_ip == host.ip and s.state == "open"),
                          key=lambda s: s.port):
            label = svc.product or (svc.service or "").upper() or UNKNOWN
            colour = colours.get((host.ip, svc.port))
            if colour is None:
                colour = "blau" if svc.port in T.LEGACY_PORTS else "gruen"
            ports.append(ServicePort(p=str(svc.port), s=label, st=colour))
        seen = {p.p for p in ports}
        for pv in sorted((p for p in facts.passive if p.host_ip == host.ip and p.port),
                         key=lambda p: p.port or 0):
            if str(pv.port) in seen:
                continue
            seen.add(str(pv.port))
            ports.append(ServicePort(p=str(pv.port), s=pv.product or UNKNOWN, st="grau"))
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


def build_posture(output: CatalogOutput) -> list[PostureBlock]:
    by_check: dict[str, list[CheckResult]] = {}
    for r in output.results:
        by_check.setdefault(r.check_id, []).append(r)
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
            for host in sorted(by_host):
                ok, text = _result_state(by_host[host], lead_by_host.get(host))
                items.append(PostureItem(l=host, ok=ok, v=text))
        for label, checks in spec["items"]:  # type: ignore[index]
            results = [r for cid in checks for r in by_check.get(cid, [])]
            ok, text = _result_state(results, by_check.get(checks[0], []))
            items.append(PostureItem(l=label, ok=ok, v=text))
        if items:
            blocks.append(PostureBlock(name=str(spec["name"]), short=str(spec["short"]),
                                       items=items))
    return blocks


def build_screens(facts: FS.Facts) -> list[Screenshot]:
    """Sichtnachweise aus den Fakten.

    ``screenshot_key`` zeigt auf das Objekt in MinIO; die Bilddatei selbst holt der
    Renderer (S4). Der Titel stammt von der fremden Seite und wird geglaettet, bevor er
    in den Bericht geht.
    """
    out: list[Screenshot] = []
    for fq in sorted(facts.fqdns, key=lambda f: f.name):
        # Ein Wildcard-Eintrag bekommt keine Bildunterschrift "Antwort von
        # *.domain" (S6, spec/08 Punkt 13).
        if not fq.screenshot_key or fq.wildcard:
            continue
        out.append(Screenshot(
            file=fq.screenshot_key.rsplit("/", 1)[-1],
            key=fq.screenshot_key,
            host=fq.name,
            what=clean_foreign_text(fq.title) or f"Antwort von {fq.name}"))
    return out


REPUTATION_SOURCES = ["AbuseIPDB", "OTX", "URLhaus"]


def build_architecture(facts: FS.Facts, output: CatalogOutput, items: list[Consolidated],
                       findings: list[Finding]) -> Architecture:
    roles = sorted({r for h in facts.hosts for r in host_roles(facts, h.ip)})
    clean = not any(
        (h.reputation and (
            (h.reputation.abuseipdb_score or 0) >= CT.ABUSEIPDB_FAIL_SCORE
            or (h.reputation.otx_pulse_count or 0) > 0
            or h.reputation.urlhaus_compromised))
        for h in facts.hosts)
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
        lead=N.architecture_lead(len(facts.hosts), roles),
        tech=build_tech(facts),
        services=build_services(facts, items, findings),
        services_note=N.SERVICES_NOTE,
        posture=build_posture(output),
        screens_lead=N.SCREENS_LEAD,
        screens=build_screens(facts),
        reputation=N.reputation_line(clean, REPUTATION_SOURCES),
        notes=notes,
    )

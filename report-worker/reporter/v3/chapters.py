# -*- coding: utf-8 -*-
"""Kapitel 1 bis 3 des Reports aus Fakten und Prüfergebnis.

Alles hier ist abgeleitet, nichts geschätzt: Zahlen kommen aus ``facts``, Status aus dem
Katalogergebnis, Texte aus ``narrative.py``. Ein Wert, den die Fakten nicht hergeben,
wird als unbekannt ausgewiesen und nicht geraten.
"""
from __future__ import annotations

import os
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from reporter.catalog.schema import CATEGORY_NAMES, CatalogOutput, CheckResult
from reporter.catalog import tables as CT
from reporter.facts import schema as FS
from reporter.v3 import levels as L
from reporter.v3 import narrative as N
from reporter.v3 import tables as T
from reporter.v3.bundles import Consolidated
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


def coverage_by_host(facts: FS.Facts) -> dict[str, tuple[str, str]]:
    """Abdeckung je Host, einmal berechnet und von allen Kapiteln geteilt."""
    return {h.ip: host_coverage(facts, h.ip) for h in facts.hosts}


# Werkzeuge, die bewusst nicht Teil des Produkts sind. Ihr Fehlen ist keine
# Einschraenkung der Pruefung, sondern eine Festlegung (Entscheidung DC, spec/07).
OUT_OF_PRODUCT_TOOLS: frozenset[str] = frozenset({"virustotal"})


def limitations(facts: FS.Facts, output: CatalogOutput) -> list[Limitation]:
    """Einschraenkungen aus Abdeckungszeilen und nicht pruefbaren Pruefungen.

    Zusammengefasst wird nach dem Klartext, nicht nach dem Code: zwei Codes mit
    derselben Erklaerung ergeben eine Zeile. Ein Code ohne hinterlegte Erklaerung
    bekommt eine, die das Werkzeug nennt, statt einer nichtssagenden Sammelmeldung.
    """
    by_text: dict[str, set[str]] = {}
    for row in facts.coverage:
        if row.status not in ("failed", "blocked", "empty", "skipped"):
            continue
        if row.tool in OUT_OF_PRODUCT_TOOLS:
            continue
        code = row.reason or row.raw_status or "insufficient_facts"
        status, text = CT.COVERAGE_REASONS.get(code, ("not_testable", ""))
        if status in ("ok", "not_applicable"):
            continue
        if not text:
            text = f"Das Werkzeug {row.tool} hat kein Ergebnis geliefert."
        where = row.fqdn or row.host_ip or row.domain or "scanweit"
        by_text.setdefault(text, set()).add(f"{row.tool} auf {where}")
    for result in output.results:
        if result.status != "not_testable" or not result.reason_code:
            continue
        code = result.reason_code.split(":", 1)[-1]
        status, text = CT.COVERAGE_REASONS.get(code, ("not_testable", ""))
        if status != "not_testable" or not text:
            continue
        by_text.setdefault(text, set()).add(result.group_label)
    out: list[Limitation] = []
    for text in sorted(by_text):
        where = sorted(by_text[text])
        shown = ", ".join(where[:6]) + (" und weitere" if len(where) > 6 else "")
        out.append(Limitation(what=text.rstrip("."), detail=f"Betroffen: {shown}."))
    return out


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


def overall_text(findings: list[Finding]) -> str:
    """Zusammenfassung Seite 1 als Katalogfassung; die KI darf sie ersetzen."""
    red = [f for f in findings if f.status == "rot"]
    yellow = [f for f in findings if f.status == "gelb"]
    if red:
        head = (f"{len(red)} Befunde erfordern unverzügliches Handeln."
                if len(red) > 1 else "Ein Befund erfordert unverzügliches Handeln.")
    elif yellow:
        head = ("Kein Befund erfordert sofortiges Handeln, es besteht aber Handlungsbedarf "
                "mit erkennbarem Angriffsweg.")
    else:
        head = "Es wurde kein Befund mit erkennbarem Angriffsweg festgestellt."
    tail = ("Die übrigen Befunde betreffen die Härtung der erreichbaren Dienste, die "
            "Authentizität der E-Mail und die Transportverschlüsselung."
            if yellow else
            "Die verbleibenden Punkte sind Verbesserungen ohne akutes Risiko.")
    return f"{head} {tail}"


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
    extra = sorted({f"{o.value} ({o.reason})" if o.reason else o.value
                    for t in facts.targets for o in t.out_of_scope})
    if extra:
        out_of_scope.append("Sichtbar, aber nicht beauftragt: " + "; ".join(extra) + ".")
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


def build_tech(facts: FS.Facts) -> list[TechBlock]:
    by_host: dict[str, list[FS.SoftwareFact]] = {}
    for sw in facts.software:
        by_host.setdefault(sw.host_ip, []).append(sw)
    blocks: list[TechBlock] = []
    for host in sorted(facts.hosts, key=lambda h: (h.family, h.ip)):
        entries = sorted(by_host.get(host.ip, []), key=lambda s: (s.kind, s.product, s.id))
        if not entries:
            continue
        rows: list[TechRow] = []
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
            status, colour = _EOL_STATUS.get(sw.eol.status, (UNKNOWN, "grau"))
            note = T.tech_note(sw.note)
            if sw.eol.status == "eol" and sw.eol.date:
                note = f"Herstellerpflege endete am {sw.eol.date}"
            elif sw.eol.upstream_eol_date:
                note = f"Lifecycle prüfen, Hersteller nennt {sw.eol.upstream_eol_date}"
            rows.append(TechRow(
                c=sw.product, v=version, src=", ".join(sorted(sw.detection_sources)) or sw.source,
                conf=_confidence_label(sw.confidence), status=status, st=colour, note=note))
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
        if not fq.screenshot_key:
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
        notes.append(
            f"{total} Beobachtungen der Werkzeuge haben keine Regel des Prüfkatalogs "
            "getroffen. Sie sind kein Befund und wurden intern zur Nachbearbeitung "
            "vorgemerkt.")
    for target in facts.targets:
        for oos in target.out_of_scope:
            notes.append(f"Sichtbar, aber nicht beauftragt: {oos.value}."
                         + (f" {oos.reason}" if oos.reason else ""))
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

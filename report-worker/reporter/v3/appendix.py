# -*- coding: utf-8 -*-
"""Anhänge A bis F.

A.1/A.2 Einstufungsskalen und Triage stehen als Tabelle in ``tables.py``. A.3 zitiert
ausschließlich Fremdwerte aus ``facts.threats``; ohne Fremdwert bleibt der Abschnitt
leer, weil ein selbst vergebener Score angreifbar wäre (spec/03 Regel 2).
B ist das Dienstinventar, C die Werkzeugliste ohne Versionsnummern.
"""
from __future__ import annotations

from reporter.catalog.schema import CatalogOutput
from reporter.facts import schema as FS
from reporter.facts import systems as SYS
from reporter.facts.serialize import sort_key
from reporter.v3 import chapters as C
from reporter.v3 import coverage as COV
from reporter.v3 import levels as L
from reporter.v3 import narrative as N
from reporter.v3 import tables as T
from reporter.v3.models import (Appendix, CveRef, Finding, InventoryRow, ScaleRow, ToolFinding,
                                ToolRow, TriageRow)

UNKNOWN = "unbekannt"


def build_inventory(facts: FS.Facts,
                    port_refs: dict[tuple[str, int], list[Finding]] | None = None) -> list[InventoryRow]:
    """Jeder erreichbare Dienst mit Querverweis auf alle Befunde, die ihn nennen.

    S6b-1 (spec/09 Teil 3): dieselbe Zuordnung wie die Farbe der Service-Karte
    (``chapters.finding_ports``), auch fuer Befunde an einem virtuellen Host. Vorher
    wurde die Betroffenenliste am Doppelpunkt zerlegt; IPv6 und VHost-Befunde fielen
    heraus, und je Port stand nur der erste Befund.
    """
    refs = port_refs or {}

    def ref(host: str, port: int) -> str:
        return ", ".join(f.id for f in refs.get((host, port), []))

    fremd = {h.ip for h in facts.hosts if h.third_party is not None}
    rows: list[InventoryRow] = []
    for svc in sorted(facts.services, key=lambda s: (s.host_ip, s.port)):
        if svc.state != "open" or svc.host_ip in fremd:
            continue
        # S6b-3 (spec/10 R14): derselbe Name wie auf der Service-Karte (MariaDB, Kennung,
        # "nicht identifiziert" statt eines geratenen nmap-Namens mit "?").
        name = C.service_display(svc)
        if svc.version_norm and svc.version_norm not in name:
            name = f"{name} {svc.version_norm}"
        # S6b-4n (spec/11 N15): bei STARTTLS ist "TLS erzwungen" die Anmeldung erst nach STARTTLS
        # (587 bei lumbeck-wolter und castenow).
        if svc.tls_required and svc.starttls:
            name = f"{name}, Anmeldung erst nach STARTTLS"
        elif svc.tls_required:
            name = f"{name}, TLS erzwungen"
        elif svc.starttls:
            name = f"{name}, STARTTLS"
        if svc.foreign:
            name = C.foreign_service_label(svc, name)
        # S6b-4n (spec/11 N5): die Transportverschluesselung dieses Ports ist nur am Namen an einer
        # anderen Adresse gemessen (huendgen 18.197.248.23:443, testssl an 52.59.120.70).
        anderswo = COV.tls_only_elsewhere(facts, svc.host_ip)
        if anderswo and any(t.host_ip == svc.host_ip and t.port == svc.port for t in facts.tls):
            name = f"{name}, Transportverschlüsselung am Namen gemessen an {', '.join(anderswo)}"
        rows.append(InventoryRow(host=svc.host_ip, port=str(svc.port), svc=name,
                                 ref=ref(svc.host_ip, svc.port)))
    for pv in sorted(facts.passive, key=lambda p: (p.host_ip or "", p.port or 0)):
        if not pv.host_ip or not pv.port or pv.host_ip in fremd:
            continue
        if any(r.host == pv.host_ip and r.port == str(pv.port) for r in rows):
            continue
        # E5: Dienstname aus dem Passivmodul ("SMTP") statt "unbekannt".
        name = C.passive_service_label(pv)
        if pv.version and pv.version not in name:
            name = f"{name} {pv.version}"
        # S6b-4 (spec/11 T1): ein Port ausserhalb des Portbereichs ist nicht "unbestaetigt".
        wo = ", außerhalb des geprüften Portbereichs" if C.port_outside_range(facts, pv.port) else ""
        rows.append(InventoryRow(host=pv.host_ip, port=str(pv.port),
                                 svc=f"{name}, laut Passivquelle{wo}",
                                 ref=ref(pv.host_ip, pv.port)))
    # S7a (spec/10 R20): die Adressen eines Systems als ein Block, erste Adresse zuerst (IPv6 von
    # junkerwerk und heuel stand bisher nach allen IPv4-Adressen).
    leads = C.system_leads(facts)
    reihe = {ip: i for i, ip in enumerate(dict.fromkeys(leads.values()))}

    def block(r: InventoryRow) -> tuple:
        lead = leads.get(r.host, r.host)
        return (reihe.get(lead, len(reihe)), sort_key(lead), r.host != lead, sort_key(r.host), int(r.port))

    rows.sort(key=block)
    # S6d (A1, E17): Netzbetreiber mit Quelle (RIR laut RDAP, sonst AbuseIPDB) in der ersten Zeile
    # jedes Hosts.
    by_ip = {h.ip: h for h in facts.hosts}
    domains = list(facts.scan.domains) or [facts.scan.domain]
    gesehen: set[str] = set()
    for r in rows:
        if r.host in gesehen:
            continue
        gesehen.add(r.host)
        lead = leads.get(r.host)
        if lead and lead != r.host:
            r.operator = f"{'IPv6-Adresse' if ':' in r.host else 'weitere Adresse'} von {lead}"
            continue
        h = by_ip.get(r.host)
        if h is None:
            continue
        label = SYS.network_operator_label(
            h.provider, platform=bool(h.cdn_provider or (h.shared and h.shared.kind == "platform")),
            customer_domains=domains)
        quelle = SYS.network_operator_source(h.provider)
        if label and quelle:
            r.operator = f"{label}, laut {quelle}"
    return rows


def build_tools(facts: FS.Facts) -> list[ToolRow]:
    """Nur Werkzeuge, die in diesem Auftrag tatsächlich gelaufen sind.

    Für die Fremdquellen reicht der Lauf des Korrelators nicht: er läuft immer,
    der Abgleich gegen NVD, EPSS und den KEV-Katalog aber nur, wenn überhaupt
    eine Schwachstellennummer zu prüfen war. Ohne Treffer stünde sonst eine
    autoritative Fremdquelle im Bericht, die nichts beigetragen hat (S5b).
    """
    ran = {c.tool for c in facts.coverage if c.status in ("ok", "empty")}
    if not _anreicherung_gelaufen(facts):
        ran -= set(T.ENRICHMENT_TOOLS)
    leer = ohne_ergebnis(facts)
    out: list[ToolRow] = []
    for label, purpose, confidence, tools in T.TOOL_ROWS:
        if ran & set(tools):
            # S6b-4n (spec/11 N12): eine Quelle, die lief, aber keine Daten lieferte, heisst so.
            for name in leer:
                label = label.replace(name, f"{name} (ohne Ergebnis)")
            out.append(ToolRow(t=label, u=purpose, c=confidence))
    return out


def ohne_ergebnis(facts: FS.Facts) -> list[str]:
    """Passivquellen, die gelaufen sind, aber keine Daten geliefert haben (spec/11 N12: URLhaus mit
    "no_data", SecurityTrails ohne Domaindaten)."""
    ran = {c.tool for c in facts.coverage if c.status in ("ok", "empty")}
    out: list[str] = []
    if "urlhaus" in ran and not any(p.source == "urlhaus" and (p.details or {}).get("compromised") is not None
                                    for p in facts.passive):
        out.append("URLhaus")
    if "securitytrails" in ran and not any(p.source == "securitytrails" for p in facts.passive):
        out.append("SecurityTrails")
    return out


def _anreicherung_gelaufen(facts: FS.Facts) -> bool:
    """Hat der Abgleich gegen die Fremdquellen etwas erbracht?

    Zwei Belege, beide aus den Fakten: ein Threat mit Fremdwert, oder die Bilanz
    der Korrelation mit ``cves_enriched`` über null.
    """
    for t in facts.threats:
        if (t.cvss_nvd and t.cvss_nvd.score is not None) or (t.kev and t.kev.listed) \
                or t.epss is not None:
            return True
    for d in facts.decisions:
        if d.source == "phase3_correlation":
            if int(d.payload.get("cves_enriched") or 0) > 0:
                return True
    return False


def build_appendix(facts: FS.Facts, output: CatalogOutput, findings: list[Finding],
                   cve_refs: list[CveRef], tool_findings: list[ToolFinding],
                   tool_messages: list[ToolFinding] | None,
                   counts: N.Counts, scan_date: str, provider: str,
                   port_refs: dict[tuple[str, int], list[Finding]] | None = None,
                   plan_stages: list[str] | None = None) -> Appendix:
    has_red = any(f.status == "rot" for f in findings)
    # S6 (spec/08 Punkt 9): Die Freischaltung der Scanner-Adresse wird nur
    # empfohlen, wenn eine Blockade belegt ist. Vorher stand der Satz in jedem
    # Bericht mit irgendeinem Werkzeug ohne Ergebnis.
    has_gaps = C.blockade_belegt(facts)
    return Appendix(
        exposure_scale=[ScaleRow(l=label, t=text) for label, text in T.EXPOSURE_SCALE],
        hygiene_scale=[ScaleRow(l=label, t=text) for label, text in T.HYGIENE_SCALE],
        triage=[TriageRow(l=label, st=status, t=text) for label, status, text in T.triage_rows()],
        overall_rule=L.OVERALL_RULE,
        cve_refs=cve_refs,
        inventory=build_inventory(facts, port_refs),
        tools=build_tools(facts),
        tool_findings=tool_findings,
        tool_messages=list(tool_messages or []),
        dkim_selectors=C.dkim_selectors_for_appendix(facts, output),
        filtering=N.filtering(counts),
        repeat=N.repeat(counts, has_red, has_gaps, plan_stages),
        disclaimer=N.disclaimer(scan_date, provider),
    )

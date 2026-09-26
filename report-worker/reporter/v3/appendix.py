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
from reporter.v3 import chapters as C
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
        if svc.tls_required:
            name = f"{name}, TLS erzwungen"
        elif svc.starttls:
            name = f"{name}, STARTTLS"
        rows.append(InventoryRow(host=svc.host_ip, port=str(svc.port), svc=name,
                                 ref=ref(svc.host_ip, svc.port)))
    for pv in sorted(facts.passive, key=lambda p: (p.host_ip or "", p.port or 0)):
        if not pv.host_ip or not pv.port or pv.host_ip in fremd:
            continue
        if any(r.host == pv.host_ip and r.port == str(pv.port) for r in rows):
            continue
        # E5: Dienstname aus dem Passivmodul ("SMTP") statt "unbekannt".
        name = C.passive_service_label(pv)
        if pv.version:
            name = f"{name} {pv.version}"
        rows.append(InventoryRow(host=pv.host_ip, port=str(pv.port),
                                 svc=f"{name}, laut Passivquelle",
                                 ref=ref(pv.host_ip, pv.port)))
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
    out: list[ToolRow] = []
    for label, purpose, confidence, tools in T.TOOL_ROWS:
        if ran & set(tools):
            out.append(ToolRow(t=label, u=purpose, c=confidence))
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
                   port_refs: dict[tuple[str, int], list[Finding]] | None = None) -> Appendix:
    has_red = any(f.status == "rot" for f in findings)
    # S6 (spec/08 Punkt 9): Die Freischaltung der Scanner-Adresse wird nur
    # empfohlen, wenn eine Blockade belegt ist. Vorher stand der Satz in jedem
    # Bericht mit irgendeinem Werkzeug ohne Ergebnis.
    has_gaps = C.blockade_belegt(facts)
    return Appendix(
        exposure_scale=[ScaleRow(l=label, t=text) for label, text in T.EXPOSURE_SCALE],
        hygiene_scale=[ScaleRow(l=label, t=text) for label, text in T.HYGIENE_SCALE],
        triage=[TriageRow(l=label, st=status, t=text) for label, status, text in T.triage_rows()],
        cve_refs=cve_refs,
        inventory=build_inventory(facts, port_refs),
        tools=build_tools(facts),
        tool_findings=tool_findings,
        tool_messages=list(tool_messages or []),
        dkim_selectors=C.dkim_selectors_for_appendix(facts, output),
        filtering=N.filtering(counts),
        repeat=N.repeat(counts, has_red, has_gaps),
        disclaimer=N.disclaimer(scan_date, provider),
    )

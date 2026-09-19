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
from reporter.v3 import narrative as N
from reporter.v3 import tables as T
from reporter.v3.models import (Appendix, CveRef, Finding, InventoryRow, ScaleRow, ToolFinding,
                                ToolRow, TriageRow)

UNKNOWN = "unbekannt"


def build_inventory(facts: FS.Facts, findings: list[Finding]) -> list[InventoryRow]:
    """Jeder erreichbare Dienst mit Querverweis auf den Befund, der ihn nennt."""
    ref_by_hostport: dict[tuple[str, int], str] = {}
    for f in findings:
        for token in f.affected.split(", "):
            host, _, rest = token.partition(":")
            port = rest.split(" ", 1)[0]
            if port.isdigit():
                ref_by_hostport.setdefault((host, int(port)), f.id)
    rows: list[InventoryRow] = []
    for svc in sorted(facts.services, key=lambda s: (s.host_ip, s.port)):
        if svc.state != "open":
            continue
        name = svc.product or (svc.service or "").upper() or UNKNOWN
        if svc.version_norm:
            name = f"{name} {svc.version_norm}"
        if svc.tls_required:
            name = f"{name}, TLS erzwungen"
        elif svc.starttls:
            name = f"{name}, STARTTLS"
        rows.append(InventoryRow(host=svc.host_ip, port=str(svc.port), svc=name,
                                 ref=ref_by_hostport.get((svc.host_ip, svc.port), "")))
    for pv in sorted(facts.passive, key=lambda p: (p.host_ip or "", p.port or 0)):
        if not pv.host_ip or not pv.port:
            continue
        if any(r.host == pv.host_ip and r.port == str(pv.port) for r in rows):
            continue
        name = pv.product or UNKNOWN
        if pv.version:
            name = f"{name} {pv.version}"
        rows.append(InventoryRow(host=pv.host_ip, port=str(pv.port),
                                 svc=f"{name}, laut Passivquelle",
                                 ref=ref_by_hostport.get((pv.host_ip, pv.port), "")))
    return rows


def build_tools(facts: FS.Facts) -> list[ToolRow]:
    """Nur Werkzeuge, die in diesem Auftrag tatsächlich gelaufen sind."""
    ran = {c.tool for c in facts.coverage if c.status in ("ok", "empty")}
    out: list[ToolRow] = []
    for label, purpose, confidence, tools in T.TOOL_ROWS:
        if ran & set(tools):
            out.append(ToolRow(t=label, u=purpose, c=confidence))
    return out


def build_appendix(facts: FS.Facts, output: CatalogOutput, findings: list[Finding],
                   cve_refs: list[CveRef], tool_findings: list[ToolFinding],
                   counts: N.Counts, scan_date: str, provider: str) -> Appendix:
    has_red = any(f.status == "rot" for f in findings)
    has_gaps = any(c.status in ("failed", "blocked") for c in facts.coverage)
    return Appendix(
        exposure_scale=[ScaleRow(l=label, t=text) for label, text in T.EXPOSURE_SCALE],
        hygiene_scale=[ScaleRow(l=label, t=text) for label, text in T.HYGIENE_SCALE],
        triage=[TriageRow(l=label, st=status, t=text) for label, status, text in T.TRIAGE],
        cve_refs=cve_refs,
        inventory=build_inventory(facts, findings),
        tools=build_tools(facts),
        tool_findings=tool_findings,
        filtering=N.filtering(counts),
        repeat=N.repeat(counts, has_red, has_gaps),
        disclaimer=N.disclaimer(scan_date, provider),
    )

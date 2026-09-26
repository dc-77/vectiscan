# -*- coding: utf-8 -*-
"""Datenmodell des Reports v3.

Struktur und Feldnamen sind exakt die des Prototyps
(``report-prototype/build/report_data.py`` DATA, Abzug in ``out/report-data.json``),
damit das Template aus S4 ohne Umbau darauf rendert. Die kurzen Feldnamen (``c``, ``v``,
``src``, ``st``, ``p``, ``s``, ``l``, ``t``, ``u``) stammen aus dem Prototyp und bleiben
so; sie stehen nur in Tabellenzeilen.

Bewusste Erweiterungen gegenueber dem Prototyp, jede optional und mit Vorgabewert:
``meta.catalog_version``, ``meta.catalog_digest``, ``meta.facts_schema_version``,
``meta.prose_rejected`` (Audit) und ``appendix.tool_findings`` (Werkzeugbefunde ohne
Bewertung, spec/06 Abschnitt 4 Stufe 2).
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- meta

class OrderRef(Base):
    label: str
    id: str


class Meta(Base):
    customer: str
    customer_short: str
    domains: list[str] = Field(default_factory=list)
    package: str
    package_label: str
    scan_date: str
    scan_window: str
    report_date: str
    # S6b-2: Auslieferungsversion (Deckblatt, 1 bei der ersten Freigabe) und die interne
    # Erzeugungsnummer aus reports.version (nur am Ende der Fusszeile).
    report_version: str
    generation: Optional[int] = None
    report_id: str
    orders: list[OrderRef] = Field(default_factory=list)
    # S6b-2 (#28): Nummern der ausgeschlossenen Befunde; genau dort darf die Folge Luecken haben.
    excluded_ids: list[str] = Field(default_factory=list)
    hosts_total: int = 0
    # S6b-2 (spec/09 Nachtrag S6b-1): Zahl der Systeme wie in Kapitel 2.1.
    systems_total: int = 0
    hosts_ipv4: int = 0
    hosts_ipv6: int = 0
    fqdns_total: int = 0
    tool_runs: int = 0
    raw_findings: int = 0
    after_fp: int = 0
    consolidated: int = 0
    positives: int = 0
    policy_version: str = ""
    classification: str = "Vertraulich"
    provider: str = ""
    provider_address: str = ""
    provider_contact: str = ""
    provider_register: str = ""
    provider_responsible: str = ""
    # Erweiterungen v3
    catalog_version: str = ""
    catalog_digest: str = ""
    facts_schema_version: str = ""
    prose_rejected: list[str] = Field(default_factory=list)
    # S6b-1 (spec/09 Q15): Herkunft je Feld des Kundenkontexts (kunde, recherche, admin).
    context_sources: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------- Schicht 1

class GlanceCategory(Base):
    key: str
    name: str
    status: str
    level: int
    note: str = ""


class Lever(Base):
    n: int
    title: str
    effect: str
    refs: list[str] = Field(default_factory=list)


class Glance(Base):
    overall: str
    overall_status: str
    overall_text: str = ""
    categories: list[GlanceCategory] = Field(default_factory=list)
    levers: list[Lever] = Field(default_factory=list)
    context: str = ""
    coverage_warning: str = ""


class ObservedSystem(Base):
    system: str
    meaning: str = ""
    # S6b-1 (spec/09 Q2): belegte Rollen und ihre Belege. Die Prosa-KI bekommt nur
    # belegte Rollen; ein Rollenwort ohne Rolle ist ein Gate-Fehler.
    role_keys: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class Business(Base):
    lead: str = ""
    observed: list[ObservedSystem] = Field(default_factory=list)
    implication: str = ""


# ---------------------------------------------------------------- Schicht 2

class ScopeHost(Base):
    ip: str
    fqdns: str = ""
    operator: str = ""
    role: str = ""
    coverage: str = ""
    cov: str = "keine"
    # S6b-1 (spec/09 Q16): weitere Adressen desselben Systems (IPv6 mit gleichem rDNS).
    more_ips: list[str] = Field(default_factory=list)


class Limitation(Base):
    what: str
    detail: str
    # S6b-1 (spec/09 Q10): Pruefungen in Kundensprache, die diese Ursache betrifft.
    checks: list[str] = Field(default_factory=list)


class DomainScope(Base):
    domain: str
    text: str


class MethodPhase(Base):
    n: str
    name: str
    text: str


class NumberTile(Base):
    v: str
    l: str


class CanCannot(Base):
    can: list[str] = Field(default_factory=list)
    cannot: list[str] = Field(default_factory=list)
    advice: str = ""


class Scope(Base):
    lead: str = ""
    hosts: list[ScopeHost] = Field(default_factory=list)
    domains: list[DomainScope] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    limitations: list[Limitation] = Field(default_factory=list)
    method_phases: list[MethodPhase] = Field(default_factory=list)
    numbers: list[NumberTile] = Field(default_factory=list)
    standard_note: str = ""
    ai_note: str = ""
    can_cannot: CanCannot = Field(default_factory=CanCannot)


class TechRow(Base):
    c: str
    v: str
    src: str
    conf: str
    status: str
    st: str
    note: str = ""


class TechBlock(Base):
    host: str
    rows: list[TechRow] = Field(default_factory=list)


class ServicePort(Base):
    p: str
    s: str
    st: str


class ServiceCard(Base):
    host: str
    label: str = ""
    ports: list[ServicePort] = Field(default_factory=list)


class PostureItem(Base):
    l: str
    ok: Optional[bool] = None
    v: str = ""


class PostureBlock(Base):
    name: str
    short: str
    items: list[PostureItem] = Field(default_factory=list)


class Screenshot(Base):
    file: str
    host: str
    what: str = ""
    # S6b-1 (spec/09 Teil 3): weitere Namen mit derselben Seite (gleicher Inhalt oder
    # gleiches Weiterleitungsziel); das Bild steht nur einmal.
    also: list[str] = Field(default_factory=list)
    # Vollstaendiger MinIO-Schluessel (<order_id>/<ip>__<vhost>.png). ``file`` ist nur
    # der Basisname; bei Berichten ueber mehrere Laeufe laesst sich der Schluessel
    # daraus nicht rekonstruieren, und der Renderer (S4) braucht ihn zum Laden.
    key: str = ""


class Architecture(Base):
    lead: str = ""
    tech: list[TechBlock] = Field(default_factory=list)
    services: list[ServiceCard] = Field(default_factory=list)
    services_note: str = ""
    posture: list[PostureBlock] = Field(default_factory=list)
    screens_lead: str = ""
    screens: list[Screenshot] = Field(default_factory=list)
    reputation: str = ""
    notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------- Schicht 3

class Provenance(Base):
    """Herkunft eines Textblocks (S6b-2, spec/09 Q4): welche Aussage welcher Pruefung ihn
    traegt und fuer welche Mitglieder ihre Bedingung gilt. Nicht Teil des Kundentexts; das
    Gate prueft damit, dass keine Aussage ohne erfuellte Bedingung im Bericht steht.

    ``field``: title, observation, meaning, recommendation, verify, positive.
    ``members``: ``<group_key>|<member_key>`` der fehlgeschlagenen (bei Positivbefunden der
    bestandenen) Mitglieder, fuer die die Aussage steht.
    """
    field: str
    check: str
    statement: str
    members: list[str] = Field(default_factory=list)
    text: str = ""


class Positive(Base):
    cat: str
    title: str
    text: str
    provenance: list[Provenance] = Field(default_factory=list)


class PlanRow(Base):
    prio: str
    st: str
    action: str
    refs: list[str] = Field(default_factory=list)
    effect: str = ""
    # S6b-2 (Q6): Hebeltitel der fuehrenden Regel dieser Zeile, ohne Hostnamen.
    lever: str = ""


class Threat(Base):
    cves: list[str] = Field(default_factory=list)
    # "ja", "nein" oder leer. Leer heisst: zu diesen CVE liegt keine
    # Fremdbewertung vor, also wurde auch der KEV-Katalog nicht abgefragt. Ein
    # "nein" waere dann eine Aussage ueber etwas, das niemand nachgesehen hat.
    kev: str = "nein"
    note: str = ""


class Finding(Base):
    id: str
    cat: str
    status: str
    urgency: str
    title: str
    affected: str
    source: str
    scale: str
    level: str
    # Anzeigetext der Einstufung ("erhöht" statt "erhoeht"). Der Bezeichner
    # bleibt ASCII, der Kundentext nicht (S6, spec/08 Punkt 11).
    level_label: str = ""
    found: str
    evidence: str = ""
    threat: Optional[Threat] = None
    impact: str = ""
    recommendation: list[list[str]] = Field(default_factory=list)
    verify: str = ""
    policy: str = ""
    # S6b-1 (spec/09 Q3): Befund auf einem geteilten System, den der Kunde nicht selbst
    # beheben kann: "beim Hoster" oder "beim Plattformbetreiber", dazu der Satz dazu.
    operator: str = ""
    operator_note: str = ""
    # S6b-2: stabiler Schluessel des Sachverhalts (Regel oder Buendel, Gruppe,
    # Zustaendigkeit); Befund-Ausschluesse (#28) verweisen darauf statt auf die Nummer.
    key: str = ""
    # S6b-2: Herkunft jedes Textblocks und die Massnahme der fuehrenden Regel fuer den Plan.
    provenance: list[Provenance] = Field(default_factory=list)
    plan_action: str = ""
    plan_stage: str = ""
    plan_effect: str = ""
    plan_lever: str = ""


# ---------------------------------------------------------------- Anhang

class ScaleRow(Base):
    l: str
    t: str


class TriageRow(Base):
    l: str
    st: str
    t: str


class CveRef(Base):
    cve: str
    name: str = ""
    score: str = ""
    src: str = ""
    ref: str = ""
    note: str = ""


class InventoryRow(Base):
    host: str
    port: str
    svc: str
    ref: str = ""


class ToolRow(Base):
    t: str
    u: str
    c: str


class ToolFinding(Base):
    what: str
    where: str = ""
    note: str = ""
    # Nachtrag S6b-2 (Entscheidung DC 26.09.): Zusammenfassung je Meldung. Einzelzeilen
    # tragen Regel und Meldungsname, die Anhangzeile die Anzahl der Einzelmeldungen.
    rule: str = ""
    message: Optional[str] = None
    count: int = 1


class Appendix(Base):
    exposure_scale: list[ScaleRow] = Field(default_factory=list)
    hygiene_scale: list[ScaleRow] = Field(default_factory=list)
    triage: list[TriageRow] = Field(default_factory=list)
    cve_refs: list[CveRef] = Field(default_factory=list)
    inventory: list[InventoryRow] = Field(default_factory=list)
    tools: list[ToolRow] = Field(default_factory=list)
    tool_findings: list[ToolFinding] = Field(default_factory=list)
    # Einzelmeldungen hinter ``tool_findings`` fuer den Export (S7), im PDF nicht gerendert.
    tool_messages: list[ToolFinding] = Field(default_factory=list)
    # S6a (#15 Teil 2): abgefragte DKIM-Selektoren, nur wenn DKIM nicht pruefbar war.
    dkim_selectors: list[str] = Field(default_factory=list)
    filtering: str = ""
    repeat: list[str] = Field(default_factory=list)
    disclaimer: str = ""


# ---------------------------------------------------------------- Wurzel

class ReportData(Base):
    meta: Meta
    glance: Glance
    business: Business
    scope: Scope
    architecture: Architecture
    landscape_lead: str = ""
    positives: list[Positive] = Field(default_factory=list)
    plan: list[PlanRow] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    appendix: Appendix

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

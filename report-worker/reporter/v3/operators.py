# -*- coding: utf-8 -*-
"""Zustaendigkeit auf geteilten Systemen (S6b-1, spec/09 Q3 Berichtsteil).

Ein Befund auf einem geteilten System, den der Kunde nicht selbst beheben kann, steht als
"beim Hoster oder Plattformbetreiber" mit Empfehlung an den Betreiber. Welche Pruefung
auf einem Hoster-System beim Betreiber liegt, steht als Daten in
``catalog/tables.SHARED_OPERATOR_CHECKS`` (Entscheidung DC 24.09.2026: Umfang wie in
spec/09 markiert). Auf einer Plattform liegt alles Hostbezogene beim Betreiber, nur
DNS- und Mail-Eintraege der Domain nicht.

Die Einstufung aendert sich dadurch nicht (das ist S6b-2, E1); nur der Adressat.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from reporter.catalog import tables as CT
from reporter.catalog.schema import CheckResult
from reporter.facts import schema as FS
from reporter.facts.systems import registrable

KIND_LABEL = {"hoster": "beim Hoster", "platform": "beim Plattformbetreiber"}
ADDRESSEE = {"hoster": "den Hoster", "platform": "den Plattformbetreiber"}
ASK_AT = {"hoster": "Beim Hoster", "platform": "Beim Plattformbetreiber"}


@dataclass(frozen=True)
class Operator:
    """Zustaendiger Betreiber eines Sachverhalts; ``None`` heisst: der Kunde."""
    kind: str          # hoster | platform
    name: str          # Betreibername laut Fakt, leer wenn unbekannt
    # S6b-3 (spec/10 R17, Entscheidung E11): Zahl der fremden Domains und ihre Quelle; die
    # Namen selbst bleiben in den Fakten und stehen nicht im Kundentext.
    foreign_count: int = 0
    foreign_source: str = ""

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.name}"

    @property
    def label(self) -> str:
        return KIND_LABEL[self.kind]


def hosts_by_ip(facts: FS.Facts) -> dict[str, FS.HostFact]:
    return {h.ip: h for h in facts.hosts}


def operator_for(result: CheckResult, scope: str, hosts: dict[str, FS.HostFact]) -> Optional[Operator]:
    """Betreiber, bei dem dieser Pruefungsbefund liegt, oder ``None`` fuer den Kunden."""
    if scope in CT.PLATFORM_CUSTOMER_SCOPES:
        return None
    host = hosts.get(str(result.vars.get("host_ip") or ""))
    if host is None or host.shared is None:
        return None
    shared = host.shared
    if shared.kind == "platform" or result.check_id in CT.SHARED_OPERATOR_CHECKS:
        domains = {registrable(n) for n in shared.foreign_names if n}
        quelle = ("Passivquelle" if "fremde_namen_shodan" in shared.signals
                  else "Zertifikat" if "fremde_namen_zertifikat" in shared.signals else "")
        return Operator(kind=shared.kind, name=shared.operator or "",
                        foreign_count=len(domains), foreign_source=quelle)
    return None


def sentence(op: Operator) -> str:
    """Satz fuer die Befundkarte: wer zustaendig ist und warum."""
    name = f" {op.name}" if op.name else ""
    if op.kind == "platform":
        return (f"Dieser Sachverhalt liegt beim Plattformbetreiber{name}: der Hostname zeigt auf "
                "dessen Plattform, Server und Grundkonfiguration betreibt er. Die Empfehlung "
                "richtet sich an ihn; Sie können sie über den Vertrag oder die Einstellungen "
                "der Plattform einfordern.")
    fremd = ""
    if op.foreign_count:
        # Auf demselben Server, nicht "auf derselben Adresse": die Namen stammen auch von der
        # IPv6-Adresse desselben Systems (junkerwerk toyota-motorsport.com).
        laut = f" laut {op.foreign_source}" if op.foreign_source else ""
        wort = "weitere Domain" if op.foreign_count == 1 else "weitere Domains"
        fremd = f" (auf demselben Server{laut} {op.foreign_count} {wort} anderer Kunden)"
    return (f"Dieser Sachverhalt liegt beim Hoster{name}: der Server wird mit anderen Kunden "
            f"geteilt{fremd}, der Dienst gehört zum Server und nicht zu Ihrer Website. Die "
            "Empfehlung richtet sich an den Hoster; Sie können sie dort einfordern oder einen "
            "eigenen Server in Betracht ziehen.")


__all__ = ["Operator", "KIND_LABEL", "ADDRESSEE", "ASK_AT", "hosts_by_ip", "operator_for", "sentence"]

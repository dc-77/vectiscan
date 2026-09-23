# -*- coding: utf-8 -*-
"""Konsolidierung: aus Pruefergebnissen werden Sachverhalte.

Der Katalog liefert ein Ergebnis je Pruefung und Gruppe (bis zu einigen Dutzend je
Auftrag). Der Report zeigt Sachverhalte: ein Befund je Sache, hostuebergreifend
(spec/03 Regel 1, spec/05 M3). Dieses Modul macht genau diesen Schritt und nichts sonst,
insbesondere keine Texte und keine Einstufungen; beides kommt aus dem Katalog.

Regeln:

* Eine fehlgeschlagene Gruppe gehoert zum Buendel ihrer Pruefung. Der
  Zusammenfuehrungsschluessel folgt ``merge_by`` des Buendels.
* Eine Pruefung ohne Buendel bildet einen eigenen Sachverhalt; alle ihre Gruppen laufen
  zusammen (hostuebergreifend).
* Positivbefunde laufen immer ueber den ganzen Auftrag zusammen. Eine Gruppe, in der ein
  Mitglied fehlgeschlagen ist, liefert keinen Positivbefund. Gruppen ohne gesehene Items
  bleiben ebenfalls draussen, weil "kein Datenbankdienst" auf einem Host ohne jeden
  Dienst keine Aussage ist. Seit S6 genuegt eine einzige nicht pruefbare Gruppe, um den
  Positivbefund der ganzen Pruefung zu unterdruecken: nicht pruefbar ist nicht bestanden.
* S6a (Issue #30): Ein Buendel kann ``positive_conflicts`` tragen. Steht auf einem Host
  einer dieser Befunde, faellt dieser Host aus dem Positivbefund heraus; bleibt kein
  Host uebrig, entfaellt der Positivbefund. "Keine Windows-Fernwartung (RDP) und keine
  Windows-Dateifreigabe (SMB)" neben FTP auf demselben Host liest sich sonst wie eine
  Entwarnung fuer den ganzen Host.
* Ein aktiv nachgewiesenes Mitglied (``active_proof``) faerbt den Sachverhalt rot,
  unabhaengig von seiner Einstufung; die Abbildung dazu steht in ``levels.py``.
* Skala, Einstufung und Kategorie eines Buendelbefunds kommen vom schwersten
  fehlgeschlagenen Mitglied; der Positivbefund traegt die Kategorie des Buendels.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from reporter.catalog.schema import BundleSpec, CatalogOutput, CheckInfo, CheckResult, Texts
from reporter.facts.serialize import sort_key
from reporter.v3 import levels as L

GLOBAL_KEY = "scan"


@dataclass
class Consolidated:
    """Ein Sachverhalt: ein Befund oder ein Positivbefund des Reports."""

    key: str                       # Buendel-ID oder Pruef-ID
    is_bundle: bool
    merge_key: str
    category: str
    scale: str
    level: str
    title: str                     # Vorlage, noch nicht gerendert
    texts: Texts
    target: str                    # findings | appendix
    positive: bool
    active_proof: bool = False     # aktiv nachgewiesen (S6, siehe levels.py)
    results: list[CheckResult] = field(default_factory=list)
    # S6a: Hosts, die wegen positive_conflicts aus dem Positivbefund herausfallen.
    excluded_hosts: list[str] = field(default_factory=list)

    @property
    def sort_key(self) -> tuple:
        return (L.severity_key(self.scale, self.level), self.category, self.key, self.merge_key)


def _merge_key(result: CheckResult, merge_by: str) -> str:
    if merge_by == "global":
        return GLOBAL_KEY
    if merge_by == "domain":
        if result.group_by == "domain":
            return result.group_key
        return str(result.vars.get("domain") or "") or GLOBAL_KEY
    if merge_by == "host":
        host = result.vars.get("host_ip") or (result.group_key if result.group_by == "host" else "")
        return str(host) or result.group_key
    return result.group_key


def _host_of(result: CheckResult) -> str:
    host = result.vars.get("host_ip") or (result.group_key if result.group_by == "host" else "")
    return str(host or "")


def _conflict_hosts(output: CatalogOutput, bundle: BundleSpec) -> set[str]:
    """Hosts, auf denen ein Befund aus ``positive_conflicts`` des Buendels steht."""
    if not bundle.positive_conflicts:
        return set()
    fehlgeschlagen: set[str] = set()  # Mitgliedsschluessel ip:port mit Fehlschlag
    for r in output.results:
        if r.kind == "check" and r.status == "fail":
            fehlgeschlagen.update(m.key for m in r.members if m.status == "fail")
    hosts: set[str] = set()
    for conflict in bundle.positive_conflicts:
        for r in output.results:
            if conflict.noted_by:
                if r.check_id != conflict.noted_by:
                    continue
                hosts.update(m.host_ip or _host_of(r) for m in r.members
                             if m.key in fehlgeschlagen)
                continue
            if r.kind != "check" or r.status != "fail" or r.check_id not in conflict.checks:
                continue
            fails = [m for m in r.members if m.status == "fail"]
            if conflict.ports:
                hosts.update(m.host_ip or _host_of(r) for m in fails if m.port in conflict.ports)
            else:
                hosts.update(m.host_ip for m in fails if m.host_ip)
                hosts.add(_host_of(r))
    hosts.discard("")
    return hosts


def _worst(results: Iterable[CheckResult]) -> tuple[str, str, str]:
    """(scale, level, category) des schwersten Ergebnisses."""
    worst = min(results, key=lambda r: (L.severity_key(r.scale, r.level), r.check_id))
    return worst.scale, worst.level, worst.category


def consolidate(output: CatalogOutput) -> tuple[list[Consolidated], list[Consolidated]]:
    """(Befunde, Positivbefunde) als Sachverhalte, stabil sortiert."""
    by_check: dict[str, CheckInfo] = {c.id: c for c in output.checks}
    bundles: dict[str, BundleSpec] = {b.id: b for b in output.bundles}
    bundle_of: dict[str, str] = {m: b.id for b in output.bundles for m in b.members}

    fails: dict[tuple[str, str], list[CheckResult]] = {}
    passes: dict[tuple[str, str], list[CheckResult]] = {}
    # S6 (spec/08 Punkt 7): Ein Positivbefund entsteht nur, wenn die Pruefung fuer
    # alle betroffenen Hosts bestanden ist. Nicht pruefbar zaehlt nicht als
    # bestanden; sonst steht "Transportverschluesselung ohne veraltete Protokolle"
    # neben "Protokollliste nicht verfuegbar" fuer fuenf Hosts.
    unpruefbar: set[str] = set()
    for result in output.results:
        if result.kind != "check":
            continue
        bid = bundle_of.get(result.check_id)
        merge_by = bundles[bid].merge_by if bid else "global"
        owner = bid or result.check_id
        if result.status == "fail":
            fails.setdefault((owner, _merge_key(result, merge_by)), []).append(result)
        elif result.status == "not_testable":
            unpruefbar.add(owner)
        elif result.positive:
            # Positivbefunde laufen global zusammen; die Gruppe merken wir uns, um
            # Gruppen mit einem Fehlschlag auszuschliessen.
            passes.setdefault((owner, _merge_key(result, merge_by)), []).append(result)

    findings: list[Consolidated] = []
    for (owner, merge_key), results in fails.items():
        results.sort(key=lambda r: sort_key(r.check_id, r.group_key))
        bundle = bundles.get(owner)
        scale, level, category = _worst(results)
        aktiv = any(r.active_proof for r in results)
        if bundle is not None:
            findings.append(Consolidated(
                key=owner, is_bundle=True, merge_key=merge_key, category=category, scale=scale,
                level=level, title=bundle.title, texts=bundle.texts, target=bundle.target,
                positive=False, active_proof=aktiv, results=results))
        else:
            info = by_check[owner]
            findings.append(Consolidated(
                key=owner, is_bundle=False, merge_key=merge_key, category=info.category,
                scale=info.scale, level=info.level, title=info.title, texts=info.texts,
                target="findings", positive=False, active_proof=aktiv, results=results))

    positives: list[Consolidated] = []
    failed_groups = set(fails)
    by_owner: dict[str, list[CheckResult]] = {}
    konflikt: dict[str, set[str]] = {
        bid: _conflict_hosts(output, bundle) for bid, bundle in bundles.items()
        if bundle.positive_conflicts}
    ausgeschlossen: dict[str, set[str]] = {}
    for (owner, merge_key), results in passes.items():
        if (owner, merge_key) in failed_groups or owner in unpruefbar:
            continue
        for result in results:
            info = by_check[result.check_id]
            if result.items_seen == 0 and info.positive_mode == "absent":
                # "Kein solcher Dienst" auf einem Host ohne jeden Dienst ist keine Aussage.
                continue
            if _host_of(result) in konflikt.get(owner, ()):
                ausgeschlossen.setdefault(owner, set()).add(_host_of(result))
                continue
            by_owner.setdefault(owner, []).append(result)
    for owner, results in by_owner.items():
        results.sort(key=lambda r: sort_key(r.check_id, r.group_key))
        bundle = bundles.get(owner)
        if bundle is not None:
            if bundle.texts.positive is None:
                continue
            positives.append(Consolidated(
                key=owner, is_bundle=True, merge_key=GLOBAL_KEY, category=bundle.category,
                scale="hygiene", level="niedrig", title=bundle.texts.positive.title,
                texts=bundle.texts, target=bundle.target, positive=True, results=results,
                excluded_hosts=sorted(ausgeschlossen.get(owner, ()), key=sort_key)))
        else:
            info = by_check[owner]
            if info.texts.positive is None:
                continue
            positives.append(Consolidated(
                key=owner, is_bundle=False, merge_key=GLOBAL_KEY, category=info.category,
                scale=info.scale, level=info.level, title=info.texts.positive.title,
                texts=info.texts, target="findings", positive=True, results=results))

    findings.sort(key=lambda c: c.sort_key)
    positives.sort(key=lambda c: (c.category, c.key))
    return findings, positives

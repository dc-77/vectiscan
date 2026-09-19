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
  Dienst keine Aussage ist.
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
    results: list[CheckResult] = field(default_factory=list)

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
    for result in output.results:
        if result.kind != "check":
            continue
        bid = bundle_of.get(result.check_id)
        merge_by = bundles[bid].merge_by if bid else "global"
        owner = bid or result.check_id
        if result.status == "fail":
            fails.setdefault((owner, _merge_key(result, merge_by)), []).append(result)
        elif result.positive:
            # Positivbefunde laufen global zusammen; die Gruppe merken wir uns, um
            # Gruppen mit einem Fehlschlag auszuschliessen.
            passes.setdefault((owner, _merge_key(result, merge_by)), []).append(result)

    findings: list[Consolidated] = []
    for (owner, merge_key), results in fails.items():
        results.sort(key=lambda r: sort_key(r.check_id, r.group_key))
        bundle = bundles.get(owner)
        scale, level, category = _worst(results)
        if bundle is not None:
            findings.append(Consolidated(
                key=owner, is_bundle=True, merge_key=merge_key, category=category, scale=scale,
                level=level, title=bundle.title, texts=bundle.texts, target=bundle.target,
                positive=False, results=results))
        else:
            info = by_check[owner]
            findings.append(Consolidated(
                key=owner, is_bundle=False, merge_key=merge_key, category=info.category,
                scale=info.scale, level=info.level, title=info.title, texts=info.texts,
                target="findings", positive=False, results=results))

    positives: list[Consolidated] = []
    failed_groups = set(fails)
    by_owner: dict[str, list[CheckResult]] = {}
    for (owner, merge_key), results in passes.items():
        if (owner, merge_key) in failed_groups:
            continue
        for result in results:
            info = by_check[result.check_id]
            if result.items_seen == 0 and info.positive_mode == "absent":
                # "Kein solcher Dienst" auf einem Host ohne jeden Dienst ist keine Aussage.
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
                texts=bundle.texts, target=bundle.target, positive=True, results=results))
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

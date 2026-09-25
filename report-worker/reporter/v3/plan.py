# -*- coding: utf-8 -*-
"""Maßnahmenplan und die drei Hebel.

Der Plan entsteht aus den Empfehlungsstufen der fehlgeschlagenen Prüfungen: Befunde mit
derselben dringlichsten Stufe und demselben Zusammenführungsschlüssel werden zu einer
Zeile. Jeder Befund steht damit in genau einer Zeile, was der Selbstcheck erzwingt
(spec/03 Regel 7).

S6a: Tragen zwei Zeilen denselben Maßnahmentext (zwei Befundgruppen auf verschiedenen
Hosts oder mit verschiedenen Kategorien), wird daraus eine Zeile mit beiden
Befundlisten und beiden Effekten. Vorher stand dieselbe Maßnahme zweimal im Plan
(Hündgen Seite 11, VS-004/007 gegen VS-006/010).

Die Hebel auf Seite 2 sind die drei gewichtigsten Planzeilen.
"""
from __future__ import annotations

from reporter.v3 import levels as L
from reporter.v3 import narrative as N
from reporter.v3.bundles import Consolidated
from reporter.v3.models import Finding, Lever, PlanRow
from reporter.v3.operators import ASK_AT

MAX_LEVERS = 3
# Trenner mehrerer Effekte einer zusammengeführten Planzeile; die Vorlage setzt daraus
# Zeilenumbrüche (Filter dot_br).
PLAN_EFFECT_SEP = " · "


def _action(item: Consolidated, stage: str) -> str:
    for rec in item.texts.recommendation:
        if rec.stage == stage:
            return rec.text
    return item.texts.recommendation[0].text


def _stage_of(item: Consolidated) -> str:
    """Wirksame Stufe eines Sachverhalts, gedeckelt durch die Abbildungstabelle."""
    return L.stage_for(item.scale, item.level,
                       [rec.stage for rec in item.texts.recommendation],
                       item.active_proof)


def build_plan(pairs: list[tuple[Consolidated, Finding]]) -> list[PlanRow]:
    # S6: Gruppiert wird nach der wirksamen Stufe, nicht nach der dringlichsten
    # Empfehlung des Katalogs. Sonst traegt die Planzeile eines gelben Befunds
    # "Unverzueglich" und eine rote Farbe (spec/08 Punkt 1). Der Massnahmentext
    # bleibt der der dringlichsten Katalogstufe, das ist die konkrete Handlung.
    # S6b-1 (spec/09 Q3): Massnahmen beim Hoster oder Plattformbetreiber stehen in eigenen
    # Zeilen und sagen, an wen sie sich richten.
    groups: dict[tuple[str, str, str], list[tuple[Consolidated, Finding]]] = {}
    for item, finding in pairs:
        op_key = item.operator.key if item.operator else ""
        groups.setdefault((_stage_of(item), item.merge_key, op_key), []).append((item, finding))

    rows: list[tuple[tuple, PlanRow]] = []
    for (stage, merge_key, op_key), members in groups.items():
        members.sort(key=lambda p: (L.severity_key(p[0].scale, p[0].level), p[1].id))
        lead_item, lead_finding = members[0]
        actions: list[str] = []
        for item, _ in members:
            text = _action(item, L.top_stage([rec.stage for rec in item.texts.recommendation]))
            if text not in actions:
                actions.append(text)
        if lead_item.operator is not None:
            actions = [f"{ASK_AT[lead_item.operator.kind]} einfordern: {actions[0]}"] + actions[1:]
        rows.append((
            (L.STAGE_RANK[stage], L.severity_key(lead_item.scale, lead_item.level),
             lead_finding.cat, merge_key, op_key),
            PlanRow(
                prio=L.URGENCY_BY_STAGE[stage],
                st=lead_finding.status,
                action=" ".join(actions),
                refs=[f.id for _, f in members],
                effect=N.PLAN_EFFECT.get(lead_finding.cat, ""),
            ),
        ))
    rows.sort(key=lambda t: t[0])
    # S6a: gleicher Maßnahmentext, eine Zeile. Die erste Zeile ist nach der Sortierung
    # die dringlichste und schwerste; sie behält Stufe und Farbe, die übrigen geben
    # ihre Befunde und Effekte ab.
    out: list[PlanRow] = []
    effects: list[list[str]] = []
    by_action: dict[str, int] = {}
    for _, row in rows:
        key = " ".join(row.action.split())
        index = by_action.get(key)
        if index is None:
            by_action[key] = len(out)
            out.append(row)
            effects.append([row.effect] if row.effect else [])
            continue
        first = out[index]
        first.refs.extend(ref for ref in row.refs if ref not in first.refs)
        if row.effect and row.effect not in effects[index]:
            effects[index].append(row.effect)
    if out and out[0].st == "rot":
        # Der Spitzensatz ersetzt nur den Effekt der Leitgruppe.
        effects[0][:1] = [N.PLAN_EFFECT_TOP]
    for row, row_effects in zip(out, effects):
        unique: list[str] = []
        for effect in row_effects:
            if effect not in unique:
                unique.append(effect)
        row.effect = PLAN_EFFECT_SEP.join(unique)
    return out


def build_levers(plan: list[PlanRow], findings: list[Finding]) -> list[Lever]:
    """Die drei gewichtigsten Planzeilen als Hebel, Titel aus dem fuehrenden Befund."""
    by_id = {f.id: f for f in findings}
    levers: list[Lever] = []
    for row in plan[:MAX_LEVERS]:
        lead = by_id.get(row.refs[0]) if row.refs else None
        if lead is None:
            continue
        levers.append(Lever(
            n=len(levers) + 1,
            title=lead.title,
            effect=row.effect,
            refs=list(row.refs),
        ))
    return levers

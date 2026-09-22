# -*- coding: utf-8 -*-
"""Maßnahmenplan und die drei Hebel.

Der Plan entsteht aus den Empfehlungsstufen der fehlgeschlagenen Prüfungen: Befunde mit
derselben dringlichsten Stufe und demselben Zusammenführungsschlüssel werden zu einer
Zeile. Jeder Befund steht damit in genau einer Zeile, was der Selbstcheck erzwingt
(spec/03 Regel 7).

Die Hebel auf Seite 2 sind die drei gewichtigsten Planzeilen.
"""
from __future__ import annotations

from reporter.v3 import levels as L
from reporter.v3 import narrative as N
from reporter.v3.bundles import Consolidated
from reporter.v3.models import Finding, Lever, PlanRow

MAX_LEVERS = 3


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
    groups: dict[tuple[str, str], list[tuple[Consolidated, Finding]]] = {}
    for item, finding in pairs:
        groups.setdefault((_stage_of(item), item.merge_key), []).append((item, finding))

    rows: list[tuple[tuple, PlanRow]] = []
    for (stage, merge_key), members in groups.items():
        members.sort(key=lambda p: (L.severity_key(p[0].scale, p[0].level), p[1].id))
        lead_item, lead_finding = members[0]
        actions: list[str] = []
        for item, _ in members:
            text = _action(item, L.top_stage([rec.stage for rec in item.texts.recommendation]))
            if text not in actions:
                actions.append(text)
        rows.append((
            (L.STAGE_RANK[stage], L.severity_key(lead_item.scale, lead_item.level),
             lead_finding.cat, merge_key),
            PlanRow(
                prio=L.URGENCY_BY_STAGE[stage],
                st=lead_finding.status,
                action=" ".join(actions),
                refs=[f.id for _, f in members],
                effect=N.PLAN_EFFECT.get(lead_finding.cat, ""),
            ),
        ))
    rows.sort(key=lambda t: t[0])
    out = [row for _, row in rows]
    if out and out[0].st == "rot":
        out[0].effect = N.PLAN_EFFECT_TOP
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

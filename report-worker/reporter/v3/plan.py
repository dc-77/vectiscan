# -*- coding: utf-8 -*-
"""Maßnahmenplan und die drei Hebel.

S6b-2 (spec/09 Q6): eine Zeile je Maßnahmentext. Jeder Befund steht mit der Maßnahme
seiner führenden Regel (der schwersten getroffenen Regel, erste Empfehlung auf deren
wirksamer Stufe) in genau einer Zeile; Befunde mit demselben Maßnahmentext und derselben
Zuständigkeit teilen sich die Zeile. Effekt und Hebeltitel kommen aus der Regel
(``texts.plan``), nicht mehr aus der Kategorie: vorher stand „Schützt die Authentizität
der eigenen E-Mail" bei DNSSEC und CAA, und ein Hebeltitel nannte Hosts, die er nicht
vollständig adressierte. Die übrigen Empfehlungen einer Regel stehen im Befund selbst.

Der Selbstcheck erzwingt, dass jeder Befund im Plan steht (spec/03 Regel 7).
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


def build_plan(pairs: list[tuple[Consolidated, Finding]]) -> list[PlanRow]:
    rows: dict[tuple[str, str], list[tuple[Consolidated, Finding]]] = {}
    for item, finding in pairs:
        op_key = item.operator.key if item.operator else ""
        action = " ".join((finding.plan_action or "").split())
        rows.setdefault((action, op_key), []).append((item, finding))

    out: list[tuple[tuple, PlanRow, list[str]]] = []
    for (action, _op_key), members in rows.items():
        members.sort(key=lambda p: (L.STAGE_RANK.get(p[1].plan_stage, 9),
                                    L.STATUS_RANK.get(p[1].status, 9),
                                    L.severity_key(p[0].scale, p[0].level), p[1].id))
        lead_item, lead = members[0]
        stage = lead.plan_stage or "mittelfristig"
        text = action
        if lead_item.operator is not None:
            text = f"{ASK_AT[lead_item.operator.kind]} einfordern: {action}"
        effects: list[str] = []
        for _, f in members:
            if f.plan_effect and f.plan_effect not in effects:
                effects.append(f.plan_effect)
        out.append((
            (L.STAGE_RANK.get(stage, 9), L.STATUS_RANK.get(lead.status, 9),
             L.severity_key(lead_item.scale, lead_item.level), lead.cat, lead.id),
            PlanRow(prio=L.URGENCY_BY_STAGE.get(stage, stage), st=lead.status, action=text,
                    refs=[f.id for _, f in members], effect="", lever=lead.plan_lever),
            effects,
        ))
    out.sort(key=lambda t: t[0])
    plan: list[PlanRow] = []
    for i, (_, row, effects) in enumerate(out):
        if i == 0 and row.st == "rot":
            # Der Spitzensatz steht vor dem Effekt der Regel; er ist eine Aussage über die
            # Reihenfolge dieses Plans, nicht über die Maßnahme.
            effects = [N.PLAN_EFFECT_TOP] + effects
        row.effect = PLAN_EFFECT_SEP.join(effects)
        plan.append(row)
    return plan


def build_levers(plan: list[PlanRow], findings: list[Finding]) -> list[Lever]:
    """Die drei gewichtigsten Planzeilen als Hebel, Titel aus der führenden Regel."""
    by_id = {f.id: f for f in findings}
    levers: list[Lever] = []
    for row in plan[:MAX_LEVERS]:
        lead = by_id.get(row.refs[0]) if row.refs else None
        if lead is None:
            continue
        levers.append(Lever(
            n=len(levers) + 1,
            title=row.lever or lead.title,
            effect=row.effect,
            refs=list(row.refs),
        ))
    return levers

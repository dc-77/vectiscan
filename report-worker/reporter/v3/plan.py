# -*- coding: utf-8 -*-
"""Maßnahmenplan und die drei Hebel.

S6b-3 (spec/10 R11, Entscheidung E8): eine Planzeile je getroffener Regel mit deren erster
Stufe, getrennt nach Zuständigkeit; der Effekt kommt aus derselben Stufe
(``Recommendation.effect``, sonst ``texts.plan.effect``). Vorher stand nur die führende Regel
eines gebündelten Befunds im Plan; SPF-Hardfail, TLS-RPT neben MTA-STS, DNSSEC neben CAA und
die Header neben HSTS fehlten. Regeln mit demselben Maßnahmentext und derselben
Zuständigkeit teilen sich die Zeile (S6b-2, spec/09 Q6). Die übrigen Stufen einer Regel
stehen im Befund selbst.

Der Selbstcheck erzwingt, dass jeder Befund im Plan steht (spec/03 Regel 7).
Die Hebel auf Seite 2 sind die drei gewichtigsten Planzeilen mit verschiedenem Titel;
eine Zeile beim Hoster oder Plattformbetreiber trägt das im Hebeltitel.
"""
from __future__ import annotations

from reporter.v3 import levels as L
from reporter.v3 import narrative as N
from reporter.v3.bundles import Consolidated
from reporter.v3.models import Finding, Lever, PlanItem, PlanRow
from reporter.v3.operators import ASK_AT

MAX_LEVERS = 3
# S6b-4 (spec/11 T12, Teil 3 HE): Reihenfolge bei gleicher Stufe, Ampel und Einstufung. Ein
# Produkt ohne Herstellerpflege mit Anmeldung geht "Zweck klären" vor (huendgen: Exchange vor den
# Ports ohne Kennung); sonst entscheidet wie bisher die Kategorie.
LEVER_RANK: dict[str, int] = {
    "software_eol": 1, "software_eol_runtime": 1, "cve_kev_listed": 1, "wordpress_plugin_vulnerable": 1,
    "admin_service_exposed": 2, "admin_panel_hoster": 3, "admin_portal_exposed": 3,
    "service_unidentified": 8, "admin_service_unconfirmed": 8, "admin_port_passive_unidentified": 8,
}
# Trenner mehrerer Effekte einer zusammengeführten Planzeile; die Vorlage setzt daraus
# Zeilenumbrüche (Filter dot_br).
PLAN_EFFECT_SEP = " · "


def _items(finding: Finding) -> list[PlanItem]:
    if finding.plan_items:
        return finding.plan_items
    # Reportdaten ohne Planeinträge (ältere Läufe): die Maßnahme der führenden Regel.
    return [PlanItem(check=finding.checks[0] if finding.checks else "", action=finding.plan_action,
                     stage=finding.plan_stage, effect=finding.plan_effect, lever=finding.plan_lever)]


def build_plan(pairs: list[tuple[Consolidated, Finding]]) -> list[PlanRow]:
    rows: dict[tuple[str, str], list[tuple[Consolidated, Finding, PlanItem]]] = {}
    for item, finding in pairs:
        op_key = item.operator.key if item.operator else ""
        for plan_item in _items(finding):
            action = " ".join((plan_item.action or "").split())
            rows.setdefault((action, op_key), []).append((item, finding, plan_item))

    out: list[tuple[tuple, PlanRow, list[str]]] = []
    for (action, _op_key), members in rows.items():
        members.sort(key=lambda p: (L.STAGE_RANK.get(p[2].stage, 9),
                                    L.STATUS_RANK.get(p[1].status, 9),
                                    L.severity_key(p[0].scale, p[0].level), p[1].id))
        lead_item, lead, lead_plan = members[0]
        stage = lead_plan.stage or "mittelfristig"
        text = action
        # S6b-4 (spec/11 T12): Zeile je Regel mit den Betroffenen aller ihrer Befunde.
        details = [pi.detail for _, _, pi in members if pi.per_rule and pi.detail]
        if details:
            text = f"{action}: {'; '.join(dict.fromkeys(details))}"
            action = text
        if lead_item.operator is not None:
            text = f"{ASK_AT[lead_item.operator.kind]} einfordern: {action}"
        effects: list[str] = []
        refs: list[str] = []
        sources: list[str] = []
        for _, f, pi in members:
            if pi.effect and pi.effect not in effects:
                effects.append(pi.effect)
            if f.id not in refs:
                refs.append(f.id)
            if f"{f.id}:{pi.check}" not in sources:
                sources.append(f"{f.id}:{pi.check}")
        out.append((
            (L.STAGE_RANK.get(stage, 9), L.STATUS_RANK.get(lead.status, 9),
             L.severity_key(lead_item.scale, lead_item.level), LEVER_RANK.get(lead_plan.check, 5),
             lead.cat, lead.id, action),
            PlanRow(prio=L.URGENCY_BY_STAGE.get(stage, stage), st=lead.status, action=text,
                    refs=refs, effect="", lever=lead_plan.lever,
                    operator=lead_item.operator.kind if lead_item.operator else "",
                    sources=sources),
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
    """Die drei gewichtigsten Planzeilen als Hebel, nach Titel entdoppelt (spec/10 R11).

    S6b-4 (spec/11 T12): je Befund hoechstens ein Hebel (bergersysteme und castenow VS-001
    trugen Hebel 1 und 2)."""
    by_id = {f.id: f for f in findings}
    levers: list[Lever] = []
    titel: set[str] = set()
    befunde: set[str] = set()
    for row in plan:
        if len(levers) >= MAX_LEVERS:
            break
        lead = by_id.get(row.refs[0]) if row.refs else None
        if lead is None or lead.id in befunde:
            continue
        title = row.lever or lead.title
        if row.operator:
            title = f"{ASK_AT[row.operator]} einfordern: {title}"
        if title in titel:
            continue
        titel.add(title)
        befunde.add(lead.id)
        levers.append(Lever(
            n=len(levers) + 1,
            title=title,
            effect=row.effect,
            refs=list(row.refs),
        ))
    return levers

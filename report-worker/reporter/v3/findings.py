# -*- coding: utf-8 -*-
"""Aus Sachverhalten werden Befunde und Positivbefunde des Reports.

Alle Texte stammen aus dem Katalog; hier werden nur die Platzhalter mit den
zusammengefuehrten Werten gefuellt, der Nachweisblock aus den Faktreferenzen gebaut und
die Quelle benannt. Kein Text wird hier erfunden, keine Einstufung veraendert.

S6b-2 (spec/09 Q4): Titel, Befundtext, Auswirkung, Empfehlung und Verifikation entstehen je
getroffener Regel aus deren eigenen Aussagen. Eine Aussage steht nur, wenn ihre
Fakten-Bedingung fuer die genannten Mitglieder gilt (``Member.holds`` aus der Engine); jede
steht mit ihrer Herkunft in ``Finding.provenance``, und das Gate prueft das nach. Ein
Buendel liefert nur den Sammeltitel.

Threat Intelligence erscheint nur, wenn zu einem betroffenen Dienst ein Fremdwert
vorliegt (NVD-Score oder ein Eintrag im KEV-Katalog). Eine CVE ohne Fremdwert wird nicht
zitiert; damit bleibt Anhang A.3 leer statt unbelegt (spec/03 Regel 2).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from reporter.catalog import render
from reporter.catalog.evidence import merge_parts
from reporter.catalog.schema import CatalogOutput, CheckInfo, CheckResult, Member
from reporter.facts import schema as FS
from reporter.facts.serialize import sort_key
from reporter.v3 import ids as IDS
from reporter.v3 import levels as L
from reporter.v3 import tables as T
from reporter.v3.bundles import GLOBAL_KEY, Consolidated
from reporter.v3.models import CveRef, Finding, PlanItem, Positive, Provenance, Threat, ToolFinding
from reporter.v3.operators import sentence as operator_sentence
from reporter.v3.orthography import clean_foreign_text

MAX_EVIDENCE_LINES = 6

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

# Werkzeuge, deren Aussagen nicht aus einer eigenen Messung stammen.
PASSIVE_TOOLS: frozenset[str] = frozenset({
    "shodan", "abuseipdb", "otx", "urlhaus", "greynoise", "securitytrails", "whois",
    "certspotter", "crtsh", "subfinder",
})

# S6b-2 (spec/09 Q14): Anzeige des Werkzeugs in der Quellenangabe. Die passive
# Webanalyse von ZAP ist eine eigene Messung, aber keine aktive Pruefung.
TOOL_DISPLAY: dict[str, tuple[str, str]] = {
    "zap": ("passiv", "ZAP"),
    "zap_spider": ("passiv", "ZAP"),
    "zap_active": ("aktiv", "ZAP"),
}

# S6b-3 (spec/10 R14): Quellen in 3.1 heissen wie in Anhang C (``tables.TOOL_ROWS``); interne
# Kennungen (cms_fingerprint, redirect_probe, dns_records) stehen nicht im Kundentext.
TOOL_NAMES: dict[str, str] = {
    "dns_records": "DNS-Abfragen",
    "dns_security": "DNS-Abfragen",
    "web_probe": "Webabruf",
    "redirect_probe": "Weiterleitungsprüfung",
    "cms_fingerprint": "CMS-Erkennung",
    "testssl": "testssl.sh",
    "shodan": "Shodan",
    "abuseipdb": "AbuseIPDB",
    "otx": "OTX",
    "urlhaus": "URLhaus",
    "crtsh": "crt.sh",
    "ffuf_param": "ffuf",
    "ffuf_sensitive": "ffuf",
    "securitytrails": "SecurityTrails",
    "certspotter": "Certspotter",
}


# ---------------------------------------------------------------- Hilfen

# S6b-1 (spec/09 Teil 3): kein Platzhalter "den geprüften Hosts" mehr. Die Form ist
# fallneutral, weil die Texte sie im Nominativ ("Die Hosts {group} bieten") und im Dativ
# ("Auf {group} antwortet") einsetzen. S6b-3 (spec/10 R6): bis zu sechs Namen, darueber
# sechs Namen und "und n weitere"; Zahl und Namen kommen aus derselben Liste. Vorher
# stand "(insgesamt 4 Einträge)" hinter drei Namen und las sich wie eine Meldungszahl.
NAMED_GROUPS = 6

# Ein Host mit vielen VHosts traegt sie alle im Gruppennamen, bei vectigal.tech 31 hinter
# einer einzigen IP (spec/08 Punkt 13). In Einschraenkungen (chapters) und Positivbefunden
# stehen deshalb drei Namen und "und weitere".
_GRUPPE_MIT_VHOSTS = re.compile(r"^(?P<kopf>[^(]+) \((?P<namen>[^()]+)\)$")
_VHOSTS_IM_NAMEN = 3


def kurz_label(label: str) -> str:
    treffer = _GRUPPE_MIT_VHOSTS.match(label)
    if not treffer:
        return label
    namen = [n.strip() for n in treffer.group("namen").split(",") if n.strip()]
    if len(namen) <= _VHOSTS_IM_NAMEN:
        return label
    return (f"{treffer.group('kopf')} ("
            f"{', '.join(namen[:_VHOSTS_IM_NAMEN])} und {len(namen) - _VHOSTS_IM_NAMEN} weitere)")


def aufzaehlung(names: list[str]) -> str:
    """"A", "A und B", "A, B und C"."""
    if len(names) <= 1:
        return "".join(names)
    return ", ".join(names[:-1]) + " und " + names[-1]


def _group_label(results: list[CheckResult], groups: list[str], merge_key: str,
                 kurz: bool = False, excluded: list[str] | None = None) -> tuple[str, int]:
    """Wie der Sachverhalt im Text benannt wird, und wie viele Gruppen das sind.

    Eine einzelne Gruppe behaelt ihre ausfuehrliche Bezeichnung aus dem Katalog (IP mit
    Hostnamen, virtueller Host). Laufen mehrere Gruppen zusammen, steht der
    Zusammenfuehrungsschluessel da, also die Host-Adresse oder die Domain; die Namen
    stehen ohnehin in der Betroffenenliste. Ueber den ganzen Auftrag stehen bis zu drei
    Namen, darueber drei Namen und die Gesamtzahl. Mit ``kurz`` (Positivbefunde, S6a)
    nennt jede Gruppe hoechstens drei ihrer virtuellen Hosts. Die Zahl steuert Einzahl
    und Mehrzahl im Text (``{n:Der Host|Die Hosts}``).
    """
    if kurz:
        groups = [kurz_label(g) for g in groups]
    if len(results) == 1:
        label = (groups[0] if groups else "") or results[0].group_label or merge_key
        return (kurz_label(label) if kurz else label), 1
    if merge_key and merge_key != GLOBAL_KEY:
        return merge_key, 1
    count = len(groups)
    if count <= NAMED_GROUPS:
        label = aufzaehlung(groups)
        if excluded and not label:
            label = "keinem Host"
        elif excluded:
            label += f" (außer {aufzaehlung(list(excluded))})"
        return label, max(count, 1)
    label = f"{', '.join(groups[:NAMED_GROUPS])} und {count - NAMED_GROUPS} weitere"
    if excluded:
        label += f" (außer {aufzaehlung(list(excluded))})"
    return label, count


_LABEL_DETAIL = re.compile(r"^(?P<kopf>[^()]+?) \((?P<detail>.+)\)$")


def merge_affected(labels: list[str]) -> list[str]:
    """Ein Eintrag je Name (S6b-1, spec/09 Teil 3).

    Ein Buendel sammelt die Betroffenen mehrerer Pruefungen; derselbe Host stand dann
    zweimal da ("mail.castenow.de", "mail.castenow.de (fehlend: x-frame-options)").
    Gleicher Kopf, verschiedene Angaben laufen in einer Klammer zusammen.
    """
    order: list[str] = []
    details: dict[str, list[str]] = {}
    for label in labels:
        m = _LABEL_DETAIL.match(label)
        kopf, detail = (m.group("kopf"), m.group("detail")) if m else (label, "")
        if kopf not in details:
            order.append(kopf)
            details[kopf] = []
        if detail and detail not in details[kopf]:
            details[kopf].append(detail)
    return [f"{k} ({'; '.join(details[k])})" if details[k] else k for k in order]


def _clean_labels(labels: list[str]) -> list[str]:
    out: list[str] = []
    for a in labels:
        # Betroffenen-Labels tragen Fremdtext (Seitentitel, Bannerzeile) und gehen
        # ueber {affected} in die Befundtexte. Deshalb hier einmal glaetten.
        a = clean_foreign_text(a, limit=200)
        if a and a not in out:
            out.append(a)
    return merge_affected(out)


def merged_vars(results: list[CheckResult], merge_key: str = GLOBAL_KEY,
                kurz: bool = False, excluded: list[str] | None = None,
                operator_labels: dict[str, str] | None = None) -> dict[str, Any]:
    """Platzhalterwerte fuer den zusammengefuehrten Sachverhalt.

    ``operator_labels`` (S6b-3, spec/10 R6): Gruppen auf einem geteilten System tragen im
    Positivbefund "beim Hoster X" hinter ihrem Namen.
    """
    affected: list[str] = []
    groups: list[str] = []
    fqdns: list[str] = []
    notes: list[str] = []
    domain = ""
    host_ip = ""
    operator_labels = operator_labels or {}
    for r in results:
        affected.extend(r.affected)
        label = r.group_label
        if label and r.group_key in operator_labels:
            label = f"{kurz_label(label) if kurz else label}, {operator_labels[r.group_key]}"
        if label and label not in groups:
            groups.append(label)
        for name in r.vars.get("fqdn_names") or []:
            if name not in fqdns:
                fqdns.append(name)
        for note in r.notes:
            if note not in notes:
                notes.append(note)
        domain = domain or str(r.vars.get("domain") or "")
        host_ip = host_ip or str(r.vars.get("host_ip") or "")
    affected = _clean_labels(affected)
    group, n = _group_label(results, groups, merge_key, kurz=kurz, excluded=excluded)
    passed: list[str] = []
    fehlend: list[str] = []
    for r in results:
        for x in r.vars.get("passed") or []:
            if x not in passed:
                passed.append(x)
        for x in r.vars.get("missing_header_names") or []:
            if x not in fehlend:
                fehlend.append(x)
    return {
        "passed": passed,
        "missing_header_names": fehlend,
        "affected": affected,
        "count": len(affected),
        "group": group,
        "n": render.Numerus(n),
        "fqdn_names": fqdns,
        "domain": domain,
        "host_ip": host_ip,
        "notes": notes,
    }


def _render(template: str, values: dict[str, Any], where: str) -> str:
    return render.format_strict(template, values, where)


def _tool_display(tool: str) -> tuple[str, str]:
    """(Art, Anzeigename) eines Werkzeugs fuer die Quellenangabe."""
    if tool in TOOL_DISPLAY:
        return TOOL_DISPLAY[tool]
    return ("passiv" if tool in PASSIVE_TOOLS else "aktiv"), TOOL_NAMES.get(tool, tool)


def evidence_block(results: list[CheckResult]) -> str:
    """Nachweis als Klartextblock: Werkzeug, Fundstelle, woertlicher Auszug.

    Ein Sachverhalt ueber viele virtuelle Hosts bringt je Host eine Zeile mit.
    Der Block endete dabei stumm bei zwoelf Zeilen: der Leser sah zwoelf
    Fundstellen und wusste nicht, dass es mehr sind. Jetzt stehen sechs, und
    die Zeile darunter sagt, wie viele noch dazugehoeren. Wer sie braucht,
    findet die betroffenen Namen vollstaendig in der Betroffenenliste.
    S6b-2 (spec/09 Q7): gleiche Zeilen stehen einmal, auch wenn zwei Werkzeuge sie
    liefern; der Kopf nennt das Werkzeug in der Anzeigeform.
    """
    # Je Fakt eine Zeile (spec/09 Q7): Regeln eines Buendels, die auf denselben Fakt sehen,
    # liefern je eine Teilzeile; sie laufen hier zusammen.
    order: list[tuple[str, str, str]] = []
    teile: dict[tuple[str, str, str], list[str]] = {}
    for r in results:
        for ev in r.evidence:
            if not ev.excerpt:
                continue
            key = (ev.fact_id, ev.tool, ev.ref)
            if key not in teile:
                order.append(key)
                teile[key] = []
            teile[key].append(ev.excerpt)
    lines: list[str] = []
    seen: set[str] = set()
    weitere = 0
    for key in order:
        text = merge_parts(teile[key])
        if text in seen:
            continue
        seen.add(text)
        if len(lines) >= MAX_EVIDENCE_LINES:
            weitere += 1
            continue
        _, name = _tool_display(key[1])
        kopf = f"{name} · {key[2]}" if key[2] else name
        lines.append(f"{kopf}\n{text}")
    if weitere:
        lines.append(f"und {weitere} weitere Fundstellen gleicher Art; "
                     "die betroffenen Namen stehen vollständig unter Betroffen."
                     if weitere > 1 else
                     "und eine weitere Fundstelle gleicher Art; "
                     "die betroffenen Namen stehen vollständig unter Betroffen.")
    return "\n\n".join(lines)


def source_label(results: list[CheckResult]) -> str:
    """Woher die Beobachtung stammt und ob sie aktiv gemessen wurde."""
    active: list[str] = []
    passive: list[str] = []
    for r in results:
        for ev in r.evidence:
            art, name = _tool_display(ev.tool)
            target = passive if art == "passiv" else active
            if name not in target:
                target.append(name)
    if not active and not passive:
        modes = {r.source_mode for r in results}
        return "passiv" if modes == {"passive"} else "aktiv"
    if active and passive:
        return f"aktiv ({', '.join(sorted(active))}), passiv ({', '.join(sorted(passive))})"
    if passive:
        return f"passiv ({', '.join(sorted(passive))})"
    return f"aktiv ({', '.join(sorted(active))})"


def policy_label(results: list[CheckResult], checks: dict[str, CheckInfo]) -> str:
    """Die Regeln, die diesen Befund erzeugt haben.

    Bis S6 stand hier die Herkunft der Einstufung ("catalog_sim R-ADMIN-EXPOSED",
    "Prototyp VS-005"). Das sind interne Begriffe aus der Entstehungsgeschichte
    des Katalogs und im Kundentext nichts wert (spec/08 Punkt 11). Jetzt steht
    dort die Regel, unter der der Befund im Katalog nachschlagbar ist.
    """
    ids: list[str] = []
    for r in results:
        if r.check_id not in ids:
            ids.append(r.check_id)
    return ", ".join(ids)


# ---------------------------------------------------------------- Regeltexte

def _member_ref(result: CheckResult, member: Member) -> str:
    return f"{result.group_key}|{member.key}"


@dataclass
class RuleHit:
    """Eine getroffene Regel innerhalb eines Sachverhalts."""

    check: CheckInfo
    results: list[CheckResult]
    fails: list[tuple[CheckResult, Member]] = field(default_factory=list)
    active_proof: bool = False
    urgent: bool = False

    @property
    def stages(self) -> list[str]:
        return [rec.stage for rec in self.check.texts.recommendation]

    def effective_stage(self, stages: list[str] | None = None) -> str:
        return L.stage_for(self.check.scale, self.check.level,
                           self.stages if stages is None else stages,
                           self.active_proof, self.urgent)


def rule_hits(item: Consolidated, checks: dict[str, CheckInfo]) -> list[RuleHit]:
    """Die getroffenen Regeln eines Befunds, schwerste zuerst (``Consolidated.rules``)."""
    hits: list[RuleHit] = []
    for cid in item.rules:
        info = checks[cid]
        results = [r for r in item.results if r.check_id == cid]
        fails = [(r, m) for r in results for m in r.members if m.status == "fail"]
        hits.append(RuleHit(check=info, results=results, fails=fails,
                            active_proof=any(r.active_proof for r in results),
                            urgent=any(r.urgent for r in results)))
    return hits


@dataclass
class Rendered:
    """Gerenderte Aussage mit Herkunft."""

    field: str
    check: str
    statement: str
    text: str
    members: list[str]
    stage: str = ""
    quantor: str = "alle"
    effect: str = ""

    def provenance(self) -> Provenance:
        return Provenance(field=self.field, check=self.check, statement=self.statement,
                          members=self.members, text=self.text)


def select_statements(hit: RuleHit, name: str, values: dict[str, Any],
                      where: str) -> list[Rendered]:
    """Die Aussagen eines Felds, deren Bedingung gilt, gerendert.

    Quantor ``alle``: die Bedingung gilt fuer jedes fehlgeschlagene Mitglied der Regel.
    Quantor ``eines``: fuer mindestens eines, und ``{affected}`` nennt nur diese.
    """
    out: list[Rendered] = []
    alle_fails = hit.fails
    for sid, text, _cond, quantor in hit.check.texts.statements(name):
        gilt = [(r, m) for r, m in alle_fails if sid in m.holds]
        if not gilt or (quantor == "alle" and len(gilt) != len(alle_fails)):
            continue
        werte = values
        if quantor == "eines" and len(gilt) != len(alle_fails):
            betroffen = _clean_labels([m.label for _, m in gilt])
            werte = dict(values, affected=betroffen, count=len(betroffen))
        rendered = _render(text, werte, f"{where}.{hit.check.id}.{sid}")
        stage = ""
        effect = ""
        if name == "recommendation":
            rec = hit.check.texts.recommendation[int(sid.split("[")[1].rstrip("]"))]
            stage = rec.stage
            effect = rec.effect or ""
        out.append(Rendered(field=name, check=hit.check.id, statement=sid, text=rendered,
                            members=[_member_ref(r, m) for r, m in gilt], stage=stage,
                            quantor=quantor, effect=effect))
    return out


def _join(parts: list[Rendered]) -> str:
    texts: list[str] = []
    for p in parts:
        if p.text not in texts:
            texts.append(p.text)
    return " ".join(texts)


@dataclass
class Composed:
    """Zusammengesetzte Texte eines Befunds."""

    title: str
    found: str
    impact: str
    verify: str
    recommendation: list[list[str]]
    urgency_stage: str
    provenance: list[Provenance]
    plan_action: str
    plan_stage: str
    plan_effect: str
    plan_lever: str
    plan_items: list[PlanItem] = field(default_factory=list)


def compose(item: Consolidated, checks: dict[str, CheckInfo], where: str) -> Composed:
    """Titel und Texte eines Befunds aus den Aussagen seiner getroffenen Regeln."""
    hits = rule_hits(item, checks)
    alle_werte = merged_vars(item.results, item.merge_key)
    teile: dict[str, list[Rendered]] = {"observation": [], "meaning": [], "verify": []}
    empfehlungen: list[tuple[int, int, str, Rendered]] = []
    wirksam: list[str] = []
    plan: Optional[tuple[str, str, str, str]] = None
    plan_items: list[PlanItem] = []
    for reihe, hit in enumerate(hits):
        werte = merged_vars(hit.results, item.merge_key)
        for name in teile:
            teile[name].extend(select_statements(hit, name, werte, where))
        recs = select_statements(hit, "recommendation", werte, where)
        eff = hit.effective_stage([r.stage for r in recs] or None)
        wirksam.append(eff)
        # Q5: die dringlichste Empfehlung steht auf der wirksamen Dringlichkeit der Regel,
        # die weiteren behalten ihren Abstand.
        verschoben = L.relative_stages([r.stage for r in recs], eff)
        for pos, (rec, stufe) in enumerate(zip(recs, verschoben)):
            rec.stage = stufe
            empfehlungen.append((L.STAGE_RANK[stufe], reihe * 100 + pos, rec.text, rec))
        if recs:
            # S6b-3 (spec/10 R11, Entscheidung E8): jede getroffene Regel bringt ihre erste
            # Stufe in den Plan, mit dem Effekt genau dieser Stufe. Vorher kam nur die Regel
            # an erster Stelle in den Plan (SPF-Hardfail, TLS-RPT und CSP fehlten).
            erste = min(zip(verschoben, recs), key=lambda p: L.STAGE_RANK[p[0]])[1]
            texte = hit.check.texts.plan
            effekt = erste.effect or (texte.effect if texte else "")
            hebel = texte.lever if texte else ""
            plan_items.append(PlanItem(check=hit.check.id, action=erste.text, stage=erste.stage,
                                       effect=effekt, lever=hebel))
            if plan is None:
                plan = (erste.text, erste.stage, effekt, hebel)
    empfehlungen.sort(key=lambda t: (t[0], t[1]))
    rec_out: list[list[str]] = []
    rec_prov: list[Provenance] = []
    gesehen: set[str] = set()
    for _, _, text, rec in empfehlungen:
        if text in gesehen:
            continue
        gesehen.add(text)
        rec_out.append([L.URGENCY_BY_STAGE[rec.stage], text])
        rec_prov.append(rec.provenance())

    if item.is_bundle:
        kurz = [hit.check.texts.short or hit.check.title for hit in hits]
        titel_werte = dict(alle_werte, rules=aufzaehlung(kurz))
        title = _render(item.title, titel_werte, f"{where}.title")
        titel_prov = [Provenance(field="title", check=hit.check.id, statement="short",
                                 members=[_member_ref(r, m) for r, m in hit.fails],
                                 text=hit.check.texts.short or hit.check.title) for hit in hits]
    else:
        title = _render(item.title, alle_werte, f"{where}.title")
        titel_prov = [Provenance(field="title", check=hits[0].check.id, statement="title",
                                 members=[_member_ref(r, m) for r, m in hits[0].fails],
                                 text=title)]
    urgency_stage = min(wirksam, key=lambda s: L.STAGE_RANK[s]) if wirksam else \
        L.stage_for(item.scale, item.level, [], item.active_proof, item.urgent)
    prov = titel_prov + [p.provenance() for name in teile for p in teile[name]] + rec_prov
    action, stage, effect, lever = plan or ("", urgency_stage, "", "")
    return Composed(
        title=title, found=_join(teile["observation"]), impact=_join(teile["meaning"]),
        verify=_join(teile["verify"]), recommendation=rec_out, urgency_stage=urgency_stage,
        provenance=prov, plan_action=action, plan_stage=stage, plan_effect=effect,
        plan_lever=lever, plan_items=plan_items)


def recommendations(item: Consolidated, checks: dict[str, CheckInfo]) -> list[list[str]]:
    """Empfehlungen in Stufenreihenfolge, Duplikate entfernt (Q5: relativ zur Dringlichkeit)."""
    return compose(item, checks, f"{item.key}/{item.merge_key}").recommendation


# ---------------------------------------------------------------- Threat Intelligence

# Quellen, deren CVE-Nennung ein Werkzeugbefund ist. ``enrichment`` steht nicht
# darin: eine Anreicherung ohne Fremdwert ist keine Aussage.
WERKZEUG_QUELLEN = frozenset({"testssl"})


def fremdbewertet(t: FS.ThreatFact) -> bool:
    return bool((t.cvss_nvd and t.cvss_nvd.score is not None) or (t.kev and t.kev.listed))


def zitierbar(t: FS.ThreatFact) -> bool:
    return fremdbewertet(t) or t.source in WERKZEUG_QUELLEN


def testssl_tests(facts: FS.Facts) -> dict[str, tuple[str, list[str]]]:
    """CVE-Kennung -> (Test-ID, alle Kennungen desselben Tests).

    S6 (spec/08 Punkt 18): Anhang A.3 fuehrte je Test nur die erste Kennung; bei
    RC4 fehlte CVE-2015-2808, bei ROBOT acht von neun. testssl nennt sie alle in
    derselben Zeile, deshalb steht der Test in einer Zeile mit allen Kennungen.
    """
    out: dict[str, tuple[str, list[str]]] = {}
    for tls in facts.tls:
        for e in tls.entries:
            alle = list(e.cves) or ([e.cve] if e.cve else [])
            if not alle:
                continue
            for cve in alle:
                if cve not in out or len(alle) > len(out[cve][1]):
                    out[cve] = (e.id, alle)
    return out


def _vuln_members(results: list[CheckResult]) -> set[tuple[str, Optional[int], str]]:
    """(Host, Port, testssl-Test) der fehlgeschlagenen TLS-Schwachstellen-Mitglieder."""
    out: set[tuple[str, Optional[int], str]] = set()
    for r in results:
        for m in r.members:
            if m.status != "fail" or "#" not in m.key:
                continue
            out.add((m.host_ip or "", m.port, m.key.rsplit("#", 1)[1]))
    return out


@dataclass
class ThreatIndex:
    """Zitierbare CVE je Host und Port.

    Zwei Faelle, und die Unterscheidung steht im Bericht: eine CVE mit
    Fremdbewertung (NVD-Basiswert oder KEV-Eintrag) und eine CVE, die ein
    Werkzeug selbst genannt hat, ohne dass eine Fremdbewertung vorliegt. Der
    zweite Fall ist seit S5b zugelassen, weil die Phase-3-Anreicherung in keinem
    Produktionslauf je einen Fremdwert geliefert hat (``cves_enriched`` 0 ueber
    42 Auftraege) und die testssl-CVE sonst nirgends auftaucht. Erfunden wird
    dabei nichts: der Basiswert bleibt leer, die Einstufung kommt aus dem Befund.

    Nicht zitiert wird eine CVE ohne beides: weder Fremdwert noch Werkzeug, das
    sie genannt haette.
    """

    by_host_port: dict[tuple[str, Optional[int]], list[FS.ThreatFact]]
    tests: dict[str, tuple[str, list[str]]] = field(default_factory=dict)

    @classmethod
    def build(cls, facts: FS.Facts) -> "ThreatIndex":
        by: dict[tuple[str, Optional[int]], list[FS.ThreatFact]] = {}
        for t in facts.threats:
            if not zitierbar(t):
                continue
            by.setdefault((t.host_ip or "", t.port), []).append(t)
        return cls(by_host_port=by, tests=testssl_tests(facts))

    def for_results(self, results: list[CheckResult],
                    werkzeuge: set[str] | None = None) -> list[FS.ThreatFact]:
        """Threats, die zu diesem Sachverhalt gehoeren.

        Host und Port allein reichen nicht. Eine von testssl genannte CVE haengt
        an Port 443, und an Port 443 haengt auch der Befund zu fehlenden
        Sicherheits-Headern; ohne weitere Bedingung staende die TLS-CVE unter
        einem Header-Befund. Ein werkzeuggestuetzter Threat wird deshalb nur
        zitiert, wenn eine der fehlgeschlagenen Pruefungen dieses Sachverhalts
        genau dieses Werkzeug braucht. Fremdbewertete Threats kommen aus der
        Korrelation und tragen ihre Zuordnung schon mit.

        S6b-2 (spec/09 Q4): Werkzeug und Port reichen auch nicht. Die BREACH-CVE hing bei
        castenow an einem Zertifikatsbefund, weil beide an 443 testssl brauchen. Eine
        testssl-CVE steht jetzt nur an einem Befund, dessen fehlgeschlagenes Mitglied genau
        den testssl-Test getroffen hat, der sie nennt.
        """
        wanted: set[tuple[str, Optional[int]]] = set()
        for r in results:
            for m in r.members:
                if m.status != "fail":
                    continue
                wanted.add((m.host_ip or "", m.port))
                wanted.add((m.host_ip or "", None))
        vulns = _vuln_members(results)
        out: list[FS.ThreatFact] = []
        for key in sorted(wanted, key=lambda k: (k[0], k[1] or 0)):
            for t in self.by_host_port.get(key, []):
                if t in out:
                    continue
                if not fremdbewertet(t):
                    if werkzeuge is not None and t.source not in werkzeuge:
                        continue
                    if t.source == "testssl":
                        test_id = self.tests.get(t.cve_id, ("", []))[0]
                        if (t.host_ip or "", t.port, test_id) not in vulns:
                            continue
                out.append(t)
        return sorted(out, key=lambda t: t.cve_id)


def _threat_note(found: list[FS.ThreatFact]) -> str:
    """Der Begleitsatz darf nicht mehr versprechen, als die Daten hergeben."""
    if all(fremdbewertet(t) for t in found):
        return ("Fremdbewertung; die Zuordnung stützt sich auf die erkannte Version "
                "und wurde nicht durch einen eigenen Nachweis bestätigt.")
    if any(fremdbewertet(t) for t in found):
        return ("Teils Fremdbewertung, teils Werkzeugbefund; die Zuordnung stützt sich auf "
                "die erkannte Version und wurde nicht eigens nachgewiesen.")
    return ("Vom Prüfwerkzeug genannt, ohne Fremdbewertung; die Einstufung dieses Befunds "
            "stammt aus dem Prüfkatalog.")


def _cve_text(t: FS.ThreatFact) -> str:
    if t.cvss_nvd and t.cvss_nvd.score is not None:
        return f"{t.cve_id} (Basiswert {t.cvss_nvd.score} laut NVD)"
    if t.kev and t.kev.listed:
        return f"{t.cve_id} (im KEV-Katalog der CISA gelistet)"
    return f"{t.cve_id} (von {t.source} genannt, keine Fremdbewertung vorhanden)"


# ---------------------------------------------------------------- Befunde

def build_findings(
    output: CatalogOutput,
    items: list[Consolidated],
    facts: FS.Facts,
    *,
    kuerzel: str | None,
    year: int,
    excluded_keys: set[str] | None = None,
    excluded_ids: list[str] | None = None,
) -> tuple[list[Finding], list[CveRef], list[ToolFinding]]:
    """Befunde, Anhang A.3 und die Werkzeugbefunde ohne Bewertung.

    ``excluded_keys`` (#28): Sachverhalte, die der Admin ausgeschlossen hat. Sie bekommen
    ihre Nummer wie ohne Ausschluss und fallen erst danach heraus; die uebrigen Befunde
    behalten damit ihre Nummer ueber jede Neuerzeugung.
    """
    checks = {c.id: c for c in output.checks}
    threats = ThreatIndex.build(facts)
    findings: list[Finding] = []
    cve_refs: list[CveRef] = []
    tool_findings: list[ToolFinding] = []
    seen_cves: dict[str, list[str]] = {}
    excluded_keys = excluded_keys or set()

    alerts = _alert_index(facts)
    index = 0
    for item in items:
        values = merged_vars(item.results, item.merge_key)
        if item.target == "appendix":
            # S6b-2 (spec/09 Teil 2 HL): "Betrifft" ist die Gruppe der einzelnen Meldung,
            # nicht die Sammelbezeichnung des ganzen Anhangbuendels; der Hinweis nennt die
            # Regel auf Deutsch, weil die Werkzeugmeldung selbst englisch heissen kann.
            for r in sorted(item.results, key=lambda r: (r.check_id, r.group_key)):
                if r.status != "fail":
                    continue
                for m in r.members:
                    if m.status != "fail":
                        continue
                    ort = m.fqdn or (f"{m.host_ip}:{m.port}" if m.host_ip and m.port else m.host_ip) or r.group_label
                    regel = f"{r.check_id}#{m.message_id}" if m.message_id else r.check_id
                    note, anzahl = f"{r.title}.", 1
                    alert = alerts.get((m.fqdn or "", m.message_id or "", m.message or ""))
                    if alert is not None:
                        note, anzahl = zap_note(alert) or note, max(alert.count, 1)
                    tool_findings.append(ToolFinding(what=m.label, where=ort, note=note,
                                                     rule=regel, message=m.message, count=anzahl))
            continue
        index += 1
        fid = IDS.finding_id(kuerzel, year, index)
        if item.stable_key in excluded_keys:
            if excluded_ids is not None:
                excluded_ids.append(fid)
            continue
        where = f"{item.key}/{item.merge_key}"
        texte = compose(item, checks, where)
        threat: Optional[Threat] = None
        werkzeuge: set[str] = set()
        for r in item.results:
            info = checks.get(r.check_id)
            if info is not None and any(m.status == "fail" for m in r.members):
                werkzeuge.update(info.requires.tools)
        found = threats.for_results(item.results, werkzeuge)
        if found:
            cves = [_cve_text(t) for t in found]
            if any(t.kev and t.kev.listed for t in found):
                kev = "ja"
            elif any(fremdbewertet(t) for t in found):
                kev = "nein"
            else:
                # Ohne Fremdbewertung wurde der KEV-Katalog nie abgefragt. Ein
                # "nein" behauptete, die CVE stehe nicht darin; niemand hat
                # nachgesehen.
                kev = ""
            threat = Threat(cves=cves, kev=kev, note=_threat_note(found))
            for t in found:
                # Dieselbe CVE kann in mehreren Befunden zitiert werden (ein Host,
                # zwei Sachverhalte). Anhang A.3 fuehrt sie einmal und nennt alle
                # Befunde; der Selbstcheck prueft die Zugehoerigkeit, nicht
                # Gleichheit mit dem ersten Befund.
                if t.cve_id in seen_cves:
                    seen_cves[t.cve_id].append(fid)
                    continue
                seen_cves[t.cve_id] = [fid]
                score = ""
                src = ""
                note = "Werkzeugbefund, keine Fremdbewertung."
                if t.cvss_nvd and t.cvss_nvd.score is not None:
                    score = str(t.cvss_nvd.score)
                    src = "NVD"
                    note = "Fremdwert, nicht selbst vergeben."
                elif t.kev and t.kev.listed:
                    src = "CISA KEV"
                    note = "Fremdwert, nicht selbst vergeben."
                else:
                    src = t.source
                test_id, alle = threats.tests.get(t.cve_id, ("", [t.cve_id]))
                # Die uebrigen Kennungen desselben Tests bekommen keine eigene
                # Zeile mehr; sie stehen in dieser.
                for weitere in alle:
                    seen_cves.setdefault(weitere, []).append(fid)
                cve_refs.append(CveRef(
                    cve=", ".join(alle) if len(alle) > 1 else t.cve_id,
                    name=T.testssl_name(test_id) if test_id else "",
                    score=score, src=src, ref=fid, note=note))
        operator_suffix = ""
        if item.operator:
            # S6b-1: ein Sachverhalt beim Betreiber traegt dessen Zustaendigkeit im Titel;
            # sonst stuende derselbe Katalogtitel zweimal da (Kunde und Hoster getrennt).
            operator_suffix = (f" ({item.operator.label} {item.operator.name})"
                               .replace("  ", " ").replace(" )", ")"))
        findings.append(Finding(
            id=fid,
            cat=item.category,
            status=L.status_for(item.scale, item.level, item.active_proof, item.urgent),
            urgency=L.URGENCY_BY_STAGE[texte.urgency_stage],
            title=texte.title + operator_suffix,
            affected=", ".join(values["affected"]),
            source=source_label(item.results),
            scale=item.scale,
            level=item.level,
            level_label=L.LEVEL_LABELS.get(item.level, item.level),
            found=texte.found,
            evidence=evidence_block(item.results),
            threat=threat,
            impact=texte.impact,
            recommendation=texte.recommendation,
            verify=texte.verify,
            policy=policy_label(item.results, checks),
            operator=(f"{item.operator.label} {item.operator.name}".strip() if item.operator else ""),
            operator_note=operator_sentence(item.operator) if item.operator else "",
            key=item.stable_key,
            provenance=texte.provenance,
            plan_action=texte.plan_action,
            plan_stage=texte.plan_stage,
            plan_effect=texte.plan_effect,
            plan_lever=texte.plan_lever,
            plan_items=texte.plan_items,
            checks=list(item.rules),
            subjects=finding_subjects(item.results),
            missing_headers=missing_headers(item.results),
        ))
    # S6b-3 (spec/10 R14): CVE-Kennungen, die ein Befund aus wpscan zitiert, stehen in A.3 mit
    # ihrer Quelle; vorher stand dort "Keine CVE-Referenzen" neben 17 zitierten Kennungen (DB).
    werkzeug_cves: dict[str, str] = {}
    for sw in facts.software:
        for v in sw.vulnerabilities:
            for cve in v.cves:
                werkzeug_cves.setdefault(cve.upper(), v.title)
    for f in findings:
        text = " ".join((f.found, f.evidence, f.impact))
        for cve in dict.fromkeys(m.upper() for m in _CVE_RE.findall(text)):
            if cve in seen_cves:
                if f.id not in seen_cves[cve]:
                    seen_cves[cve].append(f.id)
                continue
            if cve not in werkzeug_cves:
                continue
            seen_cves[cve] = [f.id]
            cve_refs.append(CveRef(cve=cve, name=clean_foreign_text(werkzeug_cves[cve], limit=120),
                                   score="", src="wpscan", ref=f.id,
                                   note="Quelle wpscan, ohne Fremdbewertung."))
    tool_findings.extend(uncovered_zap_messages(output, facts, alerts))
    for ref in cve_refs:
        erste = ref.cve.split(",")[0].strip()
        befunde: list[str] = []
        for fid in seen_cves.get(erste, [ref.ref]):
            if fid not in befunde:
                befunde.append(fid)
        ref.ref = ", ".join(befunde)
    return findings, cve_refs, tool_findings


def build_positives(items: list[Consolidated]) -> list[Positive]:
    """Positivbefunde; der Text besteht aus den Positivtexten der bestandenen Regeln.

    S6b-2 (spec/09 Q12): Ein Buendel-Positivbefund nennt nur, was jede seiner Regeln
    tatsaechlich bestanden hat; frueher sagte "kein Eintrag zeigt auf ein aufgegebenes
    Ziel" auch, wenn die Pruefung auf verwaiste Eintraege entfallen war.
    """
    out: list[Positive] = []
    for item in items:
        # S6a (spec/08 Punkt 13): bis zu drei VHosts je Host, sonst "und weitere".
        # S6a (#30): ab vier Hosts nennt die Bezeichnung die herausgenommenen Hosts
        # ("insgesamt 5 Einträge, außer 10.0.0.3"); bis zu drei verbleibende Hosts stehen
        # ohnehin namentlich da.
        values = merged_vars(item.results, item.merge_key, kurz=True, excluded=item.excluded_hosts,
                             operator_labels=item.operator_labels)
        where = f"{item.key}/{GLOBAL_KEY}"
        texte: list[str] = []
        prov: list[Provenance] = []
        for cid in item.rules:
            results = [r for r in item.results if r.check_id == cid]
            if not results:
                continue
            info_texts = item.positive_texts.get(cid)
            if info_texts is None:
                continue
            werte = merged_vars(results, item.merge_key, kurz=True, excluded=item.excluded_hosts,
                                operator_labels=item.operator_labels)
            text = _render(info_texts.text, werte, f"{where}.{cid}.positive.text")
            if text not in texte:
                texte.append(text)
            prov.append(Provenance(field="positive", check=cid, statement="positive.text",
                                   members=[r.group_key for r in results], text=text))
        title = _render(item.title, values, f"{where}.positive.title")
        prov.insert(0, Provenance(field="positive", check=",".join(item.rules),
                                  statement="positive.title",
                                  members=[r.group_key for r in item.results], text=title))
        out.append(Positive(cat=item.category, title=title, text=" ".join(texte),
                            provenance=prov, checks=list(item.rules),
                            subjects=positive_subjects(item.results)))
    return out


def finding_subjects(results: list[CheckResult]) -> list[str]:
    """Je Regel die Gruppen und Orte (Host:Port oder Name) der fehlgeschlagenen Mitglieder,
    als "regel|subjekt" (fuer das Gate, spec/10 R4 und R8). Ein Buendel traegt so nicht jede
    Regel an jedem Subjekt seiner Mitglieder."""
    out: set[str] = set()
    for r in results:
        if r.status != "fail":
            continue
        out.add(f"{r.check_id}|{r.group_key}")
        out.update(f"{r.check_id}|{m.key}" for m in r.members if m.status == "fail" and m.key)
    return sorted(out, key=sort_key)


def positive_subjects(results: list[CheckResult]) -> list[str]:
    """Gruppen und bestandene Mitglieder eines Positivbefunds (fuer das Gate, spec/10 R7)."""
    out: set[str] = set()
    for r in results:
        out.add(r.group_key)
        out.update(m.key for m in r.members if m.status == "pass" and m.key)
    return sorted(out, key=sort_key)


def missing_headers(results: list[CheckResult]) -> list[str]:
    """Fehlende Header laut Messung, Anzeigenamen (spec/10 R2)."""
    out: list[str] = []
    for r in results:
        if r.status != "fail":
            continue
        for name in r.vars.get("missing_header_names") or []:
            if name not in out:
                out.append(name)
    return out


# ---------------------------------------------------------------- Anhang: ZAP-Meldungen

def _alert_index(facts: FS.Facts) -> dict[tuple[str, str, str], FS.WebAlert]:
    out: dict[tuple[str, str, str], FS.WebAlert] = {}
    for h in facts.http:
        for a in h.alerts:
            out.setdefault((h.fqdn or "", a.plugin_id or "", a.name), a)
    return out


def zap_note(alert: FS.WebAlert) -> str:
    """Hinweis-Spalte (spec/10 R15): deutscher Titel der ZAP-Regel, bei aktiven Meldungen
    "nicht bestätigt" mit der Konfidenz des Werkzeugs."""
    titel = T.zap_title(alert.plugin_id, alert.name)
    if not titel:
        return ""
    if alert.run == "active":
        konf = T.ZAP_CONFIDENCE.get(alert.confidence or "", "")
        return f"{titel}; aktive Prüfung, nicht bestätigt" + (f", Konfidenz {konf}" if konf else "") + "."
    return f"{titel}."


def uncovered_zap_messages(output: CatalogOutput, facts: FS.Facts,
                           alerts: dict[tuple[str, str, str], FS.WebAlert]) -> list[ToolFinding]:
    """ZAP-Meldungen (Low bis High), die die Ignorierliste einer Pruefung zuschreibt, die an
    dieser Stelle nicht angeschlagen hat (spec/10 R15: castenow X-Powered-By ohne Version).
    Sie standen bisher nirgends im Bericht."""
    fails: set[tuple[str, str]] = set()
    for r in output.results:
        if r.status != "fail":
            continue
        for m in r.members:
            if m.status == "fail":
                fails.update((r.check_id, x) for x in (m.fqdn, m.host_ip) if x)
        fails.update((r.check_id, x) for x in (str(r.vars.get("host_ip") or ""), r.group_key) if x)
        for name in r.vars.get("fqdn_names") or []:
            fails.add((r.check_id, name))
    out: list[ToolFinding] = []
    for item in output.ignored:
        if item.kind != "zap_alert" or not item.covered_by:
            continue
        for fqdn in item.fqdns or [""]:
            if any((cid, x) in fails for cid in item.covered_by for x in (fqdn, item.host_ip) if x):
                continue
            alert = alerts.get((fqdn, item.plugin_id or "", item.name or ""))
            if alert is None or alert.risk not in ("Low", "Medium", "High"):
                continue
            kennung = f"#{alert.plugin_id}" if alert.plugin_id else ""
            out.append(ToolFinding(
                what=f"{alert.name} auf {fqdn}" if fqdn else alert.name,
                where=fqdn or item.host_ip or "",
                note=zap_note(alert) or "Werkzeugmeldung ohne eigene Einstufung.",
                rule=f"zap_uncovered{kennung}", message=alert.name, count=max(alert.count, 1)))
    return out


# ---------------------------------------------------------------- Anhang: eine Zeile je Meldung

# Nachtrag S6b-2 (Entscheidung DC 26.09.): hoechstens sechs Betroffene je Zeile.
MAX_BETROFFENE = 6


def _meldungen(n: int) -> str:
    return "1 Meldung" if n == 1 else f"{n} Meldungen"


def summarize_tool_messages(messages: list[ToolFinding]) -> list[ToolFinding]:
    """Werkzeugmeldungen fuer den Anhang: eine Zeile je Meldung mit Anzahl und Betroffenen.

    Nachtrag S6b-2 (Entscheidung DC 26.09.): vorher stand jede Einzelmeldung in einer
    eigenen Zeile, beim castenow-Vorlauf 4e6b6883 waren das 46. Jetzt eine Zeile je
    ZAP-Regel, testssl-Hinweis, Technik oder Regel ohne Meldungsnamen; die Betroffenen
    (Hosts oder VHosts) stehen in einer Zelle, hoechstens sechs und "und n weitere". Der
    Meldungsname des Werkzeugs steht als Zitat, der Hinweis nennt die Regel auf Deutsch.
    Die Einzelmeldungen bleiben in ``appendix.tool_messages``.
    """
    gruppen: dict[tuple[str, str], list[ToolFinding]] = {}
    for t in messages:
        # S6b-3 (spec/10 R15): eine Zeile je ZAP-Regel und Meldung, gleich ob eine Katalogregel
        # sie aufnahm oder die abdeckende Regel nicht anschlug.
        rule = t.rule
        if "#" in rule and t.message and (rule.startswith("zap_uncovered") or _zap_rule(rule)):
            rule = "zap#" + rule.split("#", 1)[1]
        gruppen.setdefault((rule, t.message or ""), []).append(t)
    out: list[ToolFinding] = []
    for (rule, name), rows in gruppen.items():
        orte = sorted({r.where for r in rows if r.where}, key=sort_key)
        betrifft = ", ".join(orte[:MAX_BETROFFENE])
        if len(orte) > MAX_BETROFFENE:
            betrifft += f" und {len(orte) - MAX_BETROFFENE} weitere"
        first = rows[0]
        if rule == "technik":
            what = first.what
        elif name:
            kennung = rule.split("#", 1)[1] if "#" in rule else ""
            what = f"„{name}“" + (f" (ZAP-Regel {kennung})" if kennung else "")
        else:
            # Ohne Meldungsnamen (TRACE aus OPTIONS, Passivport ohne Kennung): der Regeltitel.
            what = first.note.rstrip(".")
        # S6b-3 (spec/10 R15): die Anzahl steht in jeder Zeile; bei ZAP die Zahl der
        # betroffenen Adressen laut Werkzeug, sonst die Zahl der Einzelmeldungen.
        anzahl = sum(max(r.count, 1) for r in rows)
        what = f"{what}, {_meldungen(anzahl)}"
        note = first.note if (rule == "technik" or name) else "Werkzeugmeldung ohne eigene Einstufung."
        out.append(ToolFinding(what=what, where=betrifft, note=note, rule=rule, message=first.message,
                               count=anzahl))
    return out


_ZAP_APPENDIX_CHECKS = ("info_disclosure", "js_library_outdated", "web_vulnerability_reported")


def _zap_rule(rule: str) -> bool:
    return rule.split("#", 1)[0] in _ZAP_APPENDIX_CHECKS

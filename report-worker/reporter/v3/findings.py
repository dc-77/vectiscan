# -*- coding: utf-8 -*-
"""Aus Sachverhalten werden Befunde und Positivbefunde des Reports.

Alle Texte stammen aus dem Katalog; hier werden nur die Platzhalter mit den
zusammengefuehrten Werten gefuellt, der Nachweisblock aus den Faktreferenzen gebaut und
die Quelle benannt. Kein Text wird hier erfunden, keine Einstufung veraendert.

Threat Intelligence erscheint nur, wenn zu einem betroffenen Dienst ein Fremdwert
vorliegt (NVD-Score oder ein Eintrag im KEV-Katalog). Eine CVE ohne Fremdwert wird nicht
zitiert; damit bleibt Anhang A.3 leer statt unbelegt (spec/03 Regel 2).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from reporter.catalog import render
from reporter.catalog.schema import CatalogOutput, CheckInfo, CheckResult
from reporter.facts import schema as FS
from reporter.v3 import ids as IDS
from reporter.v3 import levels as L
from reporter.v3.bundles import GLOBAL_KEY, Consolidated
from reporter.v3.models import CveRef, Finding, Positive, Threat, ToolFinding
from reporter.v3.orthography import clean_foreign_text

MAX_EVIDENCE_LINES = 12

# Werkzeuge, deren Aussagen nicht aus einer eigenen Messung stammen.
PASSIVE_TOOLS: frozenset[str] = frozenset({
    "shodan", "abuseipdb", "otx", "urlhaus", "greynoise", "securitytrails", "whois",
    "certspotter", "crtsh", "subfinder",
})


# ---------------------------------------------------------------- Hilfen

MANY_GROUPS = "den geprüften Hosts"


def _group_label(results: list[CheckResult], groups: list[str], merge_key: str) -> str:
    """Wie der Sachverhalt im Text benannt wird.

    Eine einzelne Gruppe behaelt ihre ausfuehrliche Bezeichnung aus dem Katalog (IP mit
    Hostnamen, virtueller Host). Laufen mehrere Gruppen zusammen, steht der
    Zusammenfuehrungsschluessel da, also die Host-Adresse oder die Domain; die Namen
    stehen ohnehin in der Betroffenenliste. Ein Sachverhalt ueber den ganzen Auftrag
    bekommt eine Sammelbezeichnung.
    """
    if len(results) == 1:
        return results[0].group_label or merge_key
    if merge_key and merge_key != GLOBAL_KEY:
        return merge_key
    if 0 < len(groups) <= 3:
        return ", ".join(groups)
    return MANY_GROUPS


def merged_vars(results: list[CheckResult], merge_key: str = GLOBAL_KEY) -> dict[str, Any]:
    """Platzhalterwerte fuer den zusammengefuehrten Sachverhalt."""
    affected: list[str] = []
    groups: list[str] = []
    fqdns: list[str] = []
    notes: list[str] = []
    domain = ""
    host_ip = ""
    for r in results:
        for a in r.affected:
            # Betroffenen-Labels tragen Fremdtext (Seitentitel, Bannerzeile) und gehen
            # ueber {affected} in die Befundtexte. Deshalb hier einmal glaetten.
            a = clean_foreign_text(a, limit=200)
            if a and a not in affected:
                affected.append(a)
        if r.group_label and r.group_label not in groups:
            groups.append(r.group_label)
        for name in r.vars.get("fqdn_names") or []:
            if name not in fqdns:
                fqdns.append(name)
        for note in r.notes:
            if note not in notes:
                notes.append(note)
        domain = domain or str(r.vars.get("domain") or "")
        host_ip = host_ip or str(r.vars.get("host_ip") or "")
    return {
        "affected": affected,
        "count": len(affected),
        "group": _group_label(results, groups, merge_key),
        "fqdn_names": fqdns,
        "domain": domain,
        "host_ip": host_ip,
        "notes": notes,
    }


def _render(template: str, values: dict[str, Any], where: str) -> str:
    return render.format_strict(template, values, where)


def evidence_block(results: list[CheckResult]) -> str:
    """Nachweis als Klartextblock: Werkzeug, Fundstelle, woertlicher Auszug."""
    lines: list[str] = []
    seen: set[tuple[str, str]] = set()
    for r in results:
        for ev in r.evidence:
            key = (ev.tool, ev.excerpt)
            if not ev.excerpt or key in seen:
                continue
            seen.add(key)
            lines.append(f"{ev.tool} · {ev.ref}\n{ev.excerpt}")
            if len(lines) >= MAX_EVIDENCE_LINES:
                return "\n\n".join(lines)
    return "\n\n".join(lines)


def source_label(results: list[CheckResult]) -> str:
    """Woher die Beobachtung stammt und ob sie aktiv gemessen wurde."""
    active: list[str] = []
    passive: list[str] = []
    for r in results:
        for ev in r.evidence:
            target = passive if ev.tool in PASSIVE_TOOLS else active
            if ev.tool not in target:
                target.append(ev.tool)
    if not active and not passive:
        modes = {r.source_mode for r in results}
        return "passiv" if modes == {"passive"} else "aktiv"
    if active and passive:
        return f"aktiv ({', '.join(sorted(active))}), bestätigt durch {', '.join(sorted(passive))}"
    if passive:
        return f"passiv ({', '.join(sorted(passive))})"
    return f"aktiv ({', '.join(sorted(active))})"


def policy_label(results: list[CheckResult], checks: dict[str, CheckInfo]) -> str:
    sources: list[str] = []
    for r in results:
        info = checks.get(r.check_id)
        if info and info.policy.source not in sources:
            sources.append(info.policy.source)
    return ", ".join(sources)


def recommendations(item: Consolidated) -> list[list[str]]:
    """Empfehlungen in Stufenreihenfolge, Duplikate entfernt."""
    out: list[tuple[int, str, str]] = []
    seen: set[str] = set()
    for rec in item.texts.recommendation:
        if rec.text in seen:
            continue
        seen.add(rec.text)
        out.append((L.STAGE_RANK.get(rec.stage, 9), L.URGENCY_BY_STAGE[rec.stage], rec.text))
    out.sort(key=lambda t: (t[0], t[2]))
    return [[label, text] for _, label, text in out]


def stages(item: Consolidated) -> list[str]:
    return [rec.stage for rec in item.texts.recommendation]


# ---------------------------------------------------------------- Threat Intelligence

@dataclass
class ThreatIndex:
    """Fremdbewertete CVE je Host und Port. Ohne Fremdwert kein Eintrag."""

    by_host_port: dict[tuple[str, Optional[int]], list[FS.ThreatFact]]

    @classmethod
    def build(cls, facts: FS.Facts) -> "ThreatIndex":
        by: dict[tuple[str, Optional[int]], list[FS.ThreatFact]] = {}
        for t in facts.threats:
            has_score = bool(t.cvss_nvd and t.cvss_nvd.score is not None)
            has_kev = bool(t.kev and t.kev.listed)
            if not (has_score or has_kev):
                continue
            by.setdefault((t.host_ip or "", t.port), []).append(t)
        return cls(by_host_port=by)

    def for_results(self, results: list[CheckResult]) -> list[FS.ThreatFact]:
        wanted: set[tuple[str, Optional[int]]] = set()
        for r in results:
            for m in r.members:
                if m.status != "fail":
                    continue
                wanted.add((m.host_ip or "", m.port))
                wanted.add((m.host_ip or "", None))
        out: list[FS.ThreatFact] = []
        for key in sorted(wanted, key=lambda k: (k[0], k[1] or 0)):
            for t in self.by_host_port.get(key, []):
                if t not in out:
                    out.append(t)
        return sorted(out, key=lambda t: t.cve_id)


def _cve_text(t: FS.ThreatFact) -> str:
    if t.cvss_nvd and t.cvss_nvd.score is not None:
        return f"{t.cve_id} (Basiswert {t.cvss_nvd.score} laut NVD)"
    return f"{t.cve_id} (im KEV-Katalog der CISA gelistet)"


# ---------------------------------------------------------------- Befunde

def build_findings(
    output: CatalogOutput,
    items: list[Consolidated],
    facts: FS.Facts,
    *,
    kuerzel: str | None,
    year: int,
) -> tuple[list[Finding], list[CveRef], list[ToolFinding]]:
    """Befunde, Anhang A.3 und die Werkzeugbefunde ohne Bewertung."""
    checks = {c.id: c for c in output.checks}
    threats = ThreatIndex.build(facts)
    findings: list[Finding] = []
    cve_refs: list[CveRef] = []
    tool_findings: list[ToolFinding] = []
    seen_cves: set[str] = set()

    index = 0
    for item in items:
        values = merged_vars(item.results, item.merge_key)
        if item.target == "appendix":
            for label in values["affected"]:
                tool_findings.append(ToolFinding(
                    what=label, where=values["group"],
                    note="Werkzeugmeldung ohne eigene Einstufung."))
            continue
        index += 1
        fid = IDS.finding_id(kuerzel, year, index)
        where = f"{item.key}/{item.merge_key}"
        threat: Optional[Threat] = None
        found = threats.for_results(item.results)
        if found:
            cves = [_cve_text(t) for t in found]
            kev = "ja" if any(t.kev and t.kev.listed for t in found) else "nein"
            threat = Threat(
                cves=cves, kev=kev,
                note="Fremdbewertung; die Zuordnung stützt sich auf die erkannte Version "
                     "und wurde nicht durch einen eigenen Nachweis bestätigt.")
            for t in found:
                if t.cve_id in seen_cves:
                    continue
                seen_cves.add(t.cve_id)
                score = ""
                src = ""
                if t.cvss_nvd and t.cvss_nvd.score is not None:
                    score = str(t.cvss_nvd.score)
                    src = "NVD"
                elif t.kev and t.kev.listed:
                    src = "CISA KEV"
                cve_refs.append(CveRef(
                    cve=t.cve_id, name="", score=score, src=src, ref=fid,
                    note="Fremdwert, nicht selbst vergeben."))
        findings.append(Finding(
            id=fid,
            cat=item.category,
            status=L.status_for(item.level),
            urgency=L.urgency_for(stages(item)),
            title=_render(item.title, values, f"{where}.title"),
            affected=", ".join(values["affected"]),
            source=source_label(item.results),
            scale=item.scale,
            level=item.level,
            found=_render(item.texts.observation, values, f"{where}.observation"),
            evidence=evidence_block(item.results),
            threat=threat,
            impact=_render(item.texts.meaning, values, f"{where}.meaning"),
            recommendation=recommendations(item),
            verify=_render(item.texts.verify, values, f"{where}.verify"),
            policy=policy_label(item.results, checks),
        ))
    return findings, cve_refs, tool_findings


def build_positives(items: list[Consolidated]) -> list[Positive]:
    out: list[Positive] = []
    for item in items:
        if item.texts.positive is None:
            continue
        values = merged_vars(item.results, item.merge_key)
        if not values["group"]:
            values["group"] = MANY_GROUPS
        where = f"{item.key}/{GLOBAL_KEY}"
        out.append(Positive(
            cat=item.category,
            title=_render(item.texts.positive.title, values, f"{where}.positive.title"),
            text=_render(item.texts.positive.text, values, f"{where}.positive.text"),
        ))
    return out

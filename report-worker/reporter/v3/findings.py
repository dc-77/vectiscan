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
from reporter.v3 import tables as T
from reporter.v3.bundles import GLOBAL_KEY, Consolidated
from reporter.v3.models import CveRef, Finding, Positive, Threat, ToolFinding
from reporter.v3.orthography import clean_foreign_text

MAX_EVIDENCE_LINES = 6

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
    """Nachweis als Klartextblock: Werkzeug, Fundstelle, woertlicher Auszug.

    Ein Sachverhalt ueber viele virtuelle Hosts bringt je Host eine Zeile mit.
    Der Block endete dabei stumm bei zwoelf Zeilen: der Leser sah zwoelf
    Fundstellen und wusste nicht, dass es mehr sind. Jetzt stehen sechs, und
    die Zeile darunter sagt, wie viele noch dazugehoeren. Wer sie braucht,
    findet die betroffenen Namen vollstaendig in der Betroffenenliste.
    """
    lines: list[str] = []
    seen: set[tuple[str, str]] = set()
    weitere = 0
    for r in results:
        for ev in r.evidence:
            key = (ev.tool, ev.excerpt)
            if not ev.excerpt or key in seen:
                continue
            seen.add(key)
            if len(lines) >= MAX_EVIDENCE_LINES:
                weitere += 1
                continue
            kopf = f"{ev.tool} · {ev.ref}" if ev.ref else ev.tool
            lines.append(f"{kopf}\n{ev.excerpt}")
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

    @classmethod
    def build(cls, facts: FS.Facts) -> "ThreatIndex":
        by: dict[tuple[str, Optional[int]], list[FS.ThreatFact]] = {}
        for t in facts.threats:
            if not zitierbar(t):
                continue
            by.setdefault((t.host_ip or "", t.port), []).append(t)
        return cls(by_host_port=by)

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
        """
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
                if t in out:
                    continue
                if not fremdbewertet(t) and werkzeuge is not None and t.source not in werkzeuge:
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
) -> tuple[list[Finding], list[CveRef], list[ToolFinding]]:
    """Befunde, Anhang A.3 und die Werkzeugbefunde ohne Bewertung."""
    checks = {c.id: c for c in output.checks}
    threats = ThreatIndex.build(facts)
    tests = testssl_tests(facts)
    findings: list[Finding] = []
    cve_refs: list[CveRef] = []
    tool_findings: list[ToolFinding] = []
    seen_cves: dict[str, list[str]] = {}

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
                test_id, alle = tests.get(t.cve_id, ("", [t.cve_id]))
                # Die uebrigen Kennungen desselben Tests bekommen keine eigene
                # Zeile mehr; sie stehen in dieser.
                for weitere in alle:
                    seen_cves.setdefault(weitere, []).append(fid)
                cve_refs.append(CveRef(
                    cve=", ".join(alle) if len(alle) > 1 else t.cve_id,
                    name=T.testssl_name(test_id) if test_id else "",
                    score=score, src=src, ref=fid, note=note))
        findings.append(Finding(
            id=fid,
            cat=item.category,
            status=L.status_for(item.scale, item.level, item.active_proof),
            urgency=L.urgency_for(item.scale, item.level, stages(item), item.active_proof),
            title=_render(item.title, values, f"{where}.title"),
            affected=", ".join(values["affected"]),
            source=source_label(item.results),
            scale=item.scale,
            level=item.level,
            level_label=L.LEVEL_LABELS.get(item.level, item.level),
            found=_render(item.texts.observation, values, f"{where}.observation"),
            evidence=evidence_block(item.results),
            threat=threat,
            impact=_render(item.texts.meaning, values, f"{where}.meaning"),
            recommendation=recommendations(item),
            verify=_render(item.texts.verify, values, f"{where}.verify"),
            policy=policy_label(item.results, checks),
        ))
    for ref in cve_refs:
        erste = ref.cve.split(",")[0].strip()
        befunde: list[str] = []
        for fid in seen_cves.get(erste, [ref.ref]):
            if fid not in befunde:
                befunde.append(fid)
        ref.ref = ", ".join(befunde)
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

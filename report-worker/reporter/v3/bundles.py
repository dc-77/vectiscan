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
  Positivbefund der Pruefung zu unterdruecken: nicht pruefbar ist nicht bestanden.
* S6a (Issue #30): Ein Buendel kann ``positive_conflicts`` tragen. Steht auf einem Host
  einer dieser Befunde, faellt dieser Host aus dem Positivbefund heraus; bleibt kein
  Host uebrig, entfaellt der Positivbefund. "Keine Windows-Fernwartung (RDP) und keine
  Windows-Dateifreigabe (SMB)" neben FTP auf demselben Host liest sich sonst wie eine
  Entwarnung fuer den ganzen Host.
* Ein aktiv nachgewiesenes Mitglied (``active_proof``) faerbt den Sachverhalt rot,
  unabhaengig von seiner Einstufung; ebenso eine benannte Ausnahme (``urgent``, S6b-2).
  Die Abbildung dazu steht in ``levels.py``.
* Skala, Einstufung und Kategorie eines Buendelbefunds kommen vom schwersten
  fehlgeschlagenen Mitglied; der Positivbefund traegt die Kategorie des Buendels.
* S6b-1 (spec/09 Q3): Ein Sachverhalt beim Hoster oder Plattformbetreiber laeuft nicht
  mit einem Sachverhalt des Kunden zusammen; die Zustaendigkeit ist Teil des Schluessels
  (``reporter/v3/operators.py``).
* S6b-2 (spec/09 Q4, Q12): Ein Buendel gruppiert nur. Die Texte eines Befunds entstehen
  in ``findings.py`` je getroffener Regel; hier bleibt nur die Zuordnung. Positivbefunde
  entstehen je bestandener Regel: haben alle Mitglieder mit Positivtext bestanden, steht
  der Sammeltitel des Buendels darueber, sonst jede Regel fuer sich. "Nicht pruefbar"
  gilt je Regel, nicht mehr fuer das ganze Buendel; eine entfallene Pruefung (keine
  Items) zaehlt nie als bestanden. Positivbefunde der TLS-Pruefungen gelten nur fuer
  Hosts, deren verschluesselte Dienste alle geprueft sind.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from reporter.catalog.schema import BundleSpec, CatalogOutput, CheckInfo, CheckResult, PositiveText
from reporter.facts import schema as FS
from reporter.facts.serialize import sort_key
from reporter.v3 import levels as L
from reporter.v3.operators import Operator, hosts_by_ip, operator_for

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
    target: str                    # findings | appendix
    positive: bool
    active_proof: bool = False     # aktiv nachgewiesen (S6, siehe levels.py)
    urgent: bool = False           # benannte Ausnahme der Tabelle (S6b-2, E2)
    results: list[CheckResult] = field(default_factory=list)
    # S6a: Hosts, die wegen positive_conflicts aus dem Positivbefund herausfallen.
    excluded_hosts: list[str] = field(default_factory=list)
    # S6b-1: zustaendiger Betreiber auf einem geteilten System, sonst None (Kunde).
    operator: Optional[Operator] = None
    # S6b-2: die Pruefungen, die diesen Sachverhalt tragen, schwerste zuerst, und bei
    # Positivbefunden deren Positivtexte (Vorlagen) je Pruefung.
    rules: list[str] = field(default_factory=list)
    positive_texts: dict[str, PositiveText] = field(default_factory=dict)

    @property
    def sort_key(self) -> tuple:
        return (L.severity_key(self.scale, self.level), self.category, self.key, self.merge_key,
                self.operator.key if self.operator else "")

    @property
    def stable_key(self) -> str:
        """Schluessel fuer Befund-Ausschluesse (#28), stabil ueber Neuerzeugungen."""
        return "/".join((self.key, self.merge_key, self.operator.key if self.operator else "kunde"))


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


# Bereiche, deren Positivbefund eine Aussage ueber die TLS-Dienste eines Hosts ist.
TLS_SCOPES = frozenset({"tls", "tls.vulns"})


def tls_untested_hosts(facts: FS.Facts | None) -> set[str]:
    """Hosts mit einem verschluesselten Dienst, den keine TLS-Pruefung erfasst hat.

    S6b-2 (spec/09 Q12): "Zertifikate unauffaellig" stand bei bergersysteme fuer einen
    Plesk-Server, dessen Mail-TLS auf 110, 143, 465, 993 und 995 nie geprueft wurde; nmap
    zeigte dort selbstsignierte, abgelaufene Zertifikate. Ein Dienst zaehlt als
    verschluesselt, wenn nmap TLS am Port sieht (``tunnel_ssl``) oder STARTTLS meldet.
    """
    if facts is None:
        return set()
    geprueft = {(t.host_ip, t.port) for t in facts.tls}
    out: set[str] = set()
    for svc in facts.services:
        if svc.state != "open":
            continue
        if not (svc.tunnel_ssl or svc.starttls is True):
            continue
        if (svc.host_ip, svc.port) not in geprueft:
            out.add(svc.host_ip)
    return out


def passed(result: CheckResult, info: CheckInfo) -> bool:
    """Hat diese Gruppe die Pruefung mit einer Positivaussage bestanden?

    Gemeinsame Regel fuer Positivbefunde und Posture (S6b-2, spec/09 Q12): bestanden heisst
    Status pass mit Positivaussage und mindestens einem gesehenen Item. Eine entfallene
    Pruefung (etwa keine CNAME-Eintraege zum Abgleich) sagt nichts aus.
    """
    if result.status != "pass" or not result.positive:
        return False
    if result.items_seen == 0 and info.positive_mode == "absent":
        return False
    return True


def _worst(results: Iterable[CheckResult]) -> tuple[str, str, str]:
    """(scale, level, category) des schwersten Ergebnisses."""
    worst = min(results, key=lambda r: (L.severity_key(r.scale, r.level), r.check_id))
    return worst.scale, worst.level, worst.category


def rule_order(results: Iterable[CheckResult]) -> list[str]:
    """Pruefungen eines Sachverhalts, schwerste zuerst, bei Gleichstand nach ID."""
    beste: dict[str, tuple] = {}
    for r in results:
        key = (L.severity_key(r.scale, r.level), r.check_id)
        if r.check_id not in beste or key < beste[r.check_id]:
            beste[r.check_id] = key
    return [cid for cid, _ in sorted(beste.items(), key=lambda kv: kv[1])]


def consolidate(output: CatalogOutput,
                facts: FS.Facts | None = None) -> tuple[list[Consolidated], list[Consolidated]]:
    """(Befunde, Positivbefunde) als Sachverhalte, stabil sortiert.

    Mit ``facts`` trennt die Konsolidierung nach Zustaendigkeit (S6b-1) und prueft, ob die
    verschluesselten Dienste eines Hosts vollstaendig erfasst sind (S6b-2); ohne Fakten
    liegt alles beim Kunden wie bisher.
    """
    by_check: dict[str, CheckInfo] = {c.id: c for c in output.checks}
    bundles: dict[str, BundleSpec] = {b.id: b for b in output.bundles}
    bundle_of: dict[str, str] = {m: b.id for b in output.bundles for m in b.members}
    hosts = hosts_by_ip(facts) if facts is not None else {}
    operators: dict[str, Operator] = {}
    tls_offen = tls_untested_hosts(facts)

    fails: dict[tuple[str, str, str], list[CheckResult]] = {}
    passes: dict[tuple[str, str], list[CheckResult]] = {}
    # S6 (spec/08 Punkt 7): nicht pruefbar ist nicht bestanden. S6b-2: je Pruefung, nicht
    # fuer das ganze Buendel; sonst loeschte ein nicht pruefbares DKIM den SPF-Positivbefund.
    unpruefbar: set[str] = set()
    for result in output.results:
        if result.kind != "check":
            continue
        bid = bundle_of.get(result.check_id)
        merge_by = bundles[bid].merge_by if bid else "global"
        owner = bid or result.check_id
        if result.status == "fail":
            op = operator_for(result, by_check[result.check_id].scope, hosts) if hosts else None
            op_key = op.key if op else ""
            if op is not None:
                operators[op_key] = op
            fails.setdefault((owner, _merge_key(result, merge_by), op_key), []).append(result)
        elif result.status == "not_testable":
            unpruefbar.add(result.check_id)
        elif result.positive:
            # Positivbefunde laufen global zusammen; die Gruppe merken wir uns, um
            # Gruppen mit einem Fehlschlag im selben Buendel auszuschliessen.
            passes.setdefault((owner, _merge_key(result, merge_by)), []).append(result)

    findings: list[Consolidated] = []
    for (owner, merge_key, op_key), results in fails.items():
        results.sort(key=lambda r: sort_key(r.check_id, r.group_key))
        bundle = bundles.get(owner)
        scale, level, category = _worst(results)
        aktiv = any(r.active_proof for r in results)
        dringend = any(r.urgent for r in results)
        if bundle is not None:
            findings.append(Consolidated(
                key=owner, is_bundle=True, merge_key=merge_key, category=category, scale=scale,
                level=level, title=bundle.title, target=bundle.target, positive=False,
                active_proof=aktiv, urgent=dringend, results=results,
                operator=operators.get(op_key), rules=rule_order(results)))
        else:
            info = by_check[owner]
            findings.append(Consolidated(
                key=owner, is_bundle=False, merge_key=merge_key, category=info.category,
                scale=info.scale, level=info.level, title=info.title, target="findings",
                positive=False, active_proof=aktiv, urgent=dringend, results=results,
                operator=operators.get(op_key), rules=[owner]))

    failed_groups = {(owner, merge_key) for owner, merge_key, _ in fails}
    konflikt: dict[str, set[str]] = {
        bid: _conflict_hosts(output, bundle) for bid, bundle in bundles.items()
        if bundle.positive_conflicts}
    ausgeschlossen: dict[str, set[str]] = {}
    je_regel: dict[str, list[CheckResult]] = {}
    for (owner, merge_key), results in passes.items():
        if (owner, merge_key) in failed_groups:
            continue
        for result in results:
            info = by_check[result.check_id]
            if result.check_id in unpruefbar or info.texts.positive is None:
                continue
            if not passed(result, info):
                continue
            host = _host_of(result)
            if host in konflikt.get(owner, ()):
                ausgeschlossen.setdefault(owner, set()).add(host)
                continue
            if info.scope in TLS_SCOPES and host in tls_offen:
                continue
            je_regel.setdefault(result.check_id, []).append(result)

    positives: list[Consolidated] = []

    def _positive(key: str, is_bundle: bool, category: str, title: str, rules: list[str],
                  owner: str) -> None:
        results = [r for cid in rules for r in je_regel[cid]]
        results.sort(key=lambda r: sort_key(r.check_id, r.group_key))
        positives.append(Consolidated(
            key=key, is_bundle=is_bundle, merge_key=GLOBAL_KEY, category=category,
            scale="hygiene", level="niedrig", title=title, target="findings", positive=True,
            results=results, rules=rules,
            positive_texts={cid: by_check[cid].texts.positive for cid in rules
                            if by_check[cid].texts.positive is not None},
            excluded_hosts=sorted(ausgeschlossen.get(owner, ()), key=sort_key)))

    for bid, bundle in bundles.items():
        if bundle.target != "findings":
            continue
        mitglieder = [m for m in bundle.members if m in by_check and by_check[m].texts.positive]
        bestanden = [m for m in mitglieder if m in je_regel]
        if not bestanden:
            continue
        if bundle.positive_title and bestanden == mitglieder:
            _positive(bid, True, bundle.category, bundle.positive_title, bestanden, bid)
            continue
        for cid in bestanden:
            info = by_check[cid]
            assert info.texts.positive is not None
            _positive(cid, False, info.category, info.texts.positive.title, [cid], bid)
    for cid in sorted(je_regel):
        if cid in bundle_of:
            continue
        info = by_check[cid]
        assert info.texts.positive is not None
        _positive(cid, False, info.category, info.texts.positive.title, [cid], cid)

    findings.sort(key=lambda c: c.sort_key)
    positives.sort(key=lambda c: (c.category, c.key))
    return findings, positives

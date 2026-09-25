"""Engine des Pruefkatalogs: laden, kompilieren, auswerten.

Ablauf je Check und Gruppe (README, Abschnitt "Statuslogik"):
1. Domain-Gruppe ohne DNS-Fakten -> not_testable mit Grund aus der Abdeckung.
2. ``applicable_when`` falsch -> not_applicable.
3. ``not_testable_when`` (Gruppenkontext) trifft -> not_testable(reason_code).
4. Je Item: ``when`` wahr -> fail (bei ``kind: note`` ein Hinweis); sonst Item-Regeln aus
   ``not_testable_when`` (context item); sonst ``positive_when`` (Ausdruck) -> pass oder
   ``undetermined``; bei ``absent``/``never`` zaehlt ein gesehenes Item als pass.
5. Gruppe: fail > not_testable > pass > not_applicable. Ohne Items entscheidet die
   Abdeckung der Werkzeuge aus ``requires.tools`` (COVERAGE_REASONS).
6. ``positive`` nur bei pass mit ``texts.positive`` und (``absent`` oder mindestens einem
   Item, das den Positivausdruck erfuellt).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import ValidationError

from reporter.catalog import render
from reporter.catalog import tables as T
from reporter.catalog.catchall import run_catchalls
from reporter.catalog.evidence import KEEP_FACT_EVIDENCE, auszug, detail_evidence, ist_redundant
from reporter.catalog.expr import CatalogSpecError, Expr, compile_expr
from reporter.catalog.schema import (CATEGORY_NAMES, LEVEL_LABELS, BundleSpec, CatalogOutput, CheckInfo,
                                     CheckResult, CheckRollup, CheckSpec, EvidenceRef, IgnoreList, Member,
                                     NotTestableRule, RenderedTexts, Summary)
from reporter.catalog.scope import FactsIndex, Group, Item, build_groups, binding_types, without_third_party
from reporter.catalog.version import CATALOG_DIR, CATALOG_VERSION, catalog_digest
from reporter.facts import schema as FS
from reporter.facts.serialize import sort_key

STATUS_ORDER = {"fail": 0, "pass": 1, "not_testable": 2, "not_applicable": 3}
DNS_SCOPES = ("dns", "dns.dangling_cnames", "target")
MAX_EVIDENCE = 40


@dataclass
class CompiledCheck:
    spec: CheckSpec
    when: Optional[Expr]
    positive: Optional[Expr]
    applicable: Optional[Expr]
    nt_group: list[tuple[NotTestableRule, Expr]]
    nt_item: list[tuple[NotTestableRule, Expr]]
    item_filter: Optional[Expr] = None
    active_proof: Optional[Expr] = None
    urgent: Optional[Expr] = None
    path: Optional[Path] = None
    # S6b-2: (Aussage-ID, Bedingung) aller Textaussagen; ohne eigene Bedingung None.
    statements: list[tuple[str, Optional[Expr]]] = field(default_factory=list)
    # S6b-2 (spec/09 Q7): Fakten, auf die die Regel sieht; daraus entsteht der Nachweis.
    evidence_paths: frozenset[str] = frozenset()


@dataclass
class Catalog:
    checks: list[CompiledCheck]
    ignore: IgnoreList
    version: str
    digest: str
    dir: Path
    bundles: list[BundleSpec] = field(default_factory=list)
    by_id: dict[str, CompiledCheck] = field(default_factory=dict)
    bundle_by_id: dict[str, BundleSpec] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.by_id = {c.spec.id: c for c in self.checks}
        self.bundle_by_id = {b.id: b for b in self.bundles}

    @property
    def specs(self) -> list[CheckSpec]:
        return [c.spec for c in self.checks]


# ---------------------------------------------------------------- Laden


def load_yaml(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8-sig") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise CatalogSpecError(f"{path.name}: YAML muss ein Mapping sein")
    return data


def load_check(path: Path) -> CheckSpec:
    data = load_yaml(path)
    try:
        spec = CheckSpec.model_validate(data)
    except ValidationError as exc:
        raise CatalogSpecError(f"{path.name}: {exc}") from None
    if spec.id != path.stem:
        raise CatalogSpecError(f"{path.name}: id {spec.id!r} muss dem Dateinamen entsprechen")
    return spec


def load_bundle(path: Path) -> BundleSpec:
    data = load_yaml(path)
    try:
        spec = BundleSpec.model_validate(data)
    except ValidationError as exc:
        raise CatalogSpecError(f"{path.name}: {exc}") from None
    if spec.id != path.stem:
        raise CatalogSpecError(f"{path.name}: id {spec.id!r} muss dem Dateinamen entsprechen")
    return spec


def _link_bundles(compiled: list[CompiledCheck], bundles: list[BundleSpec]) -> list[BundleSpec]:
    """Beide Seiten der Zuordnung muessen uebereinstimmen, sonst Ladefehler.

    Mitglieder, deren Pruefung in diesem Katalogverzeichnis gar nicht liegt, werden
    stillschweigend entfernt; ein Buendel ohne verbleibendes Mitglied faellt weg. Damit
    bleibt ein bewusst verkleinerter Katalog (Testaufbau) ladbar, waehrend ein Tippfehler
    im vollstaendigen Katalog weiter ein Fehler ist: die Pruefung traegt dann ein
    ``bundle``, das ihre Buenddatei nicht auffuehrt.
    """
    by_id = {c.spec.id: c.spec for c in compiled}
    known = {b.id for b in bundles}
    declared: dict[str, str] = {}
    linked: list[BundleSpec] = []
    for bundle in bundles:
        members = []
        for member in bundle.members:
            spec = by_id.get(member)
            if spec is None:
                continue
            if member in declared:
                raise CatalogSpecError(
                    f"bundle {bundle.id}: Pruefung {member!r} steht schon in {declared[member]!r}")
            declared[member] = bundle.id
            if spec.bundle != bundle.id:
                raise CatalogSpecError(
                    f"{member}: bundle {spec.bundle!r} passt nicht zu bundles/{bundle.id}.yaml")
            members.append(member)
        if members:
            # S6a: Konflikte auf Pruefungen, die in diesem Katalog nicht liegen, fallen
            # wie Mitglieder still weg (Testaufbau). Im vollstaendigen Katalog prueft
            # tests/catalog/test_schema_and_table.py, dass jede genannte ID existiert.
            conflicts = []
            for conflict in bundle.positive_conflicts:
                if conflict.noted_by:
                    if conflict.noted_by in by_id:
                        conflicts.append(conflict)
                    continue
                known_checks = [c for c in conflict.checks if c in by_id]
                if known_checks:
                    conflicts.append(conflict.model_copy(update={"checks": known_checks}))
            linked.append(bundle.model_copy(
                update={"members": members, "positive_conflicts": conflicts}))
    for spec in by_id.values():
        if not spec.bundle:
            continue
        if spec.bundle not in known:
            raise CatalogSpecError(f"{spec.id}: bundle {spec.bundle!r} hat keine Datei unter bundles/")
        if declared.get(spec.id) != spec.bundle:
            raise CatalogSpecError(
                f"{spec.id}: steht nicht in members von bundles/{spec.bundle}.yaml")
    return linked


def compile_check(spec: CheckSpec, path: Path | None = None) -> CompiledCheck:
    where = f"check {spec.id}"
    types_ = binding_types(spec.scope, spec.group_by)
    tables = T.EXPR_TABLES

    def comp(text: str | None, part: str) -> Optional[Expr]:
        if text is None:
            return None
        return compile_expr(text, where=f"{where} {part}", types_=types_, tables=tables)

    when = comp(spec.when, "when")
    positive = comp(spec.positive_when, "positive_when") if spec.positive_mode == "expr" else None
    applicable = comp(spec.applicable_when, "applicable_when")
    item_filter = comp(spec.item_when, "item_when")
    active_proof = comp(spec.active_proof_when, "active_proof_when")
    urgent = comp(spec.urgent_when, "urgent_when")
    nt_group: list[tuple[NotTestableRule, Expr]] = []
    nt_item: list[tuple[NotTestableRule, Expr]] = []
    for i, rule in enumerate(spec.not_testable_when):
        ex = comp(rule.when, f"not_testable_when[{i}]")
        assert ex is not None
        (nt_item if rule.context == "item" else nt_group).append((rule, ex))
    if spec.positive_mode == "absent" and not spec.requires.tools:
        raise CatalogSpecError(f"{where}: positive_when absent braucht requires.tools")
    render.validate_template(spec.affected_template, render.ITEM_VARS[spec.scope], f"{where} affected_template")
    if spec.texts.positive:
        render.validate_template(spec.texts.positive.title, render.OBSERVATION_VARS, f"{where} texts.positive.title")
        render.validate_template(spec.texts.positive.text, render.OBSERVATION_VARS, f"{where} texts.positive.text")
    render.validate_template(spec.title, render.OBSERVATION_VARS, f"{where} title")
    if spec.texts.short is not None:
        render.validate_template(spec.texts.short, (), f"{where} texts.short")
    if spec.texts.plan is not None:
        render.validate_template(spec.texts.plan.lever, (), f"{where} texts.plan.lever")
        render.validate_template(spec.texts.plan.effect, (), f"{where} texts.plan.effect")
    # S6b-2: jede Aussage wird wie ``when`` kompiliert; eine Bedingung, die der Compiler
    # nicht kennt, ist ein Ladefehler und kein stilles Weglassen im Bericht.
    statements: list[tuple[str, Optional[Expr]]] = []
    for sid, text, cond, _quantor in spec.texts.all_statements():
        render.validate_template(text, render.OBSERVATION_VARS, f"{where} {sid}")
        statements.append((sid, comp(cond, sid)))
    paths: set[str] = set()
    for ex in (when, applicable, item_filter):
        if ex is not None:
            paths |= set(ex.paths)
    return CompiledCheck(spec=spec, when=when, positive=positive, applicable=applicable, nt_group=nt_group,
                         nt_item=nt_item, item_filter=item_filter, active_proof=active_proof, urgent=urgent,
                         path=path, statements=statements, evidence_paths=frozenset(paths))


def load_catalog(catalog_dir: Path | str | None = None) -> Catalog:
    base = Path(catalog_dir) if catalog_dir else CATALOG_DIR
    files = sorted((base / "checks").glob("*.yaml"), key=lambda p: p.name)
    if not files:
        raise CatalogSpecError(f"keine Pruefungen unter {base / 'checks'}")
    compiled: list[CompiledCheck] = []
    seen: set[str] = set()
    for path in files:
        spec = load_check(path)
        if spec.id in seen:
            raise CatalogSpecError(f"{path.name}: doppelte id {spec.id!r}")
        seen.add(spec.id)
        compiled.append(compile_check(spec, path))
    ignore_path = base / "ignore.yaml"
    if ignore_path.exists():
        try:
            ignore = IgnoreList.model_validate(load_yaml(ignore_path))
        except ValidationError as exc:
            raise CatalogSpecError(f"ignore.yaml: {exc}") from None
    else:
        ignore = IgnoreList()
    bundles = [load_bundle(p) for p in sorted((base / "bundles").glob("*.yaml"), key=lambda p: p.name)]
    bundles = _link_bundles(compiled, bundles)
    compiled.sort(key=lambda c: c.spec.id)
    return Catalog(checks=compiled, ignore=ignore, version=CATALOG_VERSION, digest=catalog_digest(base),
                   dir=base, bundles=bundles)


_DEFAULT: dict[str, Catalog] = {}


def default_catalog() -> Catalog:
    key = str(CATALOG_DIR)
    if key not in _DEFAULT:
        _DEFAULT[key] = load_catalog()
    return _DEFAULT[key]


def reset_default_catalog() -> None:
    _DEFAULT.clear()


# ---------------------------------------------------------------- Auswertung


def _reason(code: str | None) -> tuple[str, str, str]:
    """(status, reason_code, text) fuer einen Coverage- oder Regelcode."""
    code = code or "insufficient_facts"
    status, text = T.COVERAGE_REASONS.get(code, ("not_testable", T.GENERIC_NOT_TESTABLE))
    return status, code, text


def _evidence_of(obj: Any) -> list[EvidenceRef]:
    fid = getattr(obj, "id", None)
    evs = getattr(obj, "evidence", None)
    if not fid or not evs:
        return []
    # S6b-2 (spec/09 Q7): ein von der Faktenschicht gekuerzter Auszug traegt den Hinweis
    # "(Auszug)" statt drei Punkten; Rueckfall-Fundstellen der Datenbank stehen nicht da.
    return [EvidenceRef(fact_id=fid, tool=e.tool, ref="" if e.ref.startswith("scan_results:") else e.ref,
                        excerpt=auszug(e.excerpt)) for e in evs]


def _source_mode(modes: list[str]) -> str:
    s = set(modes)
    if not s:
        return "none"
    if s == {"active"}:
        return "active"
    if s == {"passive"}:
        return "passive"
    return "mixed"


def _member(item: Item, label: str, status: str, *, reason_code: str | None = None,
            holds: list[str] | None = None, urgent: bool = False) -> Member:
    reason = None
    if reason_code:
        _, _, reason = _reason(reason_code)
    return Member(key=item.key, host_ip=item.host_ip, fqdn=item.fqdn, port=item.port, label=label, status=status,
                  reason_code=reason_code, reason=reason, fact_ids=[item.fact.id], source_mode=item.source_mode,
                  verified=item.verified, via_cdn=item.via_cdn, alias_of=item.alias_of,
                  holds=list(holds or []), urgent=urgent)


class _Eval:
    def __init__(self, cc: CompiledCheck, index: FactsIndex, claimed: set[str]):
        self.cc = cc
        self.spec = cc.spec
        self.index = index
        self.claimed = claimed

    def group(self, g: Group) -> CheckResult:
        spec = self.spec
        gctx = g.ctx
        if g.kind == "domain" and spec.scope in DNS_SCOPES and gctx.get("dns") is None:
            return self.result(g, "not_testable", reason_code=g.dns_missing_reason or "no_dns_facts")
        if self.cc.applicable is not None and not self.cc.applicable.test(gctx):
            return self.result(g, "not_applicable", reason_code="precondition_not_met")
        for rule, ex in self.cc.nt_group:
            if not ex.test(gctx):
                continue
            if rule.reason_code.startswith("coverage:"):
                st, reason = g.coverage(self.index, rule.reason_code[len("coverage:"):])
                if st == "ok":
                    continue
                status, code, _ = _reason(reason or st)
                if status == "ok":
                    continue
                return self.result(g, status, reason_code=code)
            return self.result(g, "not_testable", reason_code=rule.reason_code)

        members: list[Member] = []
        matched_positive = False
        seen_ok = 0
        notes: list[str] = []
        evidence: list[EvidenceRef] = []
        active_proof = False
        urgent = False
        for item in g.items:
            ictx = {**gctx, **item.ctx}
            if self.cc.item_filter is not None and not self.cc.item_filter.test(ictx):
                continue
            label = render.format_strict(spec.affected_template, render.item_vars(spec.scope, item, g, self.index),
                                         f"check {spec.id} affected_template")
            if self.cc.when is not None and self.cc.when.test(ictx):
                self.claimed.add(item.claim_id)
                if spec.kind == "note":
                    notes.append(label)
                    members.append(_member(item, label, "pass"))
                else:
                    holds = [sid for sid, cond in self.cc.statements if cond is None or cond.test(ictx)]
                    dringend = self.cc.urgent is not None and self.cc.urgent.test(ictx)
                    members.append(_member(item, label, "fail", holds=holds, urgent=dringend))
                    evidence.extend(self.evidence(item, ictx))
                    # S6: aktiver Nachweis. Trifft der Ausdruck fuer ein
                    # fehlgeschlagenes Mitglied, ist der ganze Sachverhalt
                    # belegt und wird rot mit Unverzueglich.
                    if self.cc.active_proof is not None and self.cc.active_proof.test(ictx):
                        active_proof = True
                    urgent = urgent or dringend
                continue
            hit = next((rule for rule, ex in self.cc.nt_item if ex.test(ictx)), None)
            if hit is not None:
                members.append(_member(item, label, "not_testable", reason_code=hit.reason_code))
                continue
            if self.cc.positive is not None:
                if self.cc.positive.test(ictx):
                    matched_positive = True
                    members.append(_member(item, label, "pass"))
                elif spec.undetermined == "pass_silent":
                    members.append(_member(item, label, "pass"))
                elif spec.undetermined == "not_applicable":
                    members.append(_member(item, label, "not_applicable", reason_code="precondition_not_met"))
                else:
                    members.append(_member(item, label, "not_testable", reason_code="insufficient_facts"))
            else:
                # absent/never: ein gesehenes, unauffaelliges Item zaehlt, wird aber nicht gelistet
                seen_ok += 1

        fails = [m for m in members if m.status == "fail"]
        if fails:
            return self.result(g, "fail", members=members, evidence=evidence, notes=notes,
                               seen=seen_ok, active_proof=active_proof, urgent=urgent)
        nts = [m for m in members if m.status == "not_testable"]
        if nts:
            return self.result(g, "not_testable", members=members, reason_code=nts[0].reason_code, notes=notes, seen=seen_ok)
        passes = [m for m in members if m.status == "pass"]
        if passes or seen_ok:
            positive = self.is_positive(matched_positive)
            return self.result(g, "pass", members=members, positive=positive, notes=notes, seen=seen_ok)
        if members:
            return self.result(g, "not_applicable", members=members, reason_code="precondition_not_met")
        return self.empty_group(g)

    def is_positive(self, matched_positive: bool) -> bool:
        spec = self.spec
        if spec.kind != "check" or spec.texts.positive is None or spec.positive_mode == "never":
            return False
        return spec.positive_mode == "absent" or matched_positive

    def empty_group(self, g: Group) -> CheckResult:
        spec = self.spec
        tools = spec.requires.tools
        if tools:
            for tool in tools:
                st, reason = g.coverage(self.index, tool)
                if st == "ok":
                    continue
                status, code, _ = _reason(reason or st)
                if status == "ok":
                    continue
                return self.result(g, status, reason_code=code)
        if spec.positive_mode == "absent":
            return self.result(g, "pass", positive=self.is_positive(False))
        if spec.positive_mode == "never":
            return self.result(g, "pass")
        if spec.undetermined == "pass_silent":
            return self.result(g, "pass")
        if spec.undetermined == "not_applicable":
            return self.result(g, "not_applicable", reason_code="precondition_not_met")
        return self.result(g, "not_testable", reason_code="insufficient_facts")

    def evidence(self, item: Item, ictx: dict[str, Any]) -> list[EvidenceRef]:
        """Nachweis dieses Treffers.

        S6 (spec/08 Punkt 3): Zuerst die befundspezifische Zeile aus dem
        getroffenen Teilobjekt, danach die Evidenz des tragenden Fakts. Die
        bereichsweite Evidenz aus ``evidence: [...]`` kommt nur noch dran, wenn
        vorher nichts entstanden ist; sonst stand in sieben Befunden dieselbe
        Zusammenfassungszeile des header_check.
        """
        out = detail_evidence(self.spec.scope, item, ictx, self.spec.evidence_detail,
                              self.cc.evidence_paths)
        if not out:
            out.extend(_evidence_of(item.fact))
        elif self.spec.scope in KEEP_FACT_EVIDENCE:
            # Der woertliche Werkzeugauszug bleibt, soweit er etwas sagt, das
            # nicht schon in der Detailzeile steht (``21/tcp open ftp ProFTPD``
            # neben ``...:21/tcp Dienst=ftp Produkt=ProFTPD Zustand=open``).
            detail = " ".join(e.excerpt for e in out)
            out.extend(e for e in _evidence_of(item.fact)
                       if not ist_redundant(e.excerpt, detail))
        if out:
            return out
        for name in self.spec.evidence:
            obj = ictx.get(name)
            if obj is None or obj is item.fact:
                continue
            if isinstance(obj, list):
                for o in obj:
                    out.extend(_evidence_of(o))
            else:
                out.extend(_evidence_of(obj))
        return out

    def result(self, g: Group, status: str, *, members: list[Member] | None = None, reason_code: str | None = None,
               evidence: list[EvidenceRef] | None = None, positive: bool = False, notes: list[str] | None = None,
               seen: int = 0, active_proof: bool = False, urgent: bool = False) -> CheckResult:
        spec = self.spec
        members = members or []
        notes = notes or []
        fails = [m for m in members if m.status == "fail"]
        labels = sorted({m.label for m in fails}, key=sort_key)
        fact_ids = sorted({fid for m in fails for fid in m.fact_ids}, key=sort_key)
        reason_text = None
        if status == "not_testable" and g.host is not None and g.host.blocked.detected \
                and reason_code in (None, "unreachable", "insufficient_facts", "no_coverage_rows"):
            blocked_reason = g.host.blocked.reason or "web_unreachable_after_portscan"
            if blocked_reason in T.COVERAGE_REASONS:
                reason_code = blocked_reason
        if reason_code:
            _, reason_code, reason_text = _reason(reason_code)
        modes = [m.source_mode for m in (fails or [m for m in members if m.status == "pass"])]
        source_mode = _source_mode(modes)
        verified: bool | None = None
        if fails:
            verified = False if source_mode == "passive" else True
        seen_keys: set[tuple[str, str, str]] = set()
        ev: list[EvidenceRef] = []
        for e in evidence or []:
            key = (e.fact_id, e.ref, e.excerpt)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            ev.append(e)
            if len(ev) >= MAX_EVIDENCE:
                break
        gvars = render.group_vars(g, labels, notes)
        observation = ""
        if status == "fail":
            # Gruppenansicht: nur Aussagen, deren Bedingung fuer jedes fehlgeschlagene
            # Mitglied gilt (Quantor alle) oder fuer mindestens eines (Quantor eines).
            teile = []
            for sid, text, _cond, quantor in spec.texts.statements("observation"):
                gilt = [m for m in fails if sid in m.holds]
                if gilt and (quantor == "eines" or len(gilt) == len(fails)):
                    teile.append(render.format_strict(text, gvars, f"check {spec.id} {sid}"))
            observation = " ".join(teile)
        pos = None
        if positive and spec.texts.positive is not None:
            pos = spec.texts.positive.model_copy(update={
                "title": render.format_strict(spec.texts.positive.title, gvars, f"check {spec.id} positive.title"),
                "text": render.format_strict(spec.texts.positive.text, gvars, f"check {spec.id} positive.text"),
            })
        return CheckResult(
            check_id=spec.id, family=spec.family, bundle=spec.bundle, kind=spec.kind, title=spec.title,
            category=spec.category, scale=spec.scale, level=spec.level, group_by=spec.group_by, group_key=g.key,
            group_label=g.label, status=status, positive=positive, active_proof=active_proof,
            urgent=urgent, verified=verified, source_mode=source_mode,
            affected=labels, affected_fact_ids=fact_ids, members=members, items_seen=seen + len(members), evidence=ev,
            reason_code=reason_code, reason=reason_text, notes=sorted(set(notes), key=sort_key),
            vars={k: (v if isinstance(v, (int, list)) else render._s(v)) for k, v in gvars.items()
                  if not isinstance(v, render.Numerus)},
            texts=RenderedTexts(observation=observation, positive=pos),
        )


def evaluate_check(cc: CompiledCheck, index: FactsIndex, claimed: set[str] | None = None) -> list[CheckResult]:
    claimed = claimed if claimed is not None else set()
    ev = _Eval(cc, index, claimed)
    groups = build_groups(index, cc.spec.scope, cc.spec.group_by)
    results = [ev.group(g) for g in groups]
    results.sort(key=lambda r: sort_key(r.group_key))
    return results


def check_info(spec: CheckSpec) -> CheckInfo:
    return CheckInfo(id=spec.id, title=spec.title, family=spec.family, category=spec.category,
                     category_name=CATEGORY_NAMES[spec.category], scale=spec.scale, level=spec.level,
                     level_label=LEVEL_LABELS[spec.level], group_by=spec.group_by, scope=spec.scope, kind=spec.kind,
                     bundle=spec.bundle, positive_mode=spec.positive_mode, requires=spec.requires,
                     references=list(spec.references), frameworks=spec.frameworks, policy=spec.policy,
                     texts=spec.texts)


def rollup(check: CheckSpec, results: list[CheckResult]) -> CheckRollup:
    counts = Counter(r.status for r in results)
    return CheckRollup(check_id=check.id, family=check.family, groups=len(results),
                       counts={k: counts.get(k, 0) for k in STATUS_ORDER},
                       positives=sum(1 for r in results if r.positive),
                       affected_total=sum(len(r.affected) for r in results))


def evaluate(facts: FS.Facts | dict[str, Any], catalog: Catalog | None = None) -> CatalogOutput:
    """Katalog auf eine Faktendatei anwenden. Deterministisch: Reihenfolge nach check_id und group_key."""
    if isinstance(facts, dict):
        facts = FS.Facts.from_dict(facts)
    cat = catalog or default_catalog()
    facts = without_third_party(facts)
    index = FactsIndex(facts)
    claimed: set[str] = set()
    results: list[CheckResult] = []
    rollups: list[CheckRollup] = []
    for cc in cat.checks:
        res = evaluate_check(cc, index, claimed)
        results.extend(res)
        rollups.append(rollup(cc.spec, res))
    results.sort(key=lambda r: sort_key(r.check_id, r.group_key))
    unprocessed, ignored = run_catchalls(index, claimed, cat.ignore)
    by_status = Counter(r.status for r in results)
    fails = [r for r in results if r.status == "fail" and r.kind == "check"]
    summary = Summary(
        checks=len(cat.checks), results=len(results), by_status={k: by_status.get(k, 0) for k in STATUS_ORDER},
        fail_by_category={k: v for k, v in sorted(Counter(r.category for r in fails).items())},
        fail_by_level={k: v for k, v in sorted(Counter(r.level for r in fails).items())},
        positives=sum(1 for r in results if r.positive), unprocessed=sum(u.count for u in unprocessed),
        ignored=sum(i.count for i in ignored), warnings=list(facts.warnings),
    )
    return CatalogOutput(
        catalog_version=cat.version, catalog_digest=cat.digest, facts_schema_version=facts.schema_version,
        order_id=facts.scan.order_id, package=facts.scan.package, domain=facts.scan.domain,
        domains=list(facts.scan.domains) or [facts.scan.domain], generator=facts.generator.model_dump(mode="json"),
        checks=[check_info(cc.spec) for cc in cat.checks], bundles=list(cat.bundles),
        results=results, rollups=rollups, unprocessed=unprocessed, ignored=ignored,
        facts_unprocessed=[u.model_dump(mode="json") for u in facts.unprocessed], summary=summary,
    )


__all__ = ["Catalog", "CompiledCheck", "load_catalog", "default_catalog", "reset_default_catalog", "load_check",
           "load_bundle", "compile_check", "evaluate", "evaluate_check", "rollup", "STATUS_ORDER"]

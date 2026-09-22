"""Schema des Pruefkatalogs: Pruefung (YAML), Ignorierliste und Ergebnisse.

Pflichtfelder einer Pruefung laut S2-Auftrag: id, title, family, scale, level, group_by,
when, positive_when, not_testable_when, affected_template, evidence, references,
frameworks, texts. Erweiterungen dieser Umsetzung: category, scope, applicable_when,
undetermined, requires, kind, bundle, policy (siehe README). ZAP-Alert-Paare stehen in
tables.py und werden im ``when`` ueber ``zap_match(alert, ZAP_...)`` benutzt.

Alle Modelle sind ``extra="forbid"``: ein Tippfehler in einer YAML-Datei ist ein
Ladefehler, kein stilles Nichtstun.
"""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from reporter.catalog import tables as T

Scale = Literal["exposure", "hygiene"]
Level = Literal["kritisch", "erhoeht", "hoch", "mittel", "niedrig"]
Category = Literal["A", "B", "C", "D", "E"]
GroupBy = Literal["global", "domain", "host", "fqdn"]
Status = Literal["pass", "fail", "not_applicable", "not_testable"]
Undetermined = Literal["not_testable", "pass_silent", "not_applicable"]
Kind = Literal["check", "note"]
Stage = Literal["unverzueglich", "in_kuerze", "mittelfristig", "strategisch"]
SourceMode = Literal["active", "passive", "mixed", "none"]

LEVELS_BY_SCALE: dict[str, tuple[str, ...]] = {
    "exposure": ("kritisch", "erhoeht"),
    "hygiene": ("hoch", "mittel", "niedrig"),
}
LEVEL_LABELS: dict[str, str] = {
    "kritisch": "kritisch", "erhoeht": "erhöht", "hoch": "hoch", "mittel": "mittel", "niedrig": "niedrig",
}
CATEGORY_NAMES: dict[str, str] = {
    "A": "Perimeter-Exposition", "B": "Patch- und EOL-Status", "C": "E-Mail-Authentizität",
    "D": "Web- und Transport-Hygiene", "E": "Konfiguration und Informations-Hygiene",
}
POSITIVE_MODES = ("absent", "never")


class Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- Pruefung

class NotTestableRule(Base):
    when: str
    reason_code: str
    context: Literal["group", "item"] = "group"


class Recommendation(Base):
    stage: Stage
    text: str


class PositiveText(Base):
    title: str
    text: str


class Texts(Base):
    observation: str
    meaning: str
    recommendation: list[Recommendation] = Field(min_length=1)
    verify: str
    positive: Optional[PositiveText] = None


class Frameworks(Base):
    bsi: list[str] = Field(default_factory=list)
    nis2: list[str] = Field(default_factory=list)
    iso27001: list[str] = Field(default_factory=list)
    tr03116: list[str] = Field(default_factory=list)


class PolicyRef(Base):
    source: str
    start_level: Optional[str] = None
    deviation: Optional[str] = None


class Requires(Base):
    tools: list[str] = Field(default_factory=list)


class CheckSpec(Base):
    id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    title: str
    family: str
    category: Category
    scale: Scale
    level: Level
    group_by: GroupBy
    scope: str
    applicable_when: Optional[str] = None
    item_when: Optional[str] = None
    when: Optional[str] = None
    # S6: Ein Treffer dieses Ausdrucks macht aus dem Befund einen aktiv
    # nachgewiesenen (rot, Unverzueglich), unabhaengig von level. Nur fuer
    # Pruefungen, die einen eigenen Nachweis fuehren (ZAP-Meldung mit hoher
    # Konfidenz, testssl-Schwachstelle aus der harten Liste).
    active_proof_when: Optional[str] = None
    positive_when: str = "absent"
    not_testable_when: list[NotTestableRule] = Field(default_factory=list)
    undetermined: Undetermined = "not_testable"
    requires: Requires = Field(default_factory=Requires)
    kind: Kind = "check"
    bundle: Optional[str] = None
    affected_template: str
    evidence: list[str] = Field(default_factory=list)
    # S6: Bereich, aus dem der befundspezifische Nachweis gebaut wird
    # (reporter/catalog/evidence.py). Ohne Angabe gilt der scope der Pruefung.
    evidence_detail: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    frameworks: Frameworks = Field(default_factory=Frameworks)
    policy: PolicyRef
    texts: Texts

    @model_validator(mode="after")
    def _consistency(self) -> "CheckSpec":
        if self.level not in LEVELS_BY_SCALE[self.scale]:
            raise ValueError(f"{self.id}: level {self.level!r} passt nicht zu scale {self.scale!r}")
        if self.family not in T.FAMILIES:
            raise ValueError(f"{self.id}: family {self.family!r} nicht in tables.FAMILIES")
        if self.kind == "note":
            if not self.when:
                raise ValueError(f"{self.id}: kind note braucht when")
            if self.positive_when != "never":
                raise ValueError(f"{self.id}: kind note braucht positive_when never")
        if self.when is None and self.positive_when in POSITIVE_MODES:
            raise ValueError(f"{self.id}: ohne when muss positive_when ein Ausdruck sein")
        if not self.affected_template.strip():
            raise ValueError(f"{self.id}: affected_template leer")
        for rule in self.not_testable_when:
            if rule.reason_code.startswith("coverage:"):
                if rule.context != "group" or not rule.reason_code[len("coverage:"):]:
                    raise ValueError(f"{self.id}: reason_code coverage:<tool> nur im Gruppenkontext und mit Werkzeugname")
            elif rule.reason_code not in T.COVERAGE_REASONS:
                raise ValueError(f"{self.id}: reason_code {rule.reason_code!r} nicht in tables.COVERAGE_REASONS")
        return self

    @property
    def positive_mode(self) -> str:
        """absent | never | expr"""
        return self.positive_when if self.positive_when in POSITIVE_MODES else "expr"


# ---------------------------------------------------------------- Befund-Buendel

class BundleSpec(Base):
    """Ein Buendel fasst mehrere Pruefungen zu einem Befund des Kundenreports zusammen.

    Mitgliedschaft steht doppelt: hier in ``members`` und im Feld ``bundle`` der
    Pruefung. Der Ladevorgang erzwingt, dass beide Seiten uebereinstimmen, damit eine
    halb gepflegte Zuordnung ein Ladefehler ist und keine stille Luecke.

    ``merge_by`` bestimmt, wie die Gruppen der Mitglieder zu einem Befund
    zusammenlaufen: ``global`` ein Befund fuer den ganzen Scan, ``domain`` je Domain,
    ``host`` je Host-IP (auch fuer FQDN-Gruppen, die IP steht im Gruppenschluessel),
    ``fqdn`` je virtuellem Host.

    ``target: appendix`` haelt ein Buendel aus der Befundliste heraus und schreibt es in
    den Anhang "Werkzeugbefunde ohne Bewertung" (spec/06 Abschnitt 4, Stufe 2).
    """

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    title: str
    category: Category
    merge_by: GroupBy
    members: list[str] = Field(min_length=1)
    target: Literal["findings", "appendix"] = "findings"
    references: list[str] = Field(default_factory=list)
    frameworks: Frameworks = Field(default_factory=Frameworks)
    texts: Texts

    @model_validator(mode="after")
    def _members_unique(self) -> "BundleSpec":
        if len(set(self.members)) != len(self.members):
            raise ValueError(f"{self.id}: doppelte Mitglieder")
        return self


# ---------------------------------------------------------------- Ignorierliste

class IgnoreEntry(Base):
    kind: Literal["zap_alert", "passive_port"]
    plugin_id: Optional[str] = None
    name: Optional[str] = None
    ports: list[int] = Field(default_factory=list)
    only_cdn: bool = False
    reason: str

    @model_validator(mode="after")
    def _shape(self) -> "IgnoreEntry":
        if self.kind == "zap_alert" and not (self.plugin_id or self.name):
            raise ValueError("zap_alert braucht plugin_id oder name")
        if self.kind == "passive_port" and not self.ports:
            raise ValueError("passive_port braucht ports")
        return self


class IgnoreList(Base):
    entries: list[IgnoreEntry] = Field(default_factory=list)


# ---------------------------------------------------------------- Ergebnis

class EvidenceRef(Base):
    fact_id: str
    tool: str
    ref: str
    excerpt: str = ""


class Member(Base):
    key: str
    host_ip: Optional[str] = None
    fqdn: Optional[str] = None
    port: Optional[int] = None
    label: str
    status: Status
    reason_code: Optional[str] = None
    reason: Optional[str] = None
    fact_ids: list[str] = Field(default_factory=list)
    source_mode: SourceMode = "active"
    verified: Optional[bool] = None
    via_cdn: bool = False
    alias_of: Optional[str] = None


class RenderedTexts(Base):
    """Je Gruppe gerenderte Texte; die Vorlagen stehen einmal je Pruefung in CatalogOutput.checks."""
    observation: str = ""
    positive: Optional[PositiveText] = None


class CheckInfo(Base):
    """Stammdaten einer Pruefung, einmal je Ausgabe (Titel, Texte, Referenzen, Einstufung)."""
    id: str
    title: str
    family: str
    category: Category
    category_name: str
    scale: Scale
    level: Level
    level_label: str
    group_by: GroupBy
    scope: str
    kind: Kind
    bundle: Optional[str] = None
    positive_mode: str
    requires: Requires
    references: list[str] = Field(default_factory=list)
    frameworks: Frameworks = Field(default_factory=Frameworks)
    policy: PolicyRef
    texts: Texts


class CheckResult(Base):
    check_id: str
    family: str
    bundle: Optional[str] = None
    kind: Kind = "check"
    title: str
    category: Category
    scale: Scale
    level: Level
    group_by: GroupBy
    group_key: str
    group_label: str
    status: Status
    positive: bool = False
    active_proof: bool = False
    verified: Optional[bool] = None
    source_mode: SourceMode = "none"
    affected: list[str] = Field(default_factory=list)
    affected_fact_ids: list[str] = Field(default_factory=list)
    members: list[Member] = Field(default_factory=list)
    items_seen: int = 0
    evidence: list[EvidenceRef] = Field(default_factory=list)
    reason_code: Optional[str] = None
    reason: Optional[str] = None
    notes: list[str] = Field(default_factory=list)
    vars: dict[str, Any] = Field(default_factory=dict)
    texts: RenderedTexts = Field(default_factory=RenderedTexts)


class CheckRollup(Base):
    check_id: str
    family: str
    groups: int = 0
    counts: dict[str, int] = Field(default_factory=dict)
    positives: int = 0
    affected_total: int = 0


class Unprocessed(Base):
    kind: Literal["service_unknown_port", "zap_alert_unmapped", "passive_port_unverified"]
    what: str
    host_ip: Optional[str] = None
    fqdns: list[str] = Field(default_factory=list)
    port: Optional[int] = None
    count: int = 1
    fact_ids: list[str] = Field(default_factory=list)
    note: Optional[str] = None


class IgnoredItem(Base):
    kind: Literal["zap_alert", "passive_port"]
    what: str
    host_ip: Optional[str] = None
    fqdns: list[str] = Field(default_factory=list)
    count: int = 1
    reason: str


class Summary(Base):
    checks: int = 0
    results: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    fail_by_category: dict[str, int] = Field(default_factory=dict)
    fail_by_level: dict[str, int] = Field(default_factory=dict)
    positives: int = 0
    unprocessed: int = 0
    ignored: int = 0
    warnings: list[str] = Field(default_factory=list)


class CatalogOutput(Base):
    catalog_version: str
    catalog_digest: str
    facts_schema_version: str
    order_id: str
    package: str
    domain: str
    domains: list[str] = Field(default_factory=list)
    generator: dict[str, Any] = Field(default_factory=dict)
    checks: list[CheckInfo] = Field(default_factory=list)
    bundles: list[BundleSpec] = Field(default_factory=list)
    results: list[CheckResult] = Field(default_factory=list)
    rollups: list[CheckRollup] = Field(default_factory=list)
    unprocessed: list[Unprocessed] = Field(default_factory=list)
    ignored: list[IgnoredItem] = Field(default_factory=list)
    facts_unprocessed: list[dict[str, Any]] = Field(default_factory=list)
    summary: Summary = Field(default_factory=Summary)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

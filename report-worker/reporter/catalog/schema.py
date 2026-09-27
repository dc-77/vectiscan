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


class NotApplicableReason(Base):
    """Grund, wenn ``applicable_when`` nicht zutrifft (S6b-3, spec/10 R8): DANE entfaellt,
    weil der MX beim Dienstleister liegt, nicht nur "Voraussetzung nicht gegeben"."""
    when: str
    reason_code: str


Quantor = Literal["alle", "eines"]

# Textfelder, die aus Aussagen bestehen (S6b-2). Die Empfehlungen sind eigene Aussagen
# mit Stufe und stehen unter ``recommendation``.
STATEMENT_FIELDS: tuple[str, ...] = ("observation", "meaning", "verify")


class Statement(Base):
    """Eine Textaussage mit der Fakten-Bedingung, unter der sie stehen darf (S6b-2, spec/09 Q4).

    Ohne ``when`` ist die Bedingung die Regel selbst: die Aussage steht, wenn das Mitglied
    fehlgeschlagen ist. Mit ``when`` wird der Ausdruck im selben Kontext wie ``when`` der
    Pruefung je fehlgeschlagenem Mitglied ausgewertet. ``quantor: alle`` verlangt die
    Bedingung fuer jedes fehlgeschlagene Mitglied, ``eines`` fuer mindestens eines; dann
    nennt ``{affected}`` nur die Mitglieder, fuer die sie gilt.
    """
    text: str
    when: Optional[str] = None
    quantor: Quantor = "alle"
    # S6b-4n (spec/11 N10): Baustein-Schluessel; Aussagen mit gleichem Schluessel aus mehreren
    # Regeln eines Befunds stehen einmal (Versionspreisgabe im Header und im Dienstbanner).
    key: Optional[str] = None


def _as_statements(value: Any) -> Any:
    if isinstance(value, str):
        return [{"text": value}]
    return value


class Recommendation(Base):
    stage: Stage
    text: str
    when: Optional[str] = None
    quantor: Quantor = "alle"
    # S6b-3 (spec/10 R11): Effekt genau dieser Stufe fuer die Planzeile. Ohne Angabe gilt
    # ``texts.plan.effect``; der Lint-Test verlangt ihn, wenn die erste Stufe etwas anderes
    # bewirkt als die Hauptmassnahme (DMARC: "Berichte auswerten" vor "p=reject").
    effect: Optional[str] = None


class PositiveText(Base):
    title: str
    text: str


class PlanText(Base):
    """Hebeltitel und Effekt der Massnahme im Massnahmenplan (S6b-2, spec/09 Q6).

    ``lever`` ist ein Titel ohne Hostnamen, weil ein Hebel alle Befunde seiner Zeile
    adressiert; ``effect`` sagt, was die Massnahme bewirkt, und gilt nur fuer diese Regel.

    S6b-4 (spec/11 T12, T14): ``lever_variants`` und ``effect_variants`` ersetzen Hebel und
    Effekt, wenn ihre Fakten-Bedingung gilt ("Abgelaufenes Zertifikat ersetzen" statt
    "Zertifikate vor dem Ablauf erneuern"). Es gilt die erste zutreffende Variante.
    """
    lever: str
    effect: str
    lever_variants: list[Statement] = Field(default_factory=list)
    effect_variants: list[Statement] = Field(default_factory=list)
    # S6b-4 (spec/11 T12): eine Planzeile fuer die ganze Regel ueber alle Befunde, mit der Liste
    # der Betroffenen je Host ("Die fehlenden Sicherheits-Header setzen: www.x.de (fehlend: ...)").
    # Ohne Angabe gilt je Befund die erste Stufe.
    per_rule_action: Optional[str] = None


# S6b-4 (spec/11 T4, T14): Felder mit Varianten, deren erste zutreffende den Standardtext ersetzt.
VARIANT_FIELDS: tuple[str, ...] = ("short_variants", "plan.lever_variants", "plan.effect_variants")


class Texts(Base):
    # Kurzform der Regel im Sammeltitel eines Buendels ("kein TLS 1.3").
    short: Optional[str] = None
    # S6b-4 (spec/11 T4, T14): Kurzform je Variante ("HSTS abgeschaltet (max-age=0)",
    # "Zertifikat am Berichtsdatum abgelaufen, sofern nicht erneuert").
    short_variants: list[Statement] = Field(default_factory=list)
    observation: list[Statement] = Field(min_length=1)
    meaning: list[Statement] = Field(min_length=1)
    recommendation: list[Recommendation] = Field(min_length=1)
    verify: list[Statement] = Field(min_length=1)
    plan: Optional[PlanText] = None
    positive: Optional[PositiveText] = None

    @model_validator(mode="before")
    @classmethod
    def _strings_are_statements(cls, data: Any) -> Any:
        """Ein Textfeld als Zeichenkette ist eine Aussage ohne eigene Bedingung."""
        if isinstance(data, dict):
            data = dict(data)
            for name in STATEMENT_FIELDS:
                if name in data:
                    data[name] = _as_statements(data[name])
        return data

    def statement_key(self, name: str, sid: str) -> Optional[str]:
        """Baustein-Schluessel einer Aussage (spec/11 N10), None ohne Schluessel."""
        if name not in STATEMENT_FIELDS:
            return None
        try:
            return getattr(self, name)[int(sid.rsplit("[", 1)[1].rstrip("]"))].key
        except (IndexError, ValueError):
            return None

    def statements(self, name: str) -> list[tuple[str, str, Optional[str], str]]:
        """(Aussage-ID, Text, Bedingung, Quantor) eines Felds in Katalogreihenfolge."""
        if name == "recommendation":
            return [(f"recommendation[{i}]", r.text, r.when, r.quantor)
                    for i, r in enumerate(self.recommendation)]
        if name == "short_variants":
            return [(f"short_variants[{i}]", s.text, s.when, s.quantor)
                    for i, s in enumerate(self.short_variants)]
        if name in ("plan.lever_variants", "plan.effect_variants"):
            if self.plan is None:
                return []
            attr = name.split(".", 1)[1]
            return [(f"{name}[{i}]", s.text, s.when, s.quantor)
                    for i, s in enumerate(getattr(self.plan, attr))]
        return [(f"{name}[{i}]", s.text, s.when, s.quantor)
                for i, s in enumerate(getattr(self, name))]

    def all_statements(self) -> list[tuple[str, str, Optional[str], str]]:
        out: list[tuple[str, str, Optional[str], str]] = []
        for name in (*STATEMENT_FIELDS, "recommendation", *VARIANT_FIELDS):
            out.extend(self.statements(name))
        return out

    def joined(self, name: str) -> str:
        """Alle Aussagen eines Felds als ein Text (nur fuer Stellen ohne Faktenbezug)."""
        return " ".join(text for _, text, _, _ in self.statements(name))


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
    # S6b-2 (E2): Ausnahme in der Abbildungstabelle. Trifft der Ausdruck fuer ein
    # fehlgeschlagenes Mitglied, wird der Sachverhalt rot mit Unverzueglich, obwohl die
    # Einstufung Hygiene ist. Zulaessig nur fuer Pruefungen in levels.URGENT_EXCEPTIONS.
    urgent_when: Optional[str] = None
    # S6b-4 (spec/11 T11, E22): Gegenstueck zu ``urgent_when``. Trifft der Ausdruck fuer jedes
    # fehlgeschlagene Mitglied, steht der Sachverhalt als blauer Hinweis, obwohl seine
    # Einstufung gelb waere (Passivbefund auf einem Host, der vom Pruefstand aus nicht
    # erreichbar ist). Zulaessig nur fuer Pruefungen in levels.HINT_EXCEPTIONS.
    hint_when: Optional[str] = None
    positive_when: str = "absent"
    not_testable_when: list[NotTestableRule] = Field(default_factory=list)
    not_applicable_reasons: list[NotApplicableReason] = Field(default_factory=list)
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

    ``positive_conflicts`` (S6a, Issue #30): Befunde anderer Pruefungen, bei denen der
    Positivbefund dieses Buendels fuer denselben Host entfaellt. Die Pruefung selbst
    bleibt bestanden; nur die Aussage im Kundenreport wuerde neben dem anderen Befund
    mehr behaupten, als sie prueft.

    S6b-2 (spec/09 Q4): Ein Buendel gruppiert nur. Befundtext, Auswirkung, Empfehlung und
    Verifikation entstehen je getroffener Regel aus deren eigenen Texten; das Buendel traegt
    nur den Sammeltitel ``title`` mit ``{group}`` und ``{rules}`` (Kurzformen der
    getroffenen Regeln) und ``positive_title`` fuer den Fall, dass jedes Mitglied mit
    Positivtext bestanden hat. Frueher standen hier eigene Texte, und sie behaupteten, was
    eine andere Regel des Buendels meinte ("Kette unvollstaendig" bei einem Zertifikat, das
    nur bald ablief).
    """

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    title: str
    category: Category
    merge_by: GroupBy
    members: list[str] = Field(min_length=1)
    target: Literal["findings", "appendix"] = "findings"
    references: list[str] = Field(default_factory=list)
    frameworks: Frameworks = Field(default_factory=Frameworks)
    positive_title: Optional[str] = None
    positive_conflicts: list["PositiveConflict"] = Field(default_factory=list)

    @model_validator(mode="after")
    def _members_unique(self) -> "BundleSpec":
        if len(set(self.members)) != len(self.members):
            raise ValueError(f"{self.id}: doppelte Mitglieder")
        if self.target == "findings" and "{rules}" not in self.title:
            raise ValueError(f"{self.id}: Sammeltitel braucht {{rules}}")
        return self

    def conflicts_label(self) -> str:
        """Kurzform fuer die Buendeltabelle in decisions.md."""
        if not self.positive_conflicts:
            return "-"
        return "; ".join(c.label() for c in self.positive_conflicts)


class PositiveConflict(Base):
    """Ein Befund, bei dem der Positivbefund eines Buendels je Host entfaellt.

    Zwei Formen, genau eine je Eintrag:

    * ``checks`` (optional mit ``ports``): eine dieser Pruefungen ist auf dem Host
      fehlgeschlagen; mit ``ports`` zaehlt nur ein fehlgeschlagenes Mitglied auf einem
      dieser Ports.
    * ``noted_by``: eine Notiz-Pruefung (``kind: note``) nennt einen Dienst ``ip:port``,
      und irgendeine Pruefung ist auf genau diesem Dienst fehlgeschlagen, etwa SSH
      ausserhalb von Port 22 mit Bannerbefund.
    """

    checks: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    noted_by: Optional[str] = None

    @model_validator(mode="after")
    def _one_form(self) -> "PositiveConflict":
        if bool(self.checks) == bool(self.noted_by):
            raise ValueError("positive_conflicts: genau eines von checks oder noted_by")
        if self.ports and not self.checks:
            raise ValueError("positive_conflicts: ports nur zusammen mit checks")
        return self

    def label(self) -> str:
        if self.noted_by:
            return f"{self.noted_by} mit Befund"
        text = ", ".join(self.checks)
        if self.ports:
            text += " (Port " + ", ".join(str(p) for p in self.ports) + ")"
        return text


BundleSpec.model_rebuild()


# ---------------------------------------------------------------- Ignorierliste

class IgnoreEntry(Base):
    kind: Literal["zap_alert", "passive_port"]
    plugin_id: Optional[str] = None
    name: Optional[str] = None
    ports: list[int] = Field(default_factory=list)
    only_cdn: bool = False
    reason: str
    # S6b-3 (spec/10 R15): Pruefungen, die diese Werkzeugmeldung abdecken. Schlaegt keine davon
    # an derselben Stelle an, steht die Meldung im Anhang statt stillschweigend zu entfallen.
    covered_by: list[str] = Field(default_factory=list)

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
    # S6b-2: Aussagen der Pruefung, deren Bedingung fuer dieses fehlgeschlagene Mitglied
    # gilt (``observation[0]``, ``recommendation[1]`` ...). Aussagen ohne eigene Bedingung
    # stehen immer darin. Das Gate prueft jede Aussage des Berichts gegen diese Liste.
    holds: list[str] = Field(default_factory=list)
    urgent: bool = False
    hint: bool = False
    # Nachtrag S6b-2 (Entscheidung DC 26.09.): Name und Kennung der Werkzeugmeldung (ZAP-Regel,
    # testssl-Test), damit der Anhang eine Zeile je Meldung zusammenfassen kann.
    message: Optional[str] = None
    message_id: Optional[str] = None


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
    # S6b-3 (spec/10 R4): das Subjekt ist fuer diese Regel gemessen (fehlgeschlagen oder
    # die Positivbedingung traf zu). Grundlage der Unterdrueckung von "nicht pruefbar"-Zeilen
    # derselben Faktenfamilie und des Gates gegen Widersprueche.
    affirmed: bool = False
    active_proof: bool = False
    urgent: bool = False
    # S6b-4 (E22): jedes fehlgeschlagene Mitglied erfuellt ``hint_when``.
    hint: bool = False
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
    covered_by: list[str] = Field(default_factory=list)
    plugin_id: Optional[str] = None
    name: Optional[str] = None


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

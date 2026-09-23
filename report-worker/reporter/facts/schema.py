"""Versioniertes Faktenschema (pydantic v2) fuer facts.json.

Jedes Faktum traegt ``source`` (Werkzeug), ``mode`` (active/passive),
``observed_at`` (UTC, sekundengenau) und ``confidence`` (0..1) sowie eine
Liste woertlicher Nachweise. Es gibt keine Befunde, keine Einstufungen und
keine CVSS-Werte in dieser Datei; das ist Aufgabe des Pruefkatalogs (S2).

Bump-Regel fuer ``FACTS_SCHEMA_VERSION`` (semver):
- Patch: neue optionale Felder mit Default, neue Warnungstexte.
- Minor: neue Entitaet oder neues Pflichtfeld mit Default fuer Altbestand.
- Major: Feld entfernt, umbenannt oder Bedeutung geaendert, ID-Format geaendert.
Jeder Bump erfordert den Neubau der Golden-Facts (``python -m reporter.facts --golden``).

Historie:
- 1.0.1 (S2b, Issue #13): ``zap`` mit Status ``ok`` und null Alerts wird als
  ``empty`` mit Grund ``zap_no_alerts`` gefuehrt. Kein Feld geaendert, aber die
  Bedeutung einer Coverage-Zeile praeziser; Golden-Facts neu gebaut.
- 1.0.3 (S6, spec/08 Punkt 18): ``TlsEntry.cves`` fuehrt alle Kennungen eines
  testssl-Tests; ``cve`` bleibt die erste. Dazu Nachweiszeilen ohne
  Python-Darstellungen (spec/08 Punkt 3), was Auszuege aendert, keine Felder.
- 1.0.4 (S6a, #15 Teil 2): ``Dkim.probed`` nennt die abgefragten Selektoren,
  ``Dkim.probed_basis`` woher die Liste kommt (``scan``: aus dns_records;
  ``scanner_stand``: die feste Liste des Scanners ab ae5fa74, nur wenn der Tar
  diesen Stand belegt). Ohne gefundenen Selektor ist DKIM nicht pruefbar, und
  der Bericht nennt, wonach gesucht wurde.
"""
from __future__ import annotations

from typing import Any, ClassVar, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

FACTS_SCHEMA_VERSION = "1.0.4"

Mode = Literal["active", "passive"]

CONFIDENCE_TOOL = 1.0
CONFIDENCE_DERIVED = 0.8
CONFIDENCE_PASSIVE = 0.5

TLS_PROTOCOL_KEYS = ("SSLv2", "SSLv3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3")

CoverageStatus = Literal["ok", "empty", "failed", "blocked", "skipped", "unknown"]
EolStatus = Literal["eol", "supported", "unknown"]
BlockedSource = Literal["inventory", "scan_results", "derived"]
CoverageScope = Literal["scan", "domain", "host", "fqdn"]


class Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Evidence(Base):
    tool: str
    ref: str
    excerpt: str = ""


class Fact(Base):
    id: str
    source: str
    mode: Mode
    observed_at: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Evidence] = Field(default_factory=list)


# ---------------------------------------------------------------- scan / target

class ToolVersion(Base):
    name: str
    version: Optional[str] = None


class ScanCounts(Base):
    tool_runs: int = 0
    correlated_findings: int = 0
    correlated_fp: int = 0


class ScanFact(Fact):
    order_id: str
    package: str
    domain: str
    domains: list[str] = Field(default_factory=list)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    tool_versions: list[ToolVersion] = Field(default_factory=list)
    nmap_args: Optional[str] = None
    scanner_egress: Optional[str] = None
    hosts_scanned: Optional[int] = None
    counts: ScanCounts = Field(default_factory=ScanCounts)
    policy_version: Optional[str] = None


class Whois(Base):
    registrar: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    dnssec: Optional[bool] = None


class OutOfScope(Base):
    kind: str
    value: str
    reason: Optional[str] = None
    host_ip: Optional[str] = None


class TargetFact(Fact):
    domain: str
    is_primary: bool = True
    targets_source: str
    whois: Optional[Whois] = None
    discovery_health: Optional[dict[str, Any]] = None
    out_of_scope: list[OutOfScope] = Field(default_factory=list)


# ---------------------------------------------------------------- host / fqdn

class Provider(Base):
    isp: Optional[str] = None
    usage_type: Optional[str] = None
    country: Optional[str] = None


class PortsSummary(Base):
    open: int = 0
    closed: Optional[int] = None
    filtered: Optional[int] = None


class Blocked(Base):
    detected: bool = False
    reason: Optional[str] = None
    source: Optional[BlockedSource] = None


class Reputation(Base):
    abuseipdb_score: Optional[int] = None
    is_tor: Optional[bool] = None
    otx_pulse_count: Optional[int] = None
    urlhaus_compromised: Optional[bool] = None
    greynoise_classification: Optional[str] = None


class HostFact(Fact):
    ip: str
    family: Literal[4, 6]
    reverse: Optional[str] = None
    provider: Optional[Provider] = None
    reachable: Optional[bool] = None
    nmap_state: Optional[str] = None
    ports_summary: PortsSummary = Field(default_factory=PortsSummary)
    blocked: Blocked = Field(default_factory=Blocked)
    cdn_provider: Optional[str] = None
    edge_ips: list[str] = Field(default_factory=list)
    reputation: Optional[Reputation] = None
    fqdns: list[str] = Field(default_factory=list)


class Alias(Base):
    fqdn: str
    status: Optional[int] = None
    reason: Optional[str] = None


class Waf(Base):
    detected: Optional[bool] = None
    name: Optional[str] = None
    manufacturer: Optional[str] = None


class FqdnFact(Fact):
    name: str
    host_ip: str
    # S6 (spec/08 Punkt 13): ein Wildcard-Eintrag ``*.domain`` ist kein
    # Hostname. Er wird nicht gezaehlt, steht in keiner Betroffenenliste und
    # bekommt kein Bild; Kapitel 2.1 nennt ihn als Hinweis.
    wildcard: bool = False
    http_status: Optional[int] = None
    title: Optional[str] = None
    final_url: Optional[str] = None
    body_hash: Optional[str] = None
    is_primary: Optional[bool] = None
    aliases: list[Alias] = Field(default_factory=list)
    screenshot_key: Optional[str] = None
    web_probe_reachable: Optional[bool] = None
    waf: Optional[Waf] = None


# ---------------------------------------------------------------- service / tls

class CertShort(Base):
    cn: Optional[str] = None
    san: list[str] = Field(default_factory=list)
    not_after: Optional[str] = None


class ServiceFact(Fact):
    host_ip: str
    port: int
    proto: str
    state: str
    service: Optional[str] = None
    product: Optional[str] = None
    version_raw: Optional[str] = None
    version_norm: Optional[str] = None
    family: Optional[str] = None
    tunnel_ssl: bool = False
    tls_required: Optional[bool] = None
    starttls: Optional[bool] = None
    login_disabled: Optional[bool] = None
    auth_required: Optional[bool] = None
    auth_mechanisms: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    cert: Optional[CertShort] = None
    nmap_conf: Optional[int] = None
    method: Optional[str] = None


class TlsCert(Base):
    cn: Optional[str] = None
    san: list[str] = Field(default_factory=list)
    issuer: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_left: Optional[int] = None
    expired: Optional[bool] = None
    mismatch: Optional[bool] = None
    chain_ok: Optional[bool] = None
    self_signed: Optional[bool] = None
    wildcard: Optional[bool] = None


class TlsVuln(Base):
    """Urteil von testssl zu einer benannten TLS-Schwachstelle.

    Drei Werte, kein zweiwertiges Bild: ``not_tested`` steht fuer eine Pruefung,
    die testssl selbst nicht zu Ende gebracht hat (WARN, Zeitueberschreitung,
    Verbindungsfehler). Sie darf weder als Befund noch als "geprueft und in
    Ordnung" gelten; ohne den dritten Wert verschwand sie bisher ganz (S5b).
    """
    name: str
    status: Literal["vulnerable", "potential", "not_tested"]


class TlsEntry(Base):
    id: str
    severity: str
    finding: str
    cve: Optional[str] = None
    # Alle Kennungen desselben Tests. ``cve`` bleibt die erste, damit aeltere
    # Fakten weiter lesbar sind (S6, spec/08 Punkt 18).
    cves: list[str] = Field(default_factory=list)


class HstsInfo(Base):
    present: Optional[bool] = None
    max_age: Optional[int] = None
    include_subdomains: Optional[bool] = None
    preload: Optional[bool] = None
    raw: Optional[str] = None


class TlsFact(Fact):
    fqdn: Optional[str] = None
    host_ip: str
    port: int
    protocols: dict[str, Optional[bool]] = Field(
        default_factory=lambda: {k: None for k in TLS_PROTOCOL_KEYS}
    )
    ciphers_weak: list[str] = Field(default_factory=list)
    vulns: list[TlsVuln] = Field(default_factory=list)
    cert: Optional[TlsCert] = None
    hsts: Optional[HstsInfo] = None
    fallback_scsv: Optional[bool] = None
    grade: Optional[str] = None
    entries: list[TlsEntry] = Field(default_factory=list)
    json_filtered: bool = False


# ---------------------------------------------------------------- http

class SecHeader(Base):
    present: bool
    value: Optional[str] = None


class Csp(Base):
    present: bool
    value: Optional[str] = None
    unsafe_inline: Optional[bool] = None
    unsafe_eval: Optional[bool] = None
    wildcard: Optional[bool] = None


class Cookie(Base):
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None


class Tech(Base):
    name: str
    version: Optional[str] = None


class WebAlert(Base):
    """Ein ZAP-Alert-Typ je VHost: ``count`` = Anzahl betroffener URLs, ``urls_sample`` die ersten fuenf."""
    plugin_id: Optional[str] = None
    name: str
    risk: str
    confidence: Optional[str] = None
    url: Optional[str] = None
    urls_sample: list[str] = Field(default_factory=list)
    cwe: Optional[str] = None
    evidence: Optional[str] = None
    count: int = 1


class WebPath(Base):
    url: str
    status: Optional[int] = None
    length: Optional[int] = None


class WordPressInfo(Base):
    users: list[str] = Field(default_factory=list)
    version_status: Optional[str] = None


class HttpFact(Fact):
    fqdn: Optional[str] = None
    host_ip: str
    url: Optional[str] = None
    reachable: Optional[bool] = None
    status_code: Optional[int] = None
    headers: dict[str, str] = Field(default_factory=dict)
    security_headers: dict[str, SecHeader] = Field(default_factory=dict)
    score: Optional[str] = None
    csp: Optional[Csp] = None
    hsts: Optional[HstsInfo] = None
    cookies: list[Cookie] = Field(default_factory=list)
    server_header: Optional[str] = None
    powered_by: Optional[str] = None
    x_feserver: Optional[str] = None
    duplicate_headers: list[str] = Field(default_factory=list)
    technologies: list[Tech] = Field(default_factory=list)
    forms: list[dict[str, Any]] = Field(default_factory=list)
    login_form: Optional[bool] = None
    alerts: list[WebAlert] = Field(default_factory=list)
    paths: list[WebPath] = Field(default_factory=list)
    spider_url_count: Optional[int] = None
    wordpress: Optional[WordPressInfo] = None


# ---------------------------------------------------------------- dns

class Spf(Base):
    raw: str
    all_qualifier: Optional[str] = None


class Dmarc(Base):
    present: bool
    raw: Optional[str] = None
    p: Optional[str] = None
    sp: Optional[str] = None
    pct: Optional[int] = None
    rua: list[str] = Field(default_factory=list)
    ruf: list[str] = Field(default_factory=list)
    adkim: Optional[str] = None
    aspf: Optional[str] = None


class Dkim(Base):
    present: Optional[bool] = None
    selectors: list[str] = Field(default_factory=list)
    # S6a: abgefragte Selektoren; None heisst, der Lauf belegt die Liste nicht.
    probed: Optional[list[str]] = None
    probed_basis: Optional[Literal["scan", "scanner_stand"]] = None


class Dnssec(Base):
    signed: Optional[bool] = None
    valid: Optional[bool] = None
    issues: list[str] = Field(default_factory=list)


class Caa(Base):
    present: Optional[bool] = None
    issuers: list[str] = Field(default_factory=list)
    records: list[str] = Field(default_factory=list)


class MtaSts(Base):
    dns_record: Optional[bool] = None
    policy: Optional[bool] = None
    mode: Optional[str] = None


class TlsRpt(Base):
    present: Optional[bool] = None
    rua: list[str] = Field(default_factory=list)


class Dane(Base):
    smtp: Optional[bool] = None
    https: Optional[bool] = None


class Bimi(Base):
    present: Optional[bool] = None


class ZoneTransfer(Base):
    allowed: Optional[bool] = None
    ns_tested: list[str] = Field(default_factory=list)


class DanglingCname(Base):
    fqdn: str
    cname_target: Optional[str] = None
    takeover_risk: Optional[str] = None
    reason: Optional[str] = None


class DnsFact(Fact):
    domain: str
    ns: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    spf: Optional[Spf] = None
    dmarc: Optional[Dmarc] = None
    dkim: Optional[Dkim] = None
    dnssec: Optional[Dnssec] = None
    caa: Optional[Caa] = None
    mta_sts: Optional[MtaSts] = None
    tls_rpt: Optional[TlsRpt] = None
    dane: Optional[Dane] = None
    bimi: Optional[Bimi] = None
    zone_transfer: Optional[ZoneTransfer] = None
    dangling_cnames: list[DanglingCname] = Field(default_factory=list)


# ---------------------------------------------------------------- software

class Eol(Base):
    status: EolStatus = "unknown"
    date: Optional[str] = None
    source: Optional[str] = None
    latest_patch: Optional[str] = None
    upstream_eol_date: Optional[str] = None


class SoftwareFact(Fact):
    host_ip: str
    fqdn: Optional[str] = None
    product: str
    family: str
    kind: str
    version_raw: Optional[str] = None
    version_norm: Optional[str] = None
    build: Optional[str] = None
    distro: Optional[str] = None
    edition: Optional[str] = None
    hints: list[str] = Field(default_factory=list)
    eol: Eol = Field(default_factory=Eol)
    note: Optional[str] = None
    detection_sources: list[str] = Field(default_factory=list)
    vulnerabilities_count: Optional[int] = None


# ---------------------------------------------------------------- passive

class PassiveFact(Fact):
    host_ip: Optional[str] = None
    domain: Optional[str] = None
    port: Optional[int] = None
    transport: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner_excerpt: Optional[str] = None
    seen_at: Optional[str] = None
    verified: Optional[bool] = None
    hostnames: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------- coverage

class CoverageFact(Fact):
    scope: CoverageScope
    domain: Optional[str] = None
    host_ip: Optional[str] = None
    fqdn: Optional[str] = None
    phase: Optional[int] = None
    tool: str
    status: CoverageStatus
    raw_status: Optional[str] = None
    reason: Optional[str] = None
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None


# ---------------------------------------------------------------- threat

class CvssRef(Base):
    score: Optional[float] = None
    vector: Optional[str] = None


class Epss(Base):
    score: Optional[float] = None
    percentile: Optional[float] = None


class Kev(Base):
    listed: bool = False
    date_added: Optional[str] = None
    known_ransomware: Optional[str] = None


class ExploitDb(Base):
    count: Optional[int] = None
    metasploit: Optional[bool] = None


class ThreatFact(Fact):
    cve_id: str
    cvss_nvd: Optional[CvssRef] = None
    cwes: list[str] = Field(default_factory=list)
    epss: Optional[Epss] = None
    kev: Optional[Kev] = None
    exploitdb: Optional[ExploitDb] = None
    affected_software_ref: Optional[str] = None
    host_ip: Optional[str] = None
    port: Optional[int] = None


# ---------------------------------------------------------------- rest

class UnprocessedFact(Fact):
    kind: str
    what: str
    host_ip: Optional[str] = None
    fqdn: Optional[str] = None
    count: int = 1


class DecisionFact(Fact):
    host_ip: Optional[str] = None
    fqdn: Optional[str] = None
    payload: dict[str, Any] = Field(default_factory=dict)
    note: Optional[str] = None


class GeneratorInput(Base):
    kind: str
    name: str
    sha256: Optional[str] = None


class Generator(Base):
    name: str
    version: str
    inputs: list[GeneratorInput] = Field(default_factory=list)


class Facts(Base):
    schema_version: str = FACTS_SCHEMA_VERSION
    generator: Generator
    scan: ScanFact
    targets: list[TargetFact] = Field(default_factory=list)
    hosts: list[HostFact] = Field(default_factory=list)
    fqdns: list[FqdnFact] = Field(default_factory=list)
    services: list[ServiceFact] = Field(default_factory=list)
    tls: list[TlsFact] = Field(default_factory=list)
    http: list[HttpFact] = Field(default_factory=list)
    dns: list[DnsFact] = Field(default_factory=list)
    software: list[SoftwareFact] = Field(default_factory=list)
    passive: list[PassiveFact] = Field(default_factory=list)
    coverage: list[CoverageFact] = Field(default_factory=list)
    threats: list[ThreatFact] = Field(default_factory=list)
    unprocessed: list[UnprocessedFact] = Field(default_factory=list)
    decisions: list[DecisionFact] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    ENTITY_FIELDS: ClassVar[tuple[str, ...]] = (
        "targets", "hosts", "fqdns", "services", "tls", "http", "dns", "software",
        "passive", "coverage", "threats", "unprocessed", "decisions",
    )

    def all_facts(self) -> list[Fact]:
        out: list[Fact] = [self.scan]
        for name in self.ENTITY_FIELDS:
            out.extend(getattr(self, name))
        return out

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Facts":
        return cls.model_validate(data)

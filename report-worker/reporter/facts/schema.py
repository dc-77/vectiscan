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
- 1.0.5 (S6a2, spec/09 Q11): ``SoftwareFact.detection_sources`` nennt das Werkzeug,
  das den Eintrag geliefert hat; Eintraege aus ``tech_profile.technologies`` hiessen
  bisher pauschal ``webtech``, auch wenn webtech nichts lieferte. Die Familie wird
  nie ueber Namensgrenzen vergeben (``jQuery Migrate`` ist ``jquery_migrate``, nicht
  ``jquery``). Kein Feld geaendert, Bedeutung praeziser; Golden-Facts neu gebaut.
- 1.0.6 (S6b-1, spec/09 Q3, Q9, Q10, Q15, Q16, E4, E5, Issue #33): neue optionale
  Felder ``FqdnFact.cname`` (dnsx), ``Spf.mechanisms``, ``PassiveFact.service``
  (Shodan-Modul), ``HostFact.shared`` (geteiltes System), ``HostFact.third_party``
  (Drittanbieter), ``HostFact.reach`` (vom Pruefstand aus erreichbar?),
  ``TlsFact.assigned_from`` und ``Facts.context`` (Kundenkontext mit Quelle je Feld).
  nmap ohne offenen Port ist ``empty`` statt ``ok``. Softwarefakten eines VHosts mit
  Weiterleitung auf einen anderen Host gehoeren diesem Host; OWA-Builds aus
  Spider-URLs nur fuer den Host im Namen der URL.
- 1.0.7 (S6b-2, spec/09 Q12 bis Q14, Q18, spec/08 Punkte 4 und 20): neue optionale Felder
  ``ServiceFact.fp_server``, ``fp_title``, ``fp_login`` (Fingerabdruck aus der Antwort des
  Dienstes, nmap ``servicefp`` und Skripte), ``ServiceFact.rejects_before_auth`` (der Dienst
  weist fremde Quellen vor der Anmeldung ab, laut Passivbanner), ``Reputation``-Felder zu den
  AbuseIPDB-Meldungen, ``WebAlert.run`` (Lauf der ZAP-Meldung), ``WordPressInfo.version``,
  ``release_date`` und ``core_vulnerabilities``, ``SoftwareFact.release_date`` und
  ``SoftwareFact.vulnerabilities`` (wpscan-Kennungen). Bedeutung praeziser:
  ``WebAlert.confidence`` ist die hoechste Konfidenz der Einzelmeldungen, POP3 mit USER oder
  SASL vor STLS gilt als Anmeldung ohne TLS-Zwang. Neu ``PassiveFact.service_seen_at``,
  der Zeitstempel des Dienstes (HTTP-Kopf ``Date`` im Banner); ``seen_at`` bleibt die
  Aktualisierung des Hosts bei der Quelle.
- 1.1.0 (S6b-3, spec/10 R1 bis R19, E13): Bedeutung geaendert, deshalb Minor.
  ``HttpFact.header_eval`` beschreibt, an welcher Antwort die Sicherheits-Header gemessen
  sind (Status, ``location``, Endseite oder nicht) und welche Quelle die Endseite liefert
  (header_check, redirect_probe, testssl, Teilbelege aus wpscan und ZAP); ``csp`` und
  ``security_headers`` beschreiben diese bewertete Antwort. ``Csp`` zerlegt die Direktiven
  (script-src und style-src getrennt, Nonce und Hash heben ``unsafe-inline`` auf).
  ``HostFact.blocked`` gilt nur mit belegter Sperre (403, 429, Challenge); ``reach`` kennt
  ``no_response`` (nmap ohne Hostbericht). Neu: ``HostFact.nmap_host_report``,
  ``betriebsform``, ``Provider.domain``, ``Reputation.abuseipdb_distinct_users``,
  ``FqdnFact.real_content`` und ``skipped``, ``CertShort`` mit Aussteller, Laufzeit und
  Fingerabdruck (nmap ssl-cert), ``ServiceFact.kennung``, ``unidentified``,
  ``smtp_vrfy`` und ``auth_before_starttls``, ``TlsCert.fingerprint_sha256`` und
  ``renewal`` (crt.sh, E13), ``TlsFact.cert_assigned_from`` und
  ``cbc_obsoleted_offered``, ``WordPressInfo.findings``, ``WebAlert.param``,
  ``TargetFact.discovered`` (gefundene, nicht im Inventar angekommene Namen),
  ``CoverageFact.target``, ``SoftwareFact.conflicts``. URLhaus ohne Daten heisst
  ``compromised=None`` (Ausfall), nicht "nicht kompromittiert".
- 1.2.0 (S6b-4, spec/11 T1 bis T15): neue Entitaet ``path_search`` (Pfadsuche je Host aus
  feroxbuster-Statistik und ffuf-Treffern, T8). Neue optionale Felder: ``ScanFact.scanned_ports``
  (Portbereich des Portscans laut nmap ``scaninfo``, T1), ``TlsFact.measured_ip`` und
  ``HttpFact.measured_ip`` (tatsaechlich gemessene Adresse laut testssl ``-->>`` und httpx
  ``host``, T7), ``HostFact.additional_ips`` (AAAA aus dnsx ohne Inventareintrag, T7),
  ``HstsInfo.tool``, ``url``, ``status_code`` (Antwort, an der HSTS gemessen ist, T3, T4),
  ``PassiveFact.kennung`` (Dienstkennung aus Modul und Banner, T1), ``ServiceFact.foreign``
  (Dienst eines anderen Kunden auf einem geteilten Server, T9), ``SharedSystem.server_operator``
  (Betreiber des Servers laut rDNS und Standardzertifikat, T9), ``SoftwareFact.outdated`` und
  ``latest_version`` (wpscan, T15), ``WpFinding.found_by`` (T3). Bedeutung geaendert:
  ``ServiceFact.kennung`` entsteht auch aus Protokollskripten (IMAP, POP3, SMTP) und dem
  Passivbanner desselben Ports; ``CertRenewal`` beschreibt die Zertifikatslinie (gleiches
  Namensset und gleicher Aussteller) statt aller Zertifikate eines Namens (T14); ``HttpFact.hsts``
  wertet keine 4xx-, 429- oder Challenge-Antwort (T4).
- 1.3.0 (S6b-4n, spec/11 N1 bis N15): keine neue Entitaet, Bedeutung geaendert, deshalb Minor.
  ``HostFact.additional_ips`` fuehrt auch weitere A-Eintraege derselben Namen (N5);
  ``HttpFact.hsts`` gilt nach E24 auch an einer Fehlerseite (4xx ausser 429), dort nur als gesetzt,
  und hinter einer Sicherheitsabfrage nie aus der ersten Antwort von redirect_probe (N2);
  ``HeaderMeasurement.evaluated`` ist redirect_probe nur mit eigener Endantwort (N3);
  ``HttpFact.login_form`` nur fuer Anmeldeseiten desselben Namens (N4); Technik aus webtech und
  CMS-Erkennung einer Adresse, deren Webnamen alle auf einen anderen Host weiterleiten, gehoert
  dem Ziel (N4); ``TlsCert.valid_elsewhere`` nur fuer dieselbe Zertifikatslinie, dieselbe
  Zustaendigkeit und aus testssl mit vollstaendiger Kette (N8). Neue optionale Felder:
  ``Csp.script_rule`` (N1), ``HeaderMeasurement.final_response`` und ``client_redirect`` (N3),
  ``Dmarc.delegated_to`` (N7), ``SoftwareFact.child_of`` (N9), ``SharedSystem.foreign_sources``
  und ``ServiceFact.foreign_domain`` (N11), ``HttpFact.aspnet_source`` (N12),
  ``CoverageFact.run_status`` und ``PathSearchFact.tool_reasons``, ``statistics`` (N13). Der
  DNS-Fakt traegt den Nachweis des Zonentransfers je Domain (N6), ein Windows-Eintrag Shodan
  ``os`` als zweite Quelle (N12).
"""
from __future__ import annotations

from typing import Any, ClassVar, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

FACTS_SCHEMA_VERSION = "1.3.0"

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
    # S6b-4 (spec/11 T1): Portbereich des Portscans laut nmap ``scaninfo`` ("1,3-4,6-7,..."),
    # Grundlage fuer "ausserhalb des geprueften Portbereichs" bei Ports aus einer Passivquelle.
    scanned_ports: Optional[str] = None
    scanned_port_count: Optional[int] = None


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


class DiscoveredName(Base):
    """Ein von der Hostsuche gefundener Name, der nicht im Host-Inventar ankam (spec/10 R5).

    Quelle ist die Teilausgabe von gobuster_dns (``fqdn ip[,ip]`` je Zeile), die der
    Scanner bei Zeitueberschreitung nicht weiterreicht (spec/09 Q1). ``third_party`` nennt
    den Betreiber, wenn der Name erkennbar zu einem Drittanbieter gehoert (Microsoft 365
    Autodiscover, CNAME auf eine fremde Domain)."""
    fqdn: str
    ips: list[str] = Field(default_factory=list)
    third_party: Optional[str] = None
    source: str = "gobuster_dns"


class TargetFact(Fact):
    domain: str
    is_primary: bool = True
    targets_source: str
    whois: Optional[Whois] = None
    discovery_health: Optional[dict[str, Any]] = None
    out_of_scope: list[OutOfScope] = Field(default_factory=list)
    # S6b-3 (spec/10 R5): gefunden, aber nicht im Inventar angekommen, bis S6c (Q1) die
    # Discovery repariert. ``discovered_total`` zaehlt Inventarnamen plus diese Namen.
    discovered: list[DiscoveredName] = Field(default_factory=list)
    discovered_total: Optional[int] = None


# ---------------------------------------------------------------- host / fqdn

class Provider(Base):
    isp: Optional[str] = None
    usage_type: Optional[str] = None
    country: Optional[str] = None
    # S6b-3 (spec/10 Teil 2 CA): Domain des Netzbetreibers laut AbuseIPDB
    # (``vodafone-ip.de`` bei ``isp`` "Castenow GmbH").
    domain: Optional[str] = None


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
    # S6b-2 (spec/09 Q12): Score 0 heisst nicht "keine Meldungen"; eine Adresse auf der
    # Freigabeliste von AbuseIPDB (Vercel bei heuel) hat Score 0 trotz 26 Meldungen.
    abuseipdb_total_reports: Optional[int] = None
    abuseipdb_whitelisted: Optional[bool] = None
    abuseipdb_last_reported_at: Optional[str] = None
    is_tor: Optional[bool] = None
    otx_pulse_count: Optional[int] = None
    urlhaus_compromised: Optional[bool] = None
    greynoise_classification: Optional[str] = None
    abuseipdb_distinct_users: Optional[int] = None


SharedKind = Literal["hoster", "platform"]
ReachStatus = Literal["no_open_ports", "no_response", "unreachable_from_scanner", "no_ipv6_route"]
Betriebsform = Literal["rechenzentrum", "anschluss", "plattform", "unbekannt"]


class SharedSystem(Base):
    """Fakt "geteiltes System" (spec/09 Q3, S6b-1).

    ``platform``: ein Name des Kunden zeigt per CNAME auf eine fremde Domain (SaaS,
    Baukasten, CDN) oder der Scanner hat den Host als CDN-Kante erkannt. ``hoster``:
    auf der Adresse liegen fremde Namen (Zertifikat, Shodan), das rDNS gehoert dem
    Betreiber und die Adresse ist kein eigener Anschluss des Kunden. ``signals`` sind
    Codes, ``evidence`` die woertlichen Belege.
    """
    kind: SharedKind
    operator: Optional[str] = None
    # S6b-4 (spec/11 T9, E18): Betreiber des Servers laut rDNS und Standardzertifikat, wenn
    # das nicht der Netzbetreiber ist ("planwerk6.de" auf einem Server im Netz von Hetzner).
    server_operator: Optional[str] = None
    foreign_names: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    # S6b-4n (spec/11 N11): registrierbare fremde Domains je Quelle ("passive": Hostnamen der
    # Passivquelle, "certificate": Zertifikate), fuer die Zaehlung mit Quelle im Bericht.
    foreign_sources: dict[str, list[str]] = Field(default_factory=dict)


class ThirdParty(Base):
    """Drittanbieter-Adresse: der Scanner hat sie begruendet uebersprungen
    (``ai_host_skip``) und jeder Kundenname darauf zeigt per CNAME auf eine fremde
    Domain. Zaehlt nicht als Host des Kunden (spec/09 Teil 2, S6b-1)."""
    operator: Optional[str] = None
    reason: str = "ai_host_skip_cname"
    evidence: list[Evidence] = Field(default_factory=list)


class Reach(Base):
    """Erreichbarkeit vom Pruefstand aus (spec/09 Q9, E4).

    ``no_open_ports``: nmap lief, fand aber keinen offenen Port. Dann liegt kein
    Messergebnis vor, und die Abwesenheit eines Dienstes ist nicht belegt.
    ``unreachable_from_scanner``: zusaetzlich meldet eine Passivquelle, die hoechstens
    sieben Tage vor dem Scanende gesehen wurde, Dienste auf dieser Adresse.
    ``no_ipv6_route``: der Pruefstand hatte keine IPv6-Verbindung.
    ``no_response`` (S6b-3, spec/10 R3): nmap lieferte keinen Hostbericht (mit ``--open``
    fehlt das ``<host>``-Element); ob der Host antwortet, ist nicht belegt.
    """
    status: ReachStatus
    passive_ports: list[int] = Field(default_factory=list)
    passive_seen_at: Optional[str] = None
    passive_source: Optional[str] = None


class AdditionalIp(Base):
    """Weitere Adresse eines Systems laut DNS, die nicht im Host-Inventar steht (spec/11 T7).

    dnsx loest die Namen des Auftrags auch nach AAAA auf; der Scanner uebernimmt nur die
    A-Eintraege. Die Adresse gehoert zum System der IPv4-Adresse derselben Namen und ist
    vom Pruefstand aus nicht geprueft. S6b-4n (spec/11 N5): auch weitere A-Eintraege eines
    Namens, von denen der Scanner nur einen ins Inventar nahm (``family`` 4); testssl und httpx
    koennen dort gemessen haben (``measured_ip``), der Portscan nicht."""
    ip: str
    family: Literal[4, 6]
    names: list[str] = Field(default_factory=list)
    source: str = "dnsx"


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
    shared: Optional[SharedSystem] = None
    third_party: Optional[ThirdParty] = None
    reach: Optional[Reach] = None
    # S6b-3 (spec/10 R3): False, wenn nmap fuer die Adresse keinen Hostbericht schrieb und
    # der Leser den Host aus der Laufstatistik ergaenzt hat.
    nmap_host_report: Optional[bool] = None
    # S6b-3 (spec/10 R13): Betriebsform fuer Auswirkungs- und Rollentexte. ``anschluss``:
    # eigene Leitung des Kunden (AbuseIPDB-Nutzungsart Fixed Line ISP); ``rechenzentrum``:
    # gemieteter oder geteilter Server; ``plattform``: SaaS, Baukasten oder CDN.
    betriebsform: Optional[Betriebsform] = None
    # S6b-3 (spec/10 R9): traegt der Host Mail des Kunden (MX, SPF-Mechanismus oder
    # Autodiscover zeigen auf ihn) bzw. eine Webseite des Kunden mit Inhalt? Grundlage fuer
    # "Postfaecher" und "Webseiten" in Zustaendigkeits- und Auswirkungstexten.
    serves_customer_mail: Optional[bool] = None
    serves_customer_web: Optional[bool] = None
    # S6b-4 (spec/11 T7): AAAA-Adressen derselben Namen ohne Inventareintrag.
    additional_ips: list[AdditionalIp] = Field(default_factory=list)


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
    # S6b-1 (spec/09 Q3): CNAME-Kette aus der dnsx-Aufloesung, erstes Ziel zuerst.
    cname: list[str] = Field(default_factory=list)
    # S6b-3 (spec/10 R3): Einordnung der Startseite durch die Scan-Steuerung (Inhalt oder
    # Fehler-, Weiterleitungs-, Parkseite); nur fuer die Abdeckung, nie fuer einen Befund.
    real_content: Optional[bool] = None
    # S6b-3 (spec/10 R4): nicht eingerichteter Name ("parking"), vom Scanner uebersprungen.
    skipped: Optional[str] = None
    # S6b-4 (spec/11 Teil 3 HL): Titel und Endadresse der Seite, die redirect_probe aufgenommen
    # hat; das Bildschirmfoto zeigt diese Seite, nicht die erste Antwort.
    probe_title: Optional[str] = None
    probe_final_url: Optional[str] = None


# ---------------------------------------------------------------- service / tls

class CertShort(Base):
    cn: Optional[str] = None
    san: list[str] = Field(default_factory=list)
    not_after: Optional[str] = None
    # S6b-3 (spec/10 R3): nmap ssl-cert vollstaendig, fuer Dienste ohne testssl-Lauf.
    issuer: Optional[str] = None
    not_before: Optional[str] = None
    days_left: Optional[int] = None
    expired: Optional[bool] = None
    self_signed: Optional[bool] = None
    fingerprint_sha1: Optional[str] = None


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
    # S6b-2 (spec/09 Q13): Fingerabdruck aus der Antwort des Dienstes. ``fp_server`` ist die
    # Server-Kennung (HTTP-Kopf ``Server`` aus dem nmap-Fingerprint oder http-server-header),
    # ``fp_title`` der Seitentitel, ``fp_login`` True bei belegter Anmeldung (Anmeldemaske,
    # ``auth-required``, Passwortfeld, HTTP-Authentifizierung).
    fp_server: Optional[str] = None
    fp_title: Optional[str] = None
    fp_login: Optional[bool] = None
    # S6b-2 (spec/09 Teil 2 LW, JW): der Dienst weist fremde Quellen vor jeder Anmeldung ab
    # (PostgreSQL "no pg_hba.conf entry"), laut Passivbanner desselben IP:Port.
    rejects_before_auth: Optional[bool] = None
    # S6b-3 (spec/10 R9, R14): Kennung des Dienstes aus Produkt, Server-Kennung, Titel oder
    # Stream-Kopf; ``unidentified`` bei einem nmap-Tabellentreffer ("cadlock?") ohne jede
    # Kennung aus der Antwort des Dienstes.
    kennung: Optional[str] = None
    unidentified: Optional[bool] = None
    # S6b-3 (spec/10 R19): SMTP-Faehigkeiten vor STARTTLS laut nmap smtp-commands.
    smtp_vrfy: Optional[bool] = None
    auth_before_starttls: Optional[bool] = None
    # S6b-4 (spec/11 T9, E18): Dienst eines anderen Nutzers desselben geteilten Servers
    # (Zertifikat oder Stream-Kennung einer fremden Domain). Kein Dienst des Kunden; er
    # erscheint als Beobachtung beim Betreiber, nicht als Befund.
    foreign: Optional[bool] = None
    # S6b-4n (spec/11 N11): die fremde Domain laut Zertifikat oder Kennung; ohne sie ist der Dienst
    # kein belegter Dienst einer anderen Domain (castenow 8800, Icecast ohne Domain).
    foreign_domain: Optional[str] = None


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
    # S6b-3 (spec/10 R4): Fingerabdruck fuer die Bindung an weitere VHosts.
    fingerprint_sha256: Optional[str] = None
    # S6b-3 (E13): Erneuerungshistorie des Namens aus den CT-Logs (crt.sh).
    renewal: Optional["CertRenewal"] = None
    # S6b-4 (spec/11 T14): Adressen (``ip:port``), an denen derselbe Name bereits ein gueltiges,
    # spaeter ablaufendes Zertifikat traegt (castenow mailstore: das erneuerte Wildcard-Zertifikat
    # laeuft schon auf .4 und .6), mit dessen Ablauf.
    valid_elsewhere: list[str] = Field(default_factory=list)
    valid_elsewhere_not_after: Optional[str] = None


class CertRenewal(Base):
    """Erneuerungshistorie einer Zertifikatslinie laut Certificate Transparency (crt.sh, E13).

    S6b-4 (spec/11 T14): eine Linie sind die Zertifikate mit gleichem Namensset und gleichem
    Aussteller (die Let's-Encrypt-Linie eines Namens, nicht dazu die Wildcard-Linie eines
    anderen Ausstellers). ``certificates``: Zahl der Zertifikate der Linie;
    ``recent_leads``: Vorlauf der letzten (hoechstens drei) Erneuerungen vor dem Ablauf des
    Vorgaengers in Tagen, aelteste zuerst; ``recent_renewals``: Datum dieser Erneuerungen;
    ``expected_renewal``: Ablauf des juengsten Zertifikats minus juengster Vorlauf.
    ``interval_days`` und ``lead_days`` sind die Mediane der Linie."""
    name: str
    certificates: int
    interval_days: Optional[int] = None
    lead_days: Optional[int] = None
    last_not_before: Optional[str] = None
    last_not_after: Optional[str] = None
    source: str = "crtsh"
    issuer: Optional[str] = None
    recent_leads: list[int] = Field(default_factory=list)
    recent_renewals: list[str] = Field(default_factory=list)
    expected_renewal: Optional[str] = None
    lines: int = 1


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
    # S6b-4 (spec/11 T3, T4): die Antwort, an der HSTS gemessen ist (Werkzeug, Adresse, Status).
    tool: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None


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
    # S6b-1 (spec/09 Q10): Protokolle, Verfahren und Schwachstellen stammen aus dem
    # testssl-Lauf desselben IP:Port mit anderem Namen. Wert ist "<gepruefter Name>:<Port>".
    # S6b-3 (spec/10 R4): gilt fuer alle VHosts desselben IP:Port; das Zertifikat nur, wenn
    # Fingerabdruck oder Namensdeckung passen (``cert_assigned_from``).
    assigned_from: Optional[str] = None
    cert_assigned_from: Optional[str] = None
    # S6b-3 (spec/10 R6): testssl ``cipherlist_OBSOLETED`` ("Obsoleted CBC ciphers").
    cbc_obsoleted_offered: Optional[bool] = None
    # S6b-4 (spec/11 T7): die Adresse, an der testssl tatsaechlich gemessen hat ("-->>"); bei
    # DNS-Rotation weicht sie von der Inventaradresse ab (huendgen 52.59.120.70).
    measured_ip: Optional[str] = None


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
    # S6b-3 (spec/10 R1): Direktiven einzeln. ``script_*`` gilt fuer script-src (Rueckfall
    # default-src); ein Nonce, Hash oder strict-dynamic hebt ``unsafe-inline`` dort auf.
    directives: dict[str, list[str]] = Field(default_factory=dict)
    script_unsafe_inline: Optional[bool] = None
    script_unsafe_eval: Optional[bool] = None
    style_unsafe_inline: Optional[bool] = None
    nonce_or_hash: Optional[bool] = None
    wildcard_directives: list[str] = Field(default_factory=list)
    frame_ancestors: Optional[str] = None
    # S6b-4n (spec/11 N1): die Richtlinie regelt Skriptquellen (script-src oder default-src);
    # eine CSP nur mit frame-ancestors schuetzt vor Einbettung, nicht vor fremden Skripten.
    script_rule: Optional[bool] = None


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
    # S6b-2 (spec/09 Q14): Lauf, aus dem die Meldung stammt: "passive" (ZAP-Passivscanner,
    # sourceid 3) oder "active" (aktive Pruefung, sourceid 1).
    run: Optional[Literal["passive", "active"]] = None
    # S6b-3 (spec/10 R15): betroffener Parameter oder Kopf (z. B. Content-Security-Policy).
    param: Optional[str] = None


class WebPath(Base):
    url: str
    status: Optional[int] = None
    length: Optional[int] = None


class WordPressInfo(Base):
    users: list[str] = Field(default_factory=list)
    version_status: Optional[str] = None
    # S6b-2 (spec/09 Q18): Kernversion, Veroeffentlichung und bekannte Kern-Schwachstellen
    # laut wpscan; "outdated" allein heisst nicht unsicher, wenn der Zweig gepflegt wird.
    version: Optional[str] = None
    release_date: Optional[str] = None
    core_vulnerabilities: Optional[int] = None
    # S6b-2 (spec/09 Teil 2 DB): Adresse, ueber die wpscan die Benutzernamen fand.
    users_found_by: list[str] = Field(default_factory=list)
    # S6b-3 (spec/10 R19): wpscan ``interesting_findings`` (xmlrpc, readme, wp_cron ...).
    findings: list["WpFinding"] = Field(default_factory=list)


class WpFinding(Base):
    type: str
    url: Optional[str] = None
    note: Optional[str] = None
    # S6b-4 (spec/11 T3): wie wpscan den Fund belegt ("Direct Access", "Headers").
    found_by: Optional[str] = None


HeaderBasis = Literal["final", "redirect", "client_error", "server_error", "challenge",
                      "non_html", "unreachable"]
HeaderTool = Literal["header_check", "redirect_probe", "testssl", "wpscan", "zap"]


class HttpResponse(Base):
    """Eine gemessene HTTP-Antwort (spec/10 R1). ``status_basis``: woher der Statuscode
    stammt, weil header_check ihn nicht selbst speichert (httpx-Kette, testssl,
    ``location``, Inventar, Angabe des Werkzeugs)."""
    tool: HeaderTool
    url: Optional[str] = None
    status_code: Optional[int] = None
    status_basis: Optional[Literal["httpx_chain", "testssl", "location", "inventory", "claimed"]] = None
    location: Optional[str] = None
    content_type: Optional[str] = None
    challenge: Optional[str] = None


class HeaderValue(Base):
    present: Optional[bool] = None
    value: Optional[str] = None
    tool: HeaderTool
    url: Optional[str] = None


class HeaderMeasurement(Base):
    """An welcher Antwort die Sicherheits-Header gemessen sind (spec/10 R1).

    ``basis`` ``final``: die bewertete Antwort ist eine Endseite (2xx, HTML, ohne
    ``location``, ohne Challenge). Sonst ist die Messung nicht bewertbar, und nur HSTS
    (aus ``first``) gilt. ``complete``: der volle Header-Satz der bewerteten Antwort ist
    bekannt; Teilbelege (wpscan, ZAP) kennen nur einzelne Header. ``missing`` und
    ``unknown`` nennen die kanonischen Header ohne Beleg bzw. ohne Aussage."""
    basis: HeaderBasis
    first: Optional[HttpResponse] = None
    evaluated: Optional[HttpResponse] = None
    complete: bool = False
    headers: dict[str, HeaderValue] = Field(default_factory=dict)
    missing: list[str] = Field(default_factory=list)
    unknown: list[str] = Field(default_factory=list)
    framing_protected: Optional[bool] = None
    # S6b-4n (spec/11 N3): die bewerteten Header stammen aus der Endantwort (header_check an einer
    # Endseite, redirect_probe mit eigener Endantwort, testssl mit Status 200). False bei
    # Teilbelegen (wpscan, ZAP je URL); redirect_probe speichert bei clientseitiger Weiterleitung
    # die Header der ersten Antwort (heuel ose: gleicher ETag wie header_check), die gelten nicht.
    final_response: Optional[bool] = None
    # Die erste Antwort ist eine clientseitige Weiterleitung (Status 200, die Probe endet auf einer
    # anderen Seite desselben Hosts mit anderem Titel); ``unknown`` ist dann nur an dieser
    # Weiterleitungsseite gemessen.
    client_redirect: Optional[bool] = None


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
    # S6b-3 (spec/10 R9): X-AspNet-Version aus der ersten Antwort oder der Endseite.
    aspnet_version: Optional[str] = None
    # S6b-4n (spec/11 N12): Werkzeug, das den Wert geliefert hat (header_check, redirect_probe,
    # httpx); ohne Kopf in der Antwort nennt httpx die Version (castenow mail, mail2).
    aspnet_source: Optional[str] = None
    duplicate_headers: list[str] = Field(default_factory=list)
    technologies: list[Tech] = Field(default_factory=list)
    forms: list[dict[str, Any]] = Field(default_factory=list)
    login_form: Optional[bool] = None
    alerts: list[WebAlert] = Field(default_factory=list)
    paths: list[WebPath] = Field(default_factory=list)
    spider_url_count: Optional[int] = None
    wordpress: Optional[WordPressInfo] = None
    header_eval: Optional[HeaderMeasurement] = None
    # S6b-4 (spec/11 T7): Adresse, die httpx fuer den Namen aufgeloest und gemessen hat.
    measured_ip: Optional[str] = None


# ---------------------------------------------------------------- dns

class SpfMechanism(Base):
    """Ein Mechanismus des SPF-Eintrags (``ip4:85.22.176.0/24``, ``a``, ``a:mail.x.de``,
    ``mx``, ``include:...``, ``redirect=...``). ``value`` ist leer bei ``a`` und ``mx``
    ohne Namen."""
    qualifier: str = "+"
    kind: str
    value: Optional[str] = None
    # S6b-3 (spec/10 R19): Adressen des Auftrags, auf die der Mechanismus zeigt (``a`` auf den
    # Domainnamen, ``a:name``, ``mx`` auf MX-Namen im Inventar, ``ip4`` mit einer Adresse).
    ips: list[str] = Field(default_factory=list)


class Spf(Base):
    raw: str
    all_qualifier: Optional[str] = None
    mechanisms: list[SpfMechanism] = Field(default_factory=list)


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
    # S6b-4n (spec/11 N7): ``_dmarc.<domain>`` zeigt per CNAME auf einen Dienstleister
    # (bergersysteme: ``bergersysteme.com.dmarc.hornetdmarc.com``); die Richtlinie pflegt dann dieser.
    delegated_to: Optional[str] = None


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
    # S6b-4 (spec/11 T11): Beginn der Langzeitpflege, wenn das Release am Scantag nur noch
    # LTS-Updates erhaelt (Debian 12 seit 11.07.2026); ``date`` ist dann das Ende der LTS.
    lts_since: Optional[str] = None


class VulnRef(Base):
    """Eine vom Werkzeug genannte Schwachstelle (wpscan): Titel, Kennungen, behoben in."""
    title: str
    cves: list[str] = Field(default_factory=list)
    fixed_in: Optional[str] = None


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
    # S6b-2: Veroeffentlichung der Version (wpscan) und die genannten Schwachstellen (#16).
    release_date: Optional[str] = None
    vulnerabilities: list[VulnRef] = Field(default_factory=list)
    # S6b-3 (spec/10 R19): widersprechende Kennung einer anderen Quelle am selben Ort
    # (heuel 20.79.218.75:22 nmap FortiSSH, Shodan SSH-2.0-WingFTPServer).
    conflicts: list[str] = Field(default_factory=list)
    # S6b-4 (spec/11 T15): wpscan ``outdated`` und ``latest_version`` je Erweiterung.
    outdated: Optional[bool] = None
    latest_version: Optional[str] = None
    # S6b-4n (spec/11 N9): Slug des Elternthemes, wenn dies ein Kindtheme ist; ein eigenes
    # Kindtheme hat keine neueste Version im Verzeichnis, sein Stand folgt dem Elterntheme.
    child_of: Optional[str] = None


# ---------------------------------------------------------------- passive

class PassiveFact(Fact):
    host_ip: Optional[str] = None
    domain: Optional[str] = None
    port: Optional[int] = None
    transport: Optional[str] = None
    # S6b-1 (E5): Dienstname laut Passivquelle (Shodan-Modul ``smtp``, ``https`` ...).
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner_excerpt: Optional[str] = None
    seen_at: Optional[str] = None
    # S6b-2 (spec/09 Q13): Zeitstempel dieses Dienstes laut Banner (HTTP-Kopf ``Date``);
    # ``seen_at`` ist die letzte Aktualisierung des ganzen Hosts bei der Quelle.
    service_seen_at: Optional[str] = None
    verified: Optional[bool] = None
    hostnames: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    # S6b-4 (spec/11 T1): Kennung des Dienstes aus Modul und Banner ("ManageSieve (Dovecot
    # Pigeonhole)" bei Modul "auto"), ohne den Zusatz "laut Passivquelle".
    kennung: Optional[str] = None


# ---------------------------------------------------------------- path search

PathVerdict = Literal["reliable", "unreliable", "aborted", "skipped", "not_run"]


class PathSearchFact(Fact):
    """Suche nach nicht verlinkten Pfaden je Host (spec/11 T8).

    feroxbuster schreibt eine Statistikzeile mit den Statuscodes aller Anfragen; ffuf nennt
    nur Treffer mit Status 200, 301, 302 und 307. Laeuft die Suche gegen eine Weiterleitung
    (Apex auf www), eine Fehlerseite (403) oder eine Sicherheitsabfrage, sagt sie nichts ueber
    die Seite aus. ``verdict`` fasst beide Werkzeuge zusammen: ``reliable`` ein Lauf lieferte
    Inhaltsantworten; ``unreliable`` jede Antwort war eine Weiterleitung oder Fehlerseite
    (``status_codes``, ``challenge`` bei einer Sicherheitsabfrage der Plattform); ``aborted``
    die Laeufe brachen ab (``abort_reason``: Zeitlimit, keine Verbindung, Abwehrmerkmal);
    ``skipped`` die Scan-Steuerung liess beide Werkzeuge aus. ``tools`` nennt das Urteil je
    Werkzeug."""
    host_ip: str
    target_url: Optional[str] = None
    verdict: PathVerdict
    status_codes: list[int] = Field(default_factory=list)
    challenge: bool = False
    abort_reason: Optional[str] = None
    tools: dict[str, str] = Field(default_factory=dict)
    requests: Optional[int] = None
    hits: Optional[int] = None
    # S6b-4n (spec/11 N13): Abbruchgrund je Werkzeug (Zeitlimit von ffuf neben einer belastbaren
    # feroxbuster-Suche, dortmund-beach) und ob feroxbuster seine Abschlussstatistik schrieb
    # (junkerwerk .29: am Zeitlimit ohne Statistik beendet).
    tool_reasons: dict[str, str] = Field(default_factory=dict)
    statistics: Optional[bool] = None


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
    # S6b-3 (spec/10 R3): Ziel des Laufs laut Rohausgabe (zap_active ``target``).
    target: Optional[str] = None
    # S6b-4n (spec/11 N13): Abschluss des Laufs laut Rohausgabe (zap_active ``status: complete``).
    run_status: Optional[str] = None


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


ContextSource = Literal["kunde", "recherche", "admin"]


class ContextField(Base):
    """Ein Feld des Kundenkontexts mit Herkunft (spec/09 Q15)."""
    name: str
    value: str
    source: Optional[ContextSource] = None
    url: Optional[str] = None


class ContextSystem(Base):
    fqdn: str
    zweck: str


class CustomerContext(Base):
    """Kundenkontext der Order, wie er in den Bericht eingeht. Kein Werkzeugfakt:
    er steht hier, damit im Nachhinein pruefbar ist, woher Firmenname, Kurzname,
    Branche und Mitarbeiterzahl stammen (Kunde, Recherche oder Admin)."""
    fields: list[ContextField] = Field(default_factory=list)
    systeme: list[ContextSystem] = Field(default_factory=list)
    systeme_source: Optional[ContextSource] = None
    systeme_url: Optional[str] = None


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
    path_search: list[PathSearchFact] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    context: Optional[CustomerContext] = None

    ENTITY_FIELDS: ClassVar[tuple[str, ...]] = (
        "targets", "hosts", "fqdns", "services", "tls", "http", "dns", "software",
        "passive", "coverage", "threats", "unprocessed", "decisions", "path_search",
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


TlsCert.model_rebuild()
WordPressInfo.model_rebuild()

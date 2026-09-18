# reporter.facts: Evidence Layer (facts.json)

Session S1 des Report-Umbaus (`report-prototype/spec/05` M1 und M5, `spec/07` S1).
Eine Faktendatei je Scan, aus der der Pruefkatalog (S2) Befunde ableitet. Dieses
Paket erzeugt keine Befunde, keine Einstufungen, keine CVSS-Werte und ruft keine KI.

## Aufruf

```
python -m reporter.facts <tar|dir> [--tool-runs results.json] [--orders orders.json] [-o facts.json]
python -m reporter.facts --snapshot tests/golden/api-snapshot/<order>
python -m reporter.facts --golden [--check]
```

Programmatisch (Spec-Signatur plus zwei optionale Kwargs):

```python
from reporter.facts import build_facts
facts = build_facts(scan_data_dir, host_inventory, tech_profiles, correlated_findings, job_payload,
                    tool_runs=rows, order=order_dict)
facts.to_dict()  # JSON-faehig, deterministisch mit reporter.facts.serialize.dumps
```

`scan_data_dir` ist ein entpacktes Scan-Verzeichnis oder direkt das `.tar.gz`. Tars werden
ueber `tarfile` im Speicher gelesen und nie entpackt (IPv6-Hostverzeichnisse mit Doppelpunkt
sind unter Windows nicht anlegbar). `tool_runs` sind die `scan_results`-Zeilen (API-Form
`{"data": {"results": [...]}}`, Liste oder DB-Dicts). Ohne sie bleibt die Coverage `unknown`.

## Schema

`schema.py`, pydantic v2, `extra="forbid"`, `FACTS_SCHEMA_VERSION`. Jedes Faktum traegt
`id`, `source` (Werkzeug), `mode` (`active|passive`), `observed_at` (UTC, sekundengenau),
`confidence` und `evidence[{tool, ref, excerpt}]`. `ref` ist der POSIX-Pfad im Tar ohne
`<orderId>/` oder `scan_results:<tool>[:<host>]`; `excerpt` ist die woertliche Zeile (ANSI
entfernt, max 300 Zeichen).

| Entitaet | Inhalt | Quellen (Vorrang von links nach rechts) |
|---|---|---|
| scan | Auftrag, Paket, Domains, Scanfenster, Werkzeugversionen, nmap-Argumente, Scanner-Egress | meta.json, orders.json (targets), nmap.xml |
| targets | Domain, Primaerziel, whois, discovery_health, out_of_scope | host_inventory, phase0a/whois.json, orders.json |
| hosts | IP, Familie, rDNS, Provider, Erreichbarkeit, Portsummen, Blockade, Reputation | nmap.xml, host_inventory, abuseipdb, passive_intel |
| fqdns | VHost-Status, Titel, final_url, Body-Hash, Aliase, Screenshot-Key, WAF | host_inventory.vhosts, wafw00f |
| services | offene Ports mit Produkt, Version roh und normalisiert, TLS-Zwang, STARTTLS, LOGINDISABLED, AUTH-Mechanismen, Zertifikat | nmap.xml, sonst nmap-Text der Zeile |
| tls | Protokolle, schwache Cipher-Kategorien, Schwachstellen, Zertifikat, HSTS, Grade | testssl-JSON (Tar) + testssl-Rohtext (Zeile), httpx `tls` (nur Tar), nmap ssl-cert |
| http | Header je VHost, Security-Header, CSP, HSTS, Cookies, Technologien, ZAP-Alerts je Typ, Pfade, Spider-URLs, WordPress-Nutzer | header_check-Zeile je VHost, Tar-headers.json, httpx, zap_alerts.json, feroxbuster, ffuf, wpscan, tech_profile.redirect_data |
| dns | NS, MX, SPF, DMARC, DKIM, DNSSEC, CAA, MTA-STS, TLS-RPT, DANE, BIMI, Zonentransfer, Dangling CNAME | dns_records.json, dns_findings, dns_security.json, zone_transfer.txt |
| software | Produkt, Familie, Art, Version roh und normalisiert, Build, Distribution, Edition, EOL, Hinweise, Quellen | nmap, header_check, httpx `tech`, tech_profile (`cms_details.raw`, `technologies[]`), wpscan |
| passive | Shodan-Ports mit `verified` (nmap bestaetigt), OTX, SecurityTrails, URLhaus, GreyNoise | phase0a/*.json, Zeilen |
| coverage | eine Zeile je Werkzeuglauf mit Status `ok/empty/failed/blocked/skipped/unknown` und Grund | scan_results-Zeilen plus Sonderfaelle |
| threats | CVE mit NVD-Score, EPSS, KEV, ExploitDB (Durchreichung), testssl-CVEs | enrichment (Job, sonst Tar), testssl `cve` |
| unprocessed | unparsbare Dateien, Werkzeuge ohne Leser, Alerts ohne pluginId, Shodan-Hosts ausserhalb Inventar | Builder |
| decisions | KI-Entscheidungen nur als Protokoll: Host-Strategie, Phase-2-Konfiguration, Tech-Analyse (cms-Felder), Priorisierung, Site-Summary | host_strategy.json, ai_*-Zeilen, ai_prioritization.json, tech_profile, vhosts[].site_summary |

Konfidenz: Werkzeug 1.0 (nmap: `conf/10`), abgeleitet 0.8, passiv 0.5 (0.8 wenn nmap den
Port bestaetigt). `observed_at`: werkzeugeigen (httpx `timestamp`, nmap `@endtime`), sonst
`createdAt` der Zeile (Ende des Laufs), sonst Scanende aus `meta.json`.

### Bump-Regel (semver)

- Patch: neue optionale Felder mit Default, neue Warnungstexte.
- Minor: neue Entitaet oder neues Pflichtfeld mit Default fuer Altbestand.
- Major: Feld entfernt, umbenannt, Bedeutung geaendert, ID-Format geaendert.

Jeder Bump und jede Aenderung an Parsern oder Normalisierung erfordert den Neubau der
Golden-Facts (`python -m reporter.facts --golden`); der Drift-Guard in
`tests/test_facts_golden.py` vergleicht sonst rot. Dasselbe gilt nach einem Sync des
EOL-Feeds (`reporter/eol_data_generated.py`), dessen sha256 in `generator.inputs` steht.

## Versionsnormalisierung (versions.py)

1. MariaDB-Kompatibilitaetspraefix: `5.5.5-10.11.18-MariaDB-0+deb12u1` ist MariaDB 10.11.18.
2. `or later`, `or newer`, `>=`, `x`, Bereiche: Version `None`, Familie bleibt.
3. Exchange nur aus dem OWA-Build: 15.0 = 2013, 15.1 = 2016, 15.2 < 2562 = 2019,
   15.2 >= 2562 = SE. `X-FEServer` und `EXCHANGE-SE` sind Hinweise, nie Versionen.
   Buildquellen: httpx `tech` (`Outlook Web App:<build>`), `zap_spider_urls.json` und
   `redirect_chain` (`/owa/auth/<build>/`).
4. Banner: `nginx/1.24.0 (Ubuntu)`, `Apache/2.4.41 (Ubuntu)`, `OpenSSH 9.2p1 Debian 2+deb12u9`,
   `PHP/8.3.32`, `Microsoft-IIS/10.0`; nmap `extrainfo` liefert die Distribution.
   Namensfelder mit Zeilenumbruch oder `Name/Version` werden gesplittet.
5. `kind` aus einer kuratierten Tabelle (Webserver, Sprachen, CMS, WordPress-Themes und
   -Plugins, Datenbanken, Mail, SSH, FTP, OS); unbekannt ist `component`.
6. EOL nur bei sicherer Familie und Version, relativ zum Scanende: Feed-Termin vor dem Scan
   = `eol`, danach = `supported`, kein Eintrag = `unknown`. Distributionspakete (Ubuntu,
   Debian, RHEL ...) ergeben `unknown` mit dem Upstream-Termin als `upstream_eol_date`
   (Entscheidung DC 18.09.2026). `tech_profile.cms/cms_version` sind KI#2-Werte und werden
   nie Software-Fakt; Abweichungen zu `cms_details` stehen in `decisions`.

## Coverage (tool_coverage.py)

Status aus der Zeile; Legacy-Zeilen ohne `status`: parsebare Ausgabe gewinnt (testssl mit
Start und Done ist `ok`, auch bei exit 10/246; feroxbuster exit 1 mit JSONL ist `ok`), sonst
`exitCode -3` skipped, `-1` timeout, `-2`/`>0` failed. `timeout` wird `failed` mit
`raw_status = timeout`. Sonderfaelle: nmap ohne gescanntes Ziel (IPv6 ohne `-6`) ist `failed`
mit `target_invalid_ipv6`; Host oben ohne offene Ports ist `ok` mit `no_open_ports`; testssl
`Can't connect` ist `failed connect`; header_check `reachable: false` ist `empty`.

Blockade in fester Reihenfolge: (1) Inventar `blocked` + `blocked_reason`
(waf_block_detector), (2) Zeile `status = blocked`, (3) abgeleitet: nmap zeigt 80/443 offen,
alle VHosts unerreichbar, testssl ohne Verbindung, httpx leer. Web-Werkzeuge eines blockierten
Hosts werden `blocked` statt `empty`/`failed`. Ohne Zeilen: eine Zeile `scan_results unknown
no_tool_runs`; keine Erfindung aus Dateipraesenz.

Multi-Target: domainweite Zeilen (`hostIp: null`) tragen keine Domain. `dns` gehoert zum
Primaerziel, jede weitere Domain bekommt `coverage scope=domain status=unknown reason=
second_target_unlabeled` und eine Warnung.

## Datenfallen (Stand 18.09.2026, im Scanner nicht geaendert)

1. nmap laeuft ohne `-6`; IPv6-Ziele werden als `invalid` uebersprungen, die Zeile bleibt
   `ok` (`scan-worker/scanner/phase1.py:263-342`).
2. testssl im Perimeter-Paket mit `--severity MEDIUM` (`phase2.py:1212`): das Tar-JSON traegt
   nur MEDIUM+, "TLS 1.0 offered" (LOW) fehlt. Nur der Rohtext der Zeile hat die Protokolle;
   ohne Zeilen bleiben Protokolle `None` und `tls.json_filtered` wird gesetzt.
3. `headers.json` und `httpx.json` je Host werden je VHost ueberschrieben, nur der letzte
   VHost bleibt (`phase2.py:1248-1298`). Je-VHost-Wahrheit nur in den `header_check`-Zeilen.
4. `tech_enricher.py:151` liest `zap_spider.json`, Phase 2 schreibt `zap_spider_urls.json`:
   die OWA-Build-Extraktion des Scanners ist tot; dieses Paket liest die Datei selbst.
5. Der Freigabe-Job traegt weder `hostInventory` noch `correlatedFindings`; das Tar ist die
   einzige dauerhafte Quelle. `enrichment` steht nie in der DB.
6. Snapshot-Zeilen sind durch `output_normalizer` gekuerzt (httpx ohne `tls`/`timestamp`).
7. `meta.json` ist das Scanfenster; `orders.scan_finished_at` wird bei Freigabe ueberschrieben.
8. Mit `--open` schreibt nmap fuer Hosts ohne offene Ports kein `<host>`-Element; der Host
   wird aus `runstats` synthetisiert.

## Anbindung (nicht in S1, Entscheidung DC 18.09.2026)

Produktiv braucht der Builder neben dem Tar die `scan_results`-Zeilen mit `created_at` und
`raw_output` fuer eine Whitelist kleiner Werkzeuge (header_check, testssl, nmap, ai_*).
`reporter/worker.py::_load_tool_runs` liest heute weder `created_at` noch `raw_output`.
Vorschlag fuer S3/S6: SELECT erweitern, `build_facts(scan_data_dir, ..., tool_runs=rows)`
nach `parse_scan_data` aufrufen, Ergebnis als `<orderId>.facts.json` neben dem Tar nach MinIO
(`scan-rawdata`), geschaltet ueber `VECTISCAN_FACTS_EXPORT=1`, fail-open.

## Tests

`tests/test_facts_schema.py`, `test_facts_versions.py`, `test_facts_parsers.py`
(Fixtures unter `tests/fixtures/facts/`), `test_facts_golden.py` (alle Manifest-Orders aus
Tar plus Zeilen, Negativ-Fixtures auf Faktenebene, Coverage, TLS, Passiv, WAF, Determinismus
im Subprozess) und `test_facts_vs_catalog_sim.py` (Referenz `report-prototype/build/catalog_sim.py`).

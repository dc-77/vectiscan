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
| threats | CVE mit NVD-Score, EPSS, KEV, ExploitDB (Durchreichung), testssl-CVEs | enrichment (Job, sonst Tar), testssl `cve` **nur bei Urteil "verwundbar"** |
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

Seit S5b gibt es einen weiteren Grund, der nur aus dem Lader kommt:
`rohtext_nicht_geladen`. Er steht an einer Zeile, deren `raw_output` die Groessengrenze
ueberschritten hat und deshalb gar nicht erst geladen wurde. Der Status der Zeile bleibt
stehen, die Luecke ist benannt statt still.

Zwei Gruende kommen seit S2c nur aus der Zeile, nicht aus dem Tar: `nmap_no_runstats`
(Exit 0, aber keine Bilanz im XML) und `no_ipv6_route` (nmap lief mit `-6`, meldete
`hosts up=1` und schrieb trotzdem keinen Hostblock, und der Scanner hatte keine Route
zum Ziel). Beide setzt `phase1._nmap_status_check`. Aus dem Tar allein sind sie nicht
ableitbar, siehe Datenfalle 6.

Blockade in fester Reihenfolge: (1) Inventar `blocked` + `blocked_reason`
(waf_block_detector), (2) Zeile `status = blocked`, (3) abgeleitet: nmap zeigt 80/443 offen,
alle VHosts unerreichbar, testssl ohne Verbindung, httpx leer. Web-Werkzeuge eines blockierten
Hosts werden `blocked` statt `empty`/`failed`. Ohne Zeilen: eine Zeile `scan_results unknown
no_tool_runs`; keine Erfindung aus Dateipraesenz.

Multi-Target: domainweite Zeilen tragen seit S2b ihre Domain als `_domain` im `rawOutput`
und bekommen `scope=domain` (Issue #12). Zeilen ohne Etikett zaehlen wie bisher zum
Primaerziel (`scope=scan`). Eine weitere Domain ohne eigene Zeilen bekommt weiterhin
`coverage scope=domain status=unknown reason=second_target_unlabeled` und eine Warnung; so
bleiben die historischen Tars (Junkerwerk) lesbar.

## Tar-Aufbau

Ein Roh-Tar traegt genau ein Wurzelverzeichnis `<orderId>/`, das beim Lesen abgeschnitten
wird; alle `ref`-Angaben in den Fakten sind relativ dazu. Gelesen wird ueber `tarfile`, nie
entpackt. Werkzeuge ohne Leser landen in `unprocessed`.

```
meta.json                                 orderId, domain, domains[], package,
                                          startedAt, finishedAt, toolVersions[]
phase0/host_inventory.json                hosts[], vhosts[], dns_findings, blocked
phase0/dns_records.json                   SPF/DMARC/DKIM/MX/NS des Primaerziels
phase0/dns_records_<domain>.json          dito je weiterer Domain (seit S2b)
phase0/zone_transfer.txt                  AXFR-Versuche des Primaerziels
phase0/zone_transfer_<domain>.txt         dito je weiterer Domain (seit S2b)
phase0/host_strategy.json                 KI #1, nur Protokoll
phase0/certspotter.json                   Passivquelle
phase0/{crtsh,crtsh_raw,subfinder,dnsx_validation}.json, gobuster_dns.txt
                                          Discovery-Rohdaten, werden nicht gelesen
phase0a/dns_security.json                 DNSSEC/CAA/MTA-STS/TLS-RPT/DANE/BIMI (Primaerziel)
phase0a/dns_security_<domain>.json        dito je weiterer Domain (seit S2b)
phase0a/whois.json                        WHOIS des Primaerziels
phase0a/whois_<domain>.json               dito je weiterer Domain (seit S2b)
phase0a/{shodan_hosts,shodan_domain,abuseipdb,otx,securitytrails,urlhaus,
         greynoise,summary,virustotal}.json      Passivquellen, auftragsweit
phase3/correlated_findings.json           Liste
phase3/enrichment.json                    NVD/EPSS/KEV/ExploitDB, steht nie in der DB
phase3/ai_prioritization.json             KI, nur Protokoll
hosts/<ip>/phase1/nmap.xml                Hauptquelle fuer Dienste
hosts/<ip>/phase1/nmap.txt                Ausweichleser
hosts/<ip>/phase1/tech_profile.json       inkl. KI#2-Feldern (nie Software-Fakt)
hosts/<ip>/phase1/{webtech,wafw00f}.json
hosts/<ip>/phase2/headers.json            primaerer VHost (Legacy-Name, v2-Reporter)
hosts/<ip>/phase2/headers_<slug>.json     je VHost (seit S2b)
hosts/<ip>/phase2/httpx.json              primaerer VHost, JSONL (Legacy-Name)
hosts/<ip>/phase2/httpx_<slug>.json       je VHost, JSONL (seit S2b)
hosts/<ip>/phase2/testssl.json            seit S2b ohne Severity-Filter
hosts/<ip>/phase2/zap_alerts.json         Liste, im Snapshot eine Zusammenfassung
hosts/<ip>/phase2/zap_spider_urls.json    Liste von URLs
hosts/<ip>/phase2/{feroxbuster,ffuf_*,wpscan}.json
hosts/<ip>/phase*/screenshot_<vhost>.png  in den Golden-Fixtures entfernt
```

Zwei Regeln fuer die Namen mit Suffix: der Suffix ist nur ein Eindeutigkeitsmerkmal
(Wildcards und lange Namen werden gekuerzt und gehasht), die Zuordnung steht im Inhalt.
Bei den VHost-Dateien ist das `url` beziehungsweise `input`, bei den Domain-Dateien der
Schluessel `_domain` als erster Eintrag. Derselbe Schluessel steht in domainweiten
`scan_results`-Zeilen, weil die Tabelle keine Domainspalte hat, und auch in den Dateien
des Primaerziels; er ist Transportmittel und wird beim Lesen entfernt, bevor daraus ein
Fakt wird. Einzige Ausnahme: `zone_transfer_<domain>.txt` ist reiner Text und traegt
keinen Schluessel, dort gilt der Dateiname.

## Datenfallen

Behoben in Session S2b (gilt fuer Laeufe ab dem Deploy dieser Aenderung; die zehn
Golden-Tars sind aelter und zeigen alle fuenf Faelle weiterhin):

1. nmap lief ohne `-6`; IPv6-Ziele wurden als `invalid` uebersprungen, die Zeile blieb
   `ok`. Jetzt setzt `phase1.run_nmap` den Schalter und meldet `failed` mit Grund
   `target_invalid_ipv6`, wenn `runstats hosts total=0` sagt (Issue #8).
2. testssl lief im Perimeter-Paket mit `--severity MEDIUM`, das Tar-JSON trug nur MEDIUM+.
   Der Filter ist jetzt fuer alle Pakete leer; das JSON traegt auch die LOW- und OK-Zeilen,
   die der Katalog fuer Protokolle und Cipher braucht (Issue #9). Bei alten Tars bleiben die
   Protokolle `None` und `tls.json_filtered` wird gesetzt; der Rohtext der Zeile hilft.
3. `headers.json` und `httpx.json` wurden je VHost ueberschrieben, nur der letzte blieb.
   Jetzt schreibt jeder VHost `headers_<slug>.json` und `httpx_<slug>.json`; die alten
   Namen bleiben und tragen deterministisch den primaeren VHost (Issue #10). Rangfolge im
   Leser: VHost-Datei, dann `header_check`-Zeile, dann Legacy-Datei.
4. `tech_enricher` las `zap_spider.json`, Phase 2 schreibt `zap_spider_urls.json`. Der
   Dateiname ist korrigiert und der aus dem Build abgeleitete Wert schlaegt den KI#2-Wert
   (Issue #11). Dieses Paket liest die Datei ohnehin selbst.
5. Multi-Target: die zweite Domain bekam keine DNS- und Passivlaeufe und die domainweiten
   Zeilen trugen kein Domainfeld. Jetzt laufen DNS, Zonentransfer, dns_security und WHOIS
   je Domain, und jede domainweite Zeile traegt `_domain` (Issue #12). Kontingentpflichtige
   Quellen (Shodan, SecurityTrails, VirusTotal) bleiben beim Primaerziel.

Aufgefallen in Session S2c am Junkerwerk-Rescan 860d0d5a, dem ersten Fixture mit einem
AAAA-Host:

6. Ein nmap-Lauf mit `-6` ohne IPv6-Route im Scannernetz ist im Tar nicht von "Host lebt,
   kein Port offen" zu unterscheiden. Beide schreiben `hosts up=1 total=1`,
   `exit=success` und wegen `--open` keinen Hostblock; der Unterschied ist allein die
   Laufzeit (0,32 Sekunden gegen 23 Sekunden bei 217.243.248.27 in 0bf16342). Der Leser
   macht daraus in beiden Faellen `ok` mit `no_open_ports`, also eine Aussage ueber einen
   Host, der im zweiten Fall nie erreicht wurde. Auf eine Zeitschwelle wird bewusst keine
   Regel gebaut; stattdessen prueft `phase1._nmap_status_check` seit S2c die Route und
   meldet `no_ipv6_route`. Tars ohne diese Zeile, also alle vor dem Deploy der Aenderung,
   behalten die falsche Aussage. Issue #8 bleibt bis zur IPv6-Anbindung des Scannernetzes
   offen.

Aufgefallen in Session S5b, als die CVE-Fakten erstmals in den Bericht kamen:

7. **testssl nennt im Feld `cve` die Nummer, GEGEN die geprueft wurde**, auch wenn das
   Ergebnis "not vulnerable" lautet. Der Builder nahm bis S5b jede solche Zeile als Fakt.
   Im Fixture `860d0d5a` waren das 32 CVE-Fakten, darunter Heartbleed und POODLE, saemtlich
   mit `severity: OK`. Seit S2b laeuft testssl ohne Severity-Filter, der Fehler haette also
   jeden Produktionslauf getroffen, sobald die Fakten irgendwo sichtbar werden. Jetzt
   entscheidet das Urteil: Severity in `LOW/MEDIUM/HIGH/CRITICAL` und Befundtext ohne
   "not vulnerable" (`build._testssl_verwundbar`). `860d0d5a` faellt damit von 32 auf 3
   Threats, die uebrigen Auftraege bleiben unveraendert.
8. **`WARN` heisst "nicht geprueft"**, nicht "in Ordnung". `TlsVuln.status` hat dafuer den
   dritten Wert `not_tested` bekommen (Schema 1.0.2); vorher verschwand die Zeile ganz und
   war weder Fund noch Abdeckungsluecke. In den vierzehn Fixtures kommt der Fall nicht vor
   (`WARN` steht dort nur als `scanTime`), sichtbar wird er erst an Produktionsdaten.

Weiterhin gueltig:

6. Der Freigabe-Job traegt weder `hostInventory` noch `correlatedFindings`; das Tar ist die
   einzige dauerhafte Quelle. `enrichment` steht nie in der DB.
6. Snapshot-Zeilen sind durch `output_normalizer` gekuerzt (httpx ohne `tls`/`timestamp`).
7. `meta.json` ist das Scanfenster; `orders.scan_finished_at` wird bei Freigabe ueberschrieben.
8. Mit `--open` schreibt nmap fuer Hosts ohne offene Ports kein `<host>`-Element; der Host
   wird aus `runstats` synthetisiert.

## Anbindung (S5b, erledigt)

`reporter/worker.py::_load_tool_runs` liefert seit S5b `created_at` und `raw_output`; der
Produktionspfad baut damit dieselben Fakten wie der Golden-Pfad. Gemessen an allen dreizehn
Auftraegen fiel vorher die Zahl der `ok`-Abdeckungszeilen auf null, weil `classify_run` eine
`ok`-Zeile ohne Rohtext als leeres Ergebnis liest; dazu fehlten TLS-Protokolle und
header_check je VHost.

- **Keine Whitelist.** Alle Werkzeuge bekommen ihren Rohtext, sonst waere die Gleichheit mit
  dem Tar-Pfad nicht zu halten. Je Zeile gilt `RAW_OUTPUT_MAX_BYTES` (1 MiB,
  `VECTISCAN_TOOLRUN_RAW_MAX`); groessere Zeilen werden **weggelassen, nie abgeschnitten**
  (ein halbes JSON im Parser ist schlimmer als ein fehlendes). Messgrundlage: groesste Zeile
  ueber alle 42 Schnappschuesse 515 KB (`phase3_correlation`), groesster Auftrag 715 KB.
- **"Nicht geladen" ist ein eigenes Signal**, kein stilles `None`: die Zeile traegt
  `raw_output_omitted`, `ToolRun.raw_known` wird falsch, die Abdeckung bekommt den Grund
  `rohtext_nicht_geladen`. Eine Spalte, die in der Datenbank wirklich leer ist, bleibt ein
  leeres Ergebnis (18 solche `httpx`-Zeilen im Schnappschuss).
- **Gleichheitstest:** `tests/test_facts_production_parity.py` faehrt die Werte des
  Schnappschusses durch `_load_tool_runs` (Cursor-Doppel in der Spaltenreihenfolge des
  SELECT) und vergleicht mit den eingecheckten Golden-Facts. Abweichen darf nur die Herkunft
  der Zeilen (`generator.inputs[kind=tool_runs]`), nichts am Inhalt.
- **Export:** `VECTISCAN_FACTS_EXPORT=1` legt `facts.json` und `catalog.json` unter
  `scan-rawdata/<order_id>/` neben das Roh-Tar (`pipeline.export_facts_if_enabled`),
  fail-open und nur im v3-Zweig, weil nur dort Fakten entstehen.

## Tests

`tests/test_facts_schema.py`, `test_facts_versions.py`, `test_facts_parsers.py`
(Fixtures unter `tests/fixtures/facts/`), `test_facts_golden.py` (alle Manifest-Orders aus
Tar plus Zeilen, Negativ-Fixtures auf Faktenebene, Coverage, TLS, Passiv, WAF, Determinismus
im Subprozess) und `test_facts_vs_catalog_sim.py` (Referenz `report-prototype/build/catalog_sim.py`).

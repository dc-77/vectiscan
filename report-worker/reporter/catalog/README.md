# reporter.catalog: Pruefkatalog (Session S2)

Regeln als Daten. Jede Pruefung ist eine YAML-Datei unter `checks/`, die Engine wertet sie
deterministisch ueber `facts.json` (Ausgabe von `reporter.facts`, Session S1) aus und liefert je
Pruefung und Gruppe genau ein Ergebnis: `pass`, `fail`, `not_applicable` oder
`not_testable` mit Grund, dazu Betroffene, Nachweise (Faktreferenzen) und die Texte aus dem
Katalog. Keine KI, keine eigenen CVSS-Werte, kein Befund ohne Fakt aus einem Werkzeug.

Grundlage: `report-prototype/spec/05` (M2, M3), `spec/06` (Abschnitte 4, 5), `spec/07` (S2),
`report-prototype/build/catalog_sim.py` (Vorlage der Regeln), `reporter/severity_policy.py`
(Startwerte der Einstufung), `report-prototype/build/report_data.py` (Tonfall der Texte).

## Aufruf

```
cd report-worker
python -m reporter.catalog tests/golden/facts/<order>.json [-o ergebnis.json|-]
python -m reporter.catalog --golden <order_id>
python -m reporter.catalog --snapshot tests/golden/api-snapshot/<order>
```

Programmatisch:

```python
from reporter.catalog import evaluate, load_catalog
out = evaluate(facts_dict_or_Facts)          # CatalogOutput (pydantic), out.to_dict() fuer JSON
cat = load_catalog()                          # geladener, kompilierter Katalog (cat.by_id, cat.digest)
```

Ausgabe ist UTF-8 mit LF und deterministisch (sortierte Schluessel ueber
`reporter.facts.serialize.dumps`, Ergebnisse nach `check_id` und `group_key`).

## Dateien

| Datei | Inhalt |
|---|---|
| `version.py` | `CATALOG_VERSION` (Konstante, Bump-Regel unten) und `catalog_digest()` |
| `schema.py` | pydantic-Modelle: `CheckSpec` (YAML), `IgnoreList`, Ergebnisse (`CheckResult`, `Member`, `CatalogOutput`) |
| `expr.py` | Ausdruckssprache (ast-Whitelist, kein eval), Funktionen, statische Pfadpruefung |
| `tables.py` | Ports, Produkt- und Titelmuster, TLS-Listen, ZAP-Paare, `COVERAGE_REASONS`, `FAMILIES` |
| `scope.py` | Index ueber die Fakten, Gruppen, Bindungen, Schluesselschema |
| `render.py` | `affected_template` und Texte sicher rendern, Variablen je Scope |
| `engine.py` | laden, kompilieren, auswerten |
| `catchall.py` | Ignorierliste und die drei Auffangregeln |
| `checks/<id>.yaml` | eine Pruefung je Datei, `id` gleich Dateiname |
| `bundles/<id>.yaml` | ein Befund-Buendel je Datei (S3), `id` gleich Dateiname |
| `ignore.yaml` | ZAP-Informationsalerts und CDN-Passivports mit Begruendung |
| `decisions.md` | Entscheidungstabelle: verbindliche Einstufung je Pruefung, dazu die Buendeltabelle |

Tests: `tests/catalog/` (Fixtures je Pruefung, Engine, Schema und Tabelle, Textlint,
Golden-Tests ueber die Junkerwerk-Laeufe, alle Snapshot-Orders).

## Schema einer Pruefung

```yaml
id: db_exposed                    # ASCII, [a-z][a-z0-9_]*, gleich Dateiname
title: Datenbankdienst aus dem Internet erreichbar
family: db_exposed                # aus tables.FAMILIES (Vokabular catalog_sim / expected.json)
category: A                       # A Perimeter, B Patch/EOL, C E-Mail, D Web/Transport, E Konfiguration
scale: exposure                   # exposure | hygiene
level: kritisch                   # exposure: kritisch|erhoeht  hygiene: hoch|mittel|niedrig
group_by: host                    # global | domain | host | fqdn (Konsolidierung, eine Zeile je Gruppe)
scope: service                    # worueber iteriert wird, siehe Scopes
applicable_when: null             # Gruppenkontext; false -> not_applicable
item_when: null                   # Itemfilter; Items mit false werden gar nicht betrachtet
when: service.port in DB_PORTS    # Itemkontext; true -> fail (bei kind note: Hinweis)
active_proof_when: null           # Itemkontext; true -> aktiver Nachweis (rot, unverzueglich)
positive_when: absent             # absent | never | <Ausdruck im Itemkontext>
not_testable_when: []             # [{when, reason_code, context: group|item}]
undetermined: not_testable        # not_testable | pass_silent | not_applicable
requires:
  tools: [nmap]                   # Werkzeuge, deren Abdeckung bei Gruppen ohne Items entscheidet
kind: check                       # check | note (note: nie fail, liefert Inventarhinweise in notes)
bundle: null                      # Buendelungshinweis fuer S3, z. B. mail_transport_enforcement
affected_template: "{host_ip}:{port} ({product})"   # Variablen je Scope, siehe unten
evidence: [service]               # Bindungen, deren evidence[] uebernommen wird (Rueckfall)
evidence_detail: null             # Bereich fuer den befundspezifischen Nachweis; leer = scope
references: [CWE-284]
frameworks: {bsi: [], nis2: [], iso27001: [], tr03116: []}
policy: {source: SP-DB-001, start_level: HIGH, deviation: "warum abgewichen wird"}
texts:
  observation: "..."              # {affected}, {count}, {group}, {fqdn_names}, {domain}, {host_ip}, {notes}
  meaning: "..."
  recommendation: [{stage: unverzueglich, text: "..."}]   # unverzueglich|in_kuerze|mittelfristig|strategisch
  verify: "..."
  positive: {title: "...", text: "..."}   # optional; ohne positive bleibt pass stumm
```

Pflichtfelder laut Auftrag: id, title, family, scale, level, group_by, when, positive_when,
not_testable_when, affected_template, evidence, references, frameworks, texts. Erweiterungen
dieser Umsetzung: category, scope, applicable_when, item_when, undetermined, requires, kind,
bundle, policy, dazu seit S6 `active_proof_when` und `evidence_detail`. Alle Modelle sind
`extra="forbid"`: ein unbekanntes Feld ist ein Ladefehler.

### Aktiver Nachweis (S6)

`active_proof_when` wird je Item wie `when` ausgewertet. Trifft es fuer ein
fehlgeschlagenes Mitglied, traegt das Ergebnis `active_proof` und der Befund wird rot
mit Dringlichkeit "Unverzueglich", unabhaengig von seiner Einstufung
(`reporter/v3/levels.py`). Gesetzt ist es in genau zwei Pruefungen, beide mit einem
eigenen Nachweis des Werkzeugs: `web_vulnerability_active` (ZAP mit Risiko High **und**
Konfidenz High) und `tls_known_vulnerability` (testssl-Urteil aus der harten Liste).
Entscheidung DC, spec/08 Punkt 1, Variante (a).

### Nachweis je Befund (S6)

Der Nachweis eines Befunds ist das, was die Regel getroffen hat, nicht die
Zusammenfassung der Werkzeugzeile. `reporter/catalog/evidence.py` baut je Bereich eine
Zeile aus dem getroffenen Teilobjekt: welche Sicherheits-Header fehlen, welche Adresse
die ZAP-Meldung nennt, welche Daten das Zertifikat traegt. Sie steht im Bericht vorn;
die Evidenz des Fakts kommt nur bei Bereichen dazu, deren Auszug ein woertlicher
Werkzeugtext ist (`service`, `software`, `tls`, `passive`, `threat`). `evidence_detail`
ueberschreibt den Bereich, wenn der `scope` allein nicht trifft: `wordpress_user_enumeration`
laeuft auf `scope: http`, will im Nachweis aber die REST-Adresse und die Benutzernamen,
also `evidence_detail: http.wordpress`.

### Scopes und Bindungen

Der Gruppenkontext (fuer `applicable_when` und `not_testable_when` mit `context: group`)
enthaelt immer: `scan`, `hosts`, `group_key`, `fqdn_names`, `host` (HostFact oder None),
`fqdn` (FqdnFact oder None, nur fqdn-Gruppen), `http` (HttpFact oder None, nur fqdn-Gruppen),
`dns` (DnsFact oder None), `target`, die Listen `services`, `http_list`, `tls_list`,
`softwares`, `passives`, `threats`, `fqdns`, `items`, die Menge `ports` und die Funktionen
`coverage_ok(tool)`, `coverage_status(tool)`, `coverage_reason(tool)`.

Der Itemkontext (fuer `item_when`, `when`, `positive_when`, `not_testable_when` mit
`context: item`) enthaelt zusaetzlich das Item unter seinem Namen und bei verschachtelten
Scopes den Parent:

| scope | Item-Bindung | Parent | erlaubte group_by |
|---|---|---|---|
| `service` | `service` (ServiceFact, nur `state == open`) | | global, host |
| `host` | `host` (HostFact) | | global, host |
| `fqdn` | `fqdn` (FqdnFact, ohne Aliase) | | global, host, fqdn |
| `http` | `http` (HttpFact) | | global, host, fqdn |
| `http.alerts` | `alert` (WebAlert) | `http` | global, host, fqdn |
| `http.paths` | `path` (WebPath) | `http` | global, host, fqdn |
| `http.cookies` | `cookie` (Cookie) | `http` | global, host, fqdn |
| `tls` | `tls` (TlsFact) | | global, host, fqdn |
| `tls.vulns` | `vuln` (TlsVuln) | `tls` | global, host, fqdn |
| `dns` | `dns` (DnsFact) | | global, domain |
| `dns.dangling_cnames` | `dangling` (DanglingCname) | `dns` | global, domain |
| `software` | `software` (SoftwareFact) | | global, host, fqdn |
| `passive` | `passive` (PassiveFact) | | global, host |
| `threat` | `threat` (ThreatFact), `software` (verknuepft oder None) | | global, host |
| `target` | `target` (TargetFact) | | global, domain |
| `scan` | `scan` | | global |

Felder der Fakten: `reporter/facts/schema.py`. Wichtige dreiwertige Felder (`None` =
unbekannt): `service.tls_required`, `service.starttls`, `service.login_disabled`,
`tls.protocols[...]`, `tls.cert.mismatch/chain_ok/expired/self_signed`, `tls.fallback_scsv`,
`http.reachable`, `fqdn.waf.detected`, `passive.verified`, `dns.dnssec.signed`,
`dns.caa.present`, `dns.dane.smtp`.

### Variablen fuer `affected_template`

Fehlende Werte heissen `unbekannt`, Listen werden mit Komma verbunden. Ein Template mit einer
Variablen, die der Scope nicht kennt, ist ein Ladefehler; `?` ist im Template verboten.

| scope | Variablen |
|---|---|
| alle | `host_ip`, `host_label` (IP plus Hostnamen), `fqdn`, `port`, `domain`, `fqdn_names` |
| `service` | `proto`, `service`, `product` (aus Software-Join, bei DB-Ports nie "MySQL 5.5"), `product_or_service`, `version`, `family`, `db_name`, `admin_name`, `mail_name`, `legacy_name`, `tls_note` |
| `host` | `ports_list`, `reverse`, `abuseipdb_score`, `otx_pulse_count` |
| `fqdn` | `title`, `http_status`, `final_url`, `waf_name`, `year_hint_names` (Name und Aliase mit Produktjahr) |
| `http` | `url`, `score`, `missing_headers`, `missing_headers_basic` (XFO, XCTO, Referrer, Permissions), `disclosure_headers`, `server_header`, `powered_by`, `hsts_max_age`, `csp_flags`, `duplicate_headers`, `x_feserver`, `wp_users`, `wp_version_status` |
| `http.alerts` | `plugin_id`, `name`, `risk`, `url_path`, `count` |
| `http.paths` | `url_path`, `status` |
| `http.cookies` | `name`, `flags_missing` |
| `tls` | `target` (fqdn:port), `legacy_protocols`, `ciphers_weak`, `vulns`, `cert_cn`, `days_left`, `not_after`, `issuer`, `grade`, `hsts_max_age` |
| `tls.vulns` | `target`, `name`, `status` |
| `dns` | `spf_raw`, `spf_qualifier`, `dmarc_p`, `dmarc_raw`, `mx`, `mx_count`, `ns`, `dkim_selectors` |
| `dns.dangling_cnames` | `fqdn`, `cname_target`, `takeover_risk` |
| `software` | `product`, `family`, `kind`, `version`, `build`, `edition`, `eol_date`, `eol_status`, `vulnerabilities_count` |
| `passive` | `product`, `version`, `source`, `seen_at` |
| `threat` | `cve_id`, `cvss`, `epss`, `kev`, `product`, `version` |
| `target` | `expires_at`, `registrar`, `days_left` |

`texts.observation`, `texts.positive.*`, `title`, `meaning`, `verify` und die Empfehlungen
duerfen nur `{affected}`, `{count}`, `{group}`, `{fqdn_names}`, `{domain}`, `{host_ip}`,
`{notes}` verwenden. `observation` wird nur bei `fail` gerendert, `positive` nur bei
`positive: true`.

## Ausdruckssprache

Kein `eval`. `ast.parse` plus Whitelist: `and`, `or`, `not`, Vergleiche `== != < <= > >= in
not in is is not`, Namen aus dem Kontext, Attributzugriff, Subscript mit konstantem
Schluessel (`tls.protocols["TLS1.0"]`), Literale, Listen, Aufrufe registrierter Funktionen.
Tabellen aus `tables.py` sind unter ihrem GROSSGESCHRIEBENEN Namen sichtbar (`DB_PORTS`,
`ADMIN_PORTS`, `ADMIN_PRODUCTS`, `ADMIN_TITLES`, `LOGIN_TITLES`, `DEFAULT_TITLES`,
`DEV_HOST_PREFIX`, `YEAR_HINT`, `SENSITIVE_PATHS`, `MAIL_PORTS`, `LEGACY_PORTS`, `WEB_PORTS`,
`TLS_LEGACY`, `TLS_WEAK_CIPHER_KEYS`, `TLS_HARD_VULNS`, `TLS_SOFT_VULNS`,
`TLS_COMPRESSION_VULNS`, `HSTS_MIN_MAX_AGE`, `CERT_EXPIRING_DAYS`, `DOMAIN_EXPIRING_DAYS`,
`ABUSEIPDB_FAIL_SCORE`, `ZAP_INFO_DISCLOSURE`, `ZAP_CSRF`, `ZAP_JS_LIBRARY`, `ZAP_ACTIVE`,
`ZAP_DIRECTORY_LISTING`, `ZAP_SESSION_URL`, `ZAP_CORS`, `ZAP_SRI`).

Funktionen: `len(x)`, `count(x)`, `any_in(seq, values)`, `matches(text, MUSTER)`, `any_match(seq, MUSTER)`,
`startswith(text, prefix)`, `contains(text, teil)`, `lower(text)`, `ports(services)`,
`has_port(services, n)`, `days_until(datum, scan.finished_at)`, `has_version(text)`,
`is_cdn(host, services)`, `any_attr(seq, "feld", [werte])`, `all_attr(seq, "feld", [werte])`,
`get(obj, "schluessel")`, `first(seq)`, `zap_match(alert, ZAP_LISTE)`; im Gruppenkontext
`coverage_ok(tool)`, `coverage_status(tool)`, `coverage_reason(tool)`.

Dreiwertigkeit: jeder Vergleich mit `None` ergibt `False` (auch `!=` und `not in`).
`is None`, `is True`, `is False` sind exakt. Attributzugriff auf `None` ergibt `None`.
Felder vom Typ `Optional[bool]` duerfen nur mit `is True`, `is False`, `is not True` oder
`is None` verglichen werden, nie als nackter Operand oder unter `not` (Ladefehler). Beispiel:
`service.starttls is False` bedeutet "Faehigkeiten gesehen, kein STARTTLS";
`service.starttls is None` bedeutet "unbekannt" und ist ein `not_testable`, kein Befund.

## Statuslogik je Gruppe

1. Domain-Gruppe ohne DNS-Fakten (zweite Domain im Multi-Target) -> `not_testable` mit Grund
   aus der Abdeckung (`second_target_unlabeled`).
2. `applicable_when` false -> `not_applicable` (`precondition_not_met`).
3. `not_testable_when` mit `context: group` trifft -> `not_testable(reason_code)`. Ein
   `reason_code` der Form `coverage:<tool>` uebernimmt Status und Grund aus der Abdeckung des
   Werkzeugs (`ok` = Regel greift nicht, `not_in_package` = `not_applicable`).
4. Je Item (nach `item_when`): `when` true -> `fail` (bei `kind: note` ein Hinweis); sonst
   Item-Regeln aus `not_testable_when`; sonst `positive_when` als Ausdruck -> pass oder
   `undetermined`; bei `absent`/`never` zaehlt ein gesehenes Item als unauffaellig (wird nicht
   als Member gelistet, nur in `items_seen` gezaehlt).
5. Gruppe: `fail` > `not_testable` (ein nicht pruefbares Item macht die Gruppe nicht pruefbar,
   die Member zeigen das Detail) > `pass` > `not_applicable`.
6. Ohne Items entscheidet die Abdeckung der `requires.tools` ueber `COVERAGE_REASONS`
   (`no_ssl`, `cms_not_wordpress`, `no_web`, `not_in_package` -> `not_applicable`;
   `wordlist_missing`, `does_not_exist`, `target_invalid_ipv6`, `nmap_no_runstats`,
   `no_ipv6_route`, `web_unreachable_after_portscan`
   ... -> `not_testable`). Ist alles `ok`: `absent` -> pass (positiv, wenn `texts.positive`),
   `never` -> stummes pass, Ausdruck -> `undetermined`.
7. `positive: true` nur bei `pass` mit `texts.positive` und (`absent` oder mindestens einem
   Item, das den Positivausdruck erfuellt). `undetermined: pass_silent` laesst unbestimmte
   Items als stummes pass durch (z. B. Software mit unbekannter Version).
8. Ist der Host als blockiert bekannt (`host.blocked.detected`), ersetzt der Blockade-Grund
   die generischen Gruende `unreachable` und `insufficient_facts`.

## Ergebnisformat

`CatalogOutput`: `catalog_version`, `catalog_digest`, `facts_schema_version`, `order_id`,
`package`, `domain(s)`, `generator`, `checks[]` (Stammdaten je Pruefung: Titel, Texte,
Referenzen, Rahmenwerke, Einstufung, einmal), `results[]`, `rollups[]` (Zaehlung je Pruefung),
`unprocessed[]`, `ignored[]`, `facts_unprocessed[]`, `summary`.

`CheckResult`: `check_id`, `family`, `bundle`, `kind`, `title`, `category`, `scale`, `level`,
`group_by`, `group_key`, `group_label`, `status`, `positive`, `verified` (False bei rein
passiven Treffern), `source_mode` (active, passive, mixed, none), `affected[]` (Labels),
`affected_fact_ids[]`, `members[]` (`key`, `host_ip`, `fqdn`, `port`, `label`, `status`,
`reason_code`, `reason`, `fact_ids`, `source_mode`, `verified`, `via_cdn`, `alias_of`),
`items_seen`, `evidence[]` (`fact_id`, `tool`, `ref`, `excerpt`), `reason_code`, `reason`,
`notes[]`, `vars`, `texts.observation` (gerendert), `texts.positive` (gerendert).

Schluesselschema (stabil ueber Laeufe, Grundlage des Drift-Tests): service `ip:port`, host
`ip`, fqdn und http `name@ip`, tls `name:port@ip`, alert `name@ip#plugin_id|name`, path
`name@ip#pfad`, cookie `name@ip#name`, vuln `name:port@ip#name`, dns `domain`, dangling
`domain#fqdn`, software `sw-id`, passive `quelle:ip:port`, threat `cve@ip:port`, target
`domain`. IPv6-Adressen stehen in eckigen Klammern. Alias-FQDNs (Eintrag in `aliases` eines
anderen FQDN desselben Hosts) bilden keine eigene Gruppe.

## Ignorierliste und Auffangregeln

Ein Fakt gilt als verarbeitet, wenn das `when` einer Pruefung getroffen hat. Der Rest:
`ignore.yaml` (ZAP-Alerts als Paar `plugin_id` plus `name`-Muster mit Begruendung;
`passive_port` mit `only_cdn`) oder `unprocessed[]` mit den Arten `service_unknown_port`
(Port nicht in `KNOWN_PORTS`), `zap_alert_unmapped`, `passive_port_unverified`
(`verified False` = vom Portscan nicht bestaetigt, `verified None` = Host nicht aktiv
gescannt). Zielwert aus spec/06: unter fuenf unverarbeitete Beobachtungen je Auftrag.

## Befund-Buendel (S3)

Der Kundenreport kennt Sachverhalte, nicht Pruefungen: fehlendes CSP, fehlendes HSTS und
unvollstaendige Sicherheits-Header auf demselben Host sind ein Befund, nicht drei. Ein
Buendel unter `bundles/<id>.yaml` fasst dafuer mehrere Pruefungen zusammen. Die Auswertung
selbst aendert sich dadurch nicht: der Katalog liefert weiter ein Ergebnis je Pruefung und
Gruppe, das Buendel ist reine Zuordnung fuer die Reportdaten (`reporter/v3`).

```yaml
id: tls_hardening
title: Transportverschluesselung auf {group} mit veralteten Verfahren
category: D                 # Kategorie des Positivbefunds; der Befund erbt sie vom Ausloeser
merge_by: host              # global | domain | host | fqdn
members: [tls_legacy_protocols, tls_no_13, ...]
target: findings            # findings | appendix
references: [CWE-326]
frameworks: {bsi: [], nis2: [], iso27001: [], tr03116: []}
texts: {observation, meaning, recommendation[], verify, positive}
```

Regeln:

- Mitgliedschaft steht doppelt, in `members` und im Feld `bundle` der Pruefung. Der
  Ladevorgang erzwingt, dass beide Seiten uebereinstimmen; eine Pruefung gehoert zu
  hoechstens einem Buendel. Mitglieder, deren Pruefung im geladenen Verzeichnis fehlt,
  werden entfernt, ein Buendel ohne Mitglied faellt weg (verkleinerte Testkataloge).
- `merge_by` bestimmt, wie die Gruppen der Mitglieder zu einem Befund zusammenlaufen. Bei
  `host` liefert auch eine FQDN-Gruppe ihren Host, weil die IP im Gruppenschluessel steht.
- Skala, Einstufung und Kategorie des Befunds kommen vom hoechsten fehlgeschlagenen
  Mitglied; die im Buendel eingetragene `category` gilt fuer den Positivbefund.
- `target: appendix` haelt das Buendel aus der Befundliste heraus und schreibt es in den
  Anhang "Werkzeugbefunde ohne Bewertung" (spec/06 Abschnitt 4, Stufe 2).
- `positive_conflicts` (S6a, Issue #30) nennt Befunde anderer Pruefungen, bei denen ein Host
  aus dem Positivbefund des Buendels herausfaellt: `checks` (optional mit `ports`, dann
  zaehlt nur ein fehlgeschlagenes Mitglied auf diesen Ports) oder `noted_by` (eine
  Notiz-Pruefung nennt `ip:port`, und irgendeine Pruefung ist auf genau diesem Dienst
  fehlgeschlagen). Bleibt kein Host uebrig, entfaellt der Positivbefund; bei mehr als drei
  Hosts nennt der Text die herausgenommenen ("den geprueften Hosts ausser ...").
- Die Buendeltabelle in `decisions.md` ist verbindlich und wird per Test erzwungen; die
  Texte laufen durch denselben Textlint wie die Pruefungstexte.

## Versionierung

`CATALOG_VERSION` in `version.py`, Format `JJJJ-MM-TT.n` wie `POLICY_VERSION`. Bump-Regel:
jede inhaltliche Aenderung an `checks/`, `bundles/`, `ignore.yaml` oder `tables.py` zieht die Version hoch
und bekommt eine Zeile in der Bump-Historie im Modul-Docstring. Zusaetzlich steht in jeder
Ausgabe `catalog_digest` (sha256 ueber dieselben Dateien, CRLF-normalisiert, ohne BOM), damit
eine Aenderung ohne Bump im Audit auffaellt. Textkorrekturen ohne Aenderung von Bedingung oder
Einstufung sind ein Patch (`.n`), neue oder veraenderte Pruefungen ein neues Datum.

Bump-Historie mit Begruendung im Modul-Docstring von `version.py`; Kurzfassung:
`2026-09-19.1` Erstversion (S2), `2026-09-19.2` echte Umlaute in allen Kundentexten und
Befund-Buendel (S3), `2026-09-20.1` Rueckbau `zap_no_alerts` (S2b), `2026-09-22.1`
Pflichtkorrekturen aus spec/08 (S6), `2026-09-23.1` `positive_conflicts` und der
geschaerfte Positivbefund von `remote_admin_closed` (S6a, Issue #30), `2026-09-23.2`
`dkim_missing` ohne gefundenen Selektor nicht pruefbar (S6a, #15 Teil 2).

## Texte

- Deutsch mit echten Umlauten, Sie-Form, keine Gedankenstriche (weder `–` noch `—`), keine
  Fragezeichen als Platzhalter, keine `{...}`-Reste. Bezeichner bleiben ASCII (Pruef-IDs,
  YAML-Schluessel, Stufen wie `unverzueglich`); die Umschrift `ae/oe/ue` gehoert nicht in
  einen Kundentext. Die Wortliste dazu steht in `tests/textlint.py` (S3).
- Generisch: keine Kunden-, Hoster- oder Herstellernamen, die nicht aus Template-Variablen
  kommen. `report_data.py` ist nur die Tonfall-Referenz, nicht die Textquelle.
- Zahlen nur aus Variablen oder aus der Whitelist des Textlints (Protokollversionen wie
  TLS 1.2, Standardports aus `tables.py`, Fristen wie 30 Tage, RFC-Nummern).
- Keine Zusagen (PTES, KI-gestuetzt, Vollstaendigkeit), keine CVSS-Werte, keine Aufwaende.
- `observation`: was beobachtet wurde, mit `{affected}`; `meaning`: warum es zaehlt, ohne
  Uebertreibung; `recommendation`: Stufen unverzueglich (Tage), in_kuerze (Wochen),
  mittelfristig (naechster Wartungszyklus), strategisch (Quartal); `verify`: wie der Kunde
  die Behebung selbst prueft; `positive`: Titel und Satz fuer die bestandene Pruefung.
- Kategorien A bis E entsprechen der Ampel des Prototyps (spec/03).

## Fixtures und Tests

Je Pruefung liegen unter `tests/catalog/fixtures/` die Dateien `<id>_pass.json` und
`<id>_fail.json` (Pflicht, sofern `when` gesetzt ist und `kind: check`; bei `kind: note`
zeigt das `_pass`-Fixture den Hinweis ueber `notes`), `<id>_nt.json` (Pflicht, wenn
`not_testable_when` gesetzt ist) und optional `<id>_na.json`. Format:

```json
{
 "facts": {
  "services": [{"host_ip": "10.0.0.1", "port": 3306, "service": "mysql", "product": "MySQL"}]
 },
 "coverage_default": "ok",
 "expect": {"status": "fail", "group_key": "10.0.0.1", "affected": ["10.0.0.1:3306 (MariaDB/MySQL)"], "positive": false}
}
```

`make_facts` (tests/catalog/conftest.py) fuellt `scan`, `generator`, `id`, `source`, `mode`,
`confidence`, legt fehlende Hosts, FQDNs und Targets an und erzeugt bei
`coverage_default: ok` Abdeckungszeilen fuer alle Werkzeuge. `expect` kennt `status`,
`group_key`, `affected`, `affected_contains`, `positive`, `reason_code`, `notes`, `verified`,
`source_mode`, `members` (Schluessel -> Status), `results_count`. Beispiel-IPs aus
`10.0.0.0/8`, Beispiel-Domain `example.test`.

Test je Pruefung (`tests/catalog/test_<id>.py`, drei Zeilen, wird per
`python scripts/catalog_stubs.py` aus `decisions.md` erzeugt):

```python
import pytest
from tests.catalog.conftest import fixture_kinds, run_fixture
CHECK_ID = "db_exposed"

@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_db_exposed(kind):
    run_fixture(CHECK_ID, kind)
```

`tests/catalog/test_fixtures_all.py` entdeckt alle Fixtures automatisch und prueft, dass jede
Pruefung ihre Pflicht-Fixtures hat. Katalogtest: `cd report-worker && pytest tests/catalog`.

## Ablauf fuer den Subagent check-author

1. Zeile der Pruefung in `decisions.md` lesen. `family`, `category`, `scale`, `level`,
   `group_by`, `scope`, `positive_when` (Art), `undetermined`, `bundle`, `frameworks` und die
   Bedingung sind verbindlich. Einstufungen werden nicht geaendert.
2. Eine bestehende Pruefung desselben Scopes als Muster lesen (`db_exposed` service/host,
   `http_no_tls` host, `tls_legacy_protocols` tls/fqdn, `dmarc_missing` dns/domain,
   `security_headers_incomplete` http/fqdn, `csrf_token_missing` http.alerts,
   `admin_service_exposed_passive` passive, `software_eol` software mit pass_silent).
3. `checks/<id>.yaml` schreiben: alle Felder wie in der Vorlage, deutsche Texte nach den Regeln
   oben, `policy.source` und `policy.deviation` aus der Tabelle.
4. Fixtures schreiben: `_pass` und `_fail` (bei `when`), `_nt` (bei `not_testable_when`),
   Werte so waehlen, dass genau die Bedingung greift; `expect.affected` ausschreiben.
5. Test-Stub pruefen (existiert nach `python scripts/catalog_stubs.py`), dann
   `cd report-worker && pytest tests/catalog -k "<id>"` (mehrere: `-k "id1 or id2"`), zusaetzlich
   `pytest tests/catalog/test_text_lint.py tests/catalog/test_expr.py -q`. Der vollstaendige Lauf
   (inklusive Tabellenabgleich und Golden-Tests) ist Sache der Hauptsession. Erst wenn gruen:
   Dateiliste zurueckgeben.
6. Nicht tun: Einstufungen aendern, andere Pruefungen anfassen, Engine-Code, `tables.py`,
   `ignore.yaml`, `decisions.md` oder `version.py` aendern, Fakten erfinden. Bei Unklarheit in
   der Tabelle abbrechen und die Frage zurueckgeben.

## Datenfallen (aus S1 uebernommen, im Katalog beruecksichtigt)

- Lauf 2 von Junkerwerk hat null ZAP-Alerts. Seit S2b (Issue #13) steht das in der
  Abdeckung: `zap` mit Status `ok` und null Alerts wird als `empty` mit Grund
  `zap_no_alerts` gefuehrt. Die ZAP-Pruefungen sind darueber nicht pruefbar, nicht
  bestanden; die frueheren Gruppenregeln `len(http.alerts) == 0` sind zurueckgebaut.
- `http.reachable False` mit vorhandenen ZAP-Alerts (openotp.junkerwerk.hu): Header-Pruefungen
  sind nicht pruefbar, ZAP-Pruefungen laufen.
- `tls.protocols` ist bei httpx-Fakten und bei gefilterter testssl-Ausgabe `None`.
- Software-Fakten liegen je Host und je VHost getrennt vor; Labels ohne VHost fallen im
  Ergebnis zusammen.
- `passive.verified` ist `None`, wenn der Host keinen nmap-Lauf hatte.
- Cloudflare-Edge-Hosts tragen Dienste auf 8080/8443 und viele Passivports; `is_cdn` und die
  Ignorierliste fangen das ab.
- Multi-Target: nur die erste Domain hat DNS-Fakten; weitere Domains sind `not_testable`.

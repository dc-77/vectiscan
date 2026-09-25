# Golden-Fixtures (Session S0c)

Unveraenderliche Wahrheitsbasis fuer den Report-Umbau nach
`report-prototype/spec/05-architektur-befund-und-plan.md` bis `spec/07`.
S1 baut daraus `facts.json`, S2 prueft den Katalog dagegen, S3 vergleicht sein
Datenmodell mit der Soll-Liste.

## Inhalt

| Pfad | Inhalt |
|---|---|
| `manifest.json` | einzige Wahrheit ueber das Set: Auftrag, Domains, Daten, Rolle, Tar-Status mit sha256 |
| `orders.txt` | Auftragsliste fuer den Ops-Job `ops-export-golden-tars` |
| `tars/<order>.tar.gz` | Roh-Tar aus MinIO `scan-rawdata`, ohne Screenshots, deterministisch gepackt |
| `api-snapshot/orders.json` | API-Listenantwort; einzige Quelle fuer `createdAt` und die Multi-Target-Liste |
| `api-snapshot/<order>/` | `order.json`, `findings.json`, `results.json` je Auftrag |
| `expected/junkerwerk.json` | 15 Befunde und 8 Positivbefunde des Prototyps als Soll-Liste |
| `expected/<slug>.json` | abgeleitete Soll-Listen der uebrigen Fixtures, erzeugt mit `scripts/golden/build-expected-order.py`; Regressionssperre, keine unabhaengige Gegenprobe |
| `negative.json` | belegbar falsche Befunde aus ausgelieferten Reports; kein Check darf sie erzeugen |
| `facts/<order>.json` | Ausgabe von `reporter.facts` je Auftrag mit Tar (S1), Neubau mit `python -m reporter.facts --golden` |
| `report-data/<order>.json` | Datenmodell des Reports aus `reporter.v3` (S3), ohne Auftragsdaten und ohne KI, fester Stichtag; Neubau mit `python -m reporter.v3 --golden-all` |

## Rollen im Manifest

- `golden` Referenzlauf fuer den Vergleich mit der Soll-Liste
- `drift` Wiederholungslauf; gleiche Fakten muessen dieselbe Ergebnisliste ergeben
- `negative` traegt Eintraege aus `negative.json`
- `coverage` Lauf mit Werkzeugluecken ueber die Hosts; sie muessen im Abdeckungskapitel stehen
  (`f77ccff2`, castenow.de: neun Hosts, davon nur einer mit ffuf_param und wpscan, sechs mit zap,
  sieben mit feroxbuster)

Zur Laufzeit dieses Auftrags: die API zeigt 19.07. bis 22.07.2026, `meta.json` im Tar aber
19.07. 23:40 bis 20.07. 00:26. Die drei Tage liegen zwischen Scanende und Auftragsabschluss,
also in Bericht und Freigabe, nicht im Scan. Fuer Laufzeitfragen gilt `meta.json`.

## Anonymisierung

- Dateinamen tragen nur Auftrags-UUIDs, also keine Kundennamen.
- Domains bleiben in den Daten stehen. Ohne sie waeren die Fakten wertlos.
- Screenshots sind aus allen Tars entfernt, nicht erst ab einer Groessengrenze.
  Grundlage ist spec/07 Abschnitt 1: Junkerwerk-Rohdaten duerfen ins Repo,
  Screenshots nicht. `parser.parse_scan_data` kommt ohne sie zurecht.
- In `api-snapshot/orders.json` ist die E-Mail des bestellenden Benutzers
  ersetzt. Adressen aus dem DNS (DMARC rua, TLS-RPT, postmaster) bleiben, weil
  die Mail-Pruefungen genau darauf laufen.

## Regenerieren

```
# 1 API-Snapshot. report-prototype/input/ ist gitignored, der Ordner liegt nur
#   lokal; neu ziehen mit report-prototype/scripts/fetch-all-orders.sh
python3 scripts/golden/build-api-snapshot.py --source <pfad>/report-prototype/input/_all

# 2 Soll-Liste Junkerwerk (liest report-prototype/build/report_data.py im Repo)
python3 scripts/golden/build-expected-junkerwerk.py

# 3 Negativ-Fixtures (arbeitet auf dem eingecheckten Snapshot)
python3 scripts/golden/build-negative-fixtures.py

# 3b Einzelnen Auftrag aufnehmen (statt Schritt 1, wenn nur einer dazukommt):
#   python3 scripts/golden/add-order-to-snapshot.py <uuid> --creds <pfad>
#   Danach orders.txt, die GOLDEN_ORDER-Matrix in .gitlab-ci.yml und ROLES in
#   scripts/golden/build-manifest.py ergaenzen, sonst faellt test_golden_fixtures.
#   Das Skript kuerzt einen etwaigen Kundenkontext auf den Firmennamen und
#   entfernt Admin-Felder (Auflage S5b).

# 4 Roh-Tars: API-Pipeline auf dem Branch ausloesen, die Matrix-Jobs
#   ops-export-golden-tars der neuen Auftraege starten (einer je Auftrag),
#   die Artefakte golden-tars/ nach tars/ entpacken.
#   Ein Auftrag je Job, weil der Artefakt-Upload dieser GitLab-Instanz schon bei
#   wenigen hundert Kilobyte mit 413 abbricht. Dieselbe Grenze trifft git push
#   ueber HTTPS; der Branch geht ueber SSH raus.

# 5 Manifest neu schreiben (liest tars/ und negative.json)
python3 scripts/golden/build-manifest.py

# 6 Fakten und Reportdaten aller Auftraege (Tars werden gelesen, nicht entpackt)
cd report-worker && python -m reporter.facts --golden && python -m reporter.v3 --golden-all

# 7 Soll-Liste je neuem Auftrag, abgeleitet (strict false). Markierungen neben
#   "checks" in expected_map_<slug>.json bleiben beim Neuerzeugen erhalten.
python3 scripts/golden/build-expected-order.py <uuid> --name <slug>

# 8 Seitenerwartung: ops-update-pages in der MR-Pipeline starten (nicht auf einer
#   API-Pipeline), render-pages/expected-pages.json nach render/ uebernehmen.
```

## Tests

`report-worker/tests/test_golden_fixtures.py`. Der Smoke-Test entpackt jedes Tar,
loest das Scan-Verzeichnis wie `reporter/worker.py` auf und ruft
`parse_scan_data`. Unter Windows werden `0bf16342`, `2572eebc` und `860d0d5a`
uebersprungen: sie fuehren Hosts unter IPv6-Adressen, und der Doppelpunkt ist
dort kein zulaessiges Pfadzeichen. Der Test erkennt das an den Tar-Mitgliedern
selbst, es gibt keine gepflegte Liste. Vollstaendig laeuft der Test unter Linux,
also im CI-Job `test-report-worker`, der sich auf einer API-Pipeline manuell
starten laesst.

## Hinweis fuer S1: Hostverzeichnisse nicht nach IP benennen

Im Tar liegen Hosts unter `hosts/<ip>/`. Bei IPv6 enthaelt der Name Doppelpunkte
(`hosts/2a01:4f8:d0a:3124::2/`), und unter Windows ist der Doppelpunkt in Pfaden
nicht zulaessig. Deshalb laesst sich ein solches Tar dort nicht entpacken; die
beiden betroffenen Junkerwerk-Laeufe werden im Smoke-Test uebersprungen.

Der Faktenbuilder darf diesen Namen nicht uebernehmen. Wo er selbst
Verzeichnisse oder Dateien je Host anlegt, braucht er einen Slug: Doppelpunkt
durch Bindestrich ersetzen oder die Adresse hashen. Die IP bleibt als Feld im
Datensatz stehen, sie ist nur kein Pfadbestandteil. Lesen aus dem Tar ist
unproblematisch, solange nicht auf die Platte entpackt wird: `tarfile` liefert
Mitglieder unabhaengig davon, ob ihr Name ein gueltiger Windows-Pfad waere.

## Die beiden Fixtures aus S2c

Beide Auftraege sind Rescans vom 20.09.2026 bei Pilotkunden mit schriftlicher Freigabe
und die ersten Fixtures mit den Scannerfixen aus S2b.

`57b3ac85` (lumbeck-wolter.de) ist der Beleg fuer einen bis dahin unsichtbaren Defekt.
Haupt- und www-Name tragen neben dem A-Record den AAAA `2a01:4f8:d0a:668b::2`, im Lauf
steht aber nur `116.202.77.64`. Die Zusammenfassung gleicher Hosts in
`scanner/phase0.py` fasst Adressen mit identischem FQDN-Satz zusammen und behaelt IPv4;
der AAAA faellt damit vor Phase 1 heraus. Sichtbar ist das in
`phase0/host_inventory.json`.

`860d0d5a` (junkerwerk.de und junkerwerk.hu) ist der vierte Junkerwerk-Lauf und der
erste mit einem AAAA-Host. Er traegt drei Nachweise: DNS je Domain (Issue #12,
`dns_records_junkerwerk.hu.json` und `dns_security_junkerwerk.hu.json` im Tar),
junkerwerk.hu weiterhin ohne eigene Hosts (Issue #17) und den `-6`-Schalter an echten
Daten (Issue #8). Beim IPv6-Host `2a01:4f8:d0a:3124::2` steht `-6` in der
Kommandozeile im Tar, der alte Grund `target_invalid_ipv6` ist weg, und trotzdem kommt
kein Port zurueck. Warum, steht in `reporter/facts/README.md` unter Datenfalle 6;
Issue #8 bleibt offen.

## Das Fixture aus S5b: der einzige WebCheck-Auftrag

`75338c97` (vectigal.tech und vectiscan.de, 20.09.2026) ist der vierzehnte Auftrag und
der erste, der nicht Perimeter ist. Bis dahin war die WebCheck-Variante des Renderers nur
synthetisch geprueft: `tests/pdf_v3/conftest.py::as_package` stellte einen
Perimeter-Auftrag im Datenmodell auf WebCheck um. An echten Daten war weder belegt, dass
Kapitel 3.4 und das Service-Inventar sauber entfallen, noch was die Hostgrenze drei und
der kleinere Werkzeugsatz mit den uebrigen Kapiteln machen (Issue #23).

Beide Ziele sind eigene Domains hinter derselben Traefik-Instanz mit Rate-Limit; der Lauf
ist ein interner Nachweis aus S2b und wird nicht ausgeliefert. Die synthetische Pruefung
bleibt als Gegenprobe "gleiche Daten, anderes Paket" bestehen.

## Die sieben Fixtures der Scan-Runde (S6a2)

Perimeter-Auftraege vom 23.09.2026 bei Pilotkunden mit schriftlichem Einverstaendnis,
Engine catalog, Layout v3, Gate strict, gegengelesen in
`report-prototype/spec/09-gegenlesen-scanrunde.md`. Domains stehen im Repo, Bilder nicht.

| Auftrag | Ziel | Soll-Liste | Befunde / Positive | Markiert | Zustaendig |
|---|---|---|---|---|---|
| 1fbc92b9 | dortmund-beach.com | `dortmund-beach-0923` | 20 / 16 | 0 | 0 |
| c3d5724c | lumbeck-wolter.de | `lumbeck-wolter-0923` | 8 / 12 | 0 | 1 |
| 31d67a02 | junkerwerk.de, junkerwerk.hu | `junkerwerk-0923` | 41 / 41 | 2 | 1 |
| 3cf01f8d | huendgen-entsorgung.de | `huendgen-0923` | 16 / 29 | 1 | 3 |
| 68d59573 | bergersysteme.com | `bergersysteme-0923` | 19 / 36 | 5 | 7 |
| 1f8bc977 | castenow.de | `castenow-0923` | 53 / 88 | 4 | 10 |
| 2e56abe1 | heuel.com | `heuel-0923` | 29 / 51 | 6 | 5 |

Stand S6b-2 (25.09.2026). Nach S6b-1 standen dort 24/17, 10/11, 41/41, 15/31, 22/39,
52/92 und 30/52 Eintraege sowie 60 Markierungen; vor S6b-1 41/40, 15/29, 22/52, 52/86 und
29/53 sowie 95 Markierungen. Die Aenderungen stehen unter "Bekannte Abweichungen".
"Zustaendig" zaehlt die Eintraege mit `zustaendig` (hoster oder platform).

Die Soll-Listen sind wie bei dortmund-beach und lumbeck-wolter aus dem Katalogergebnis
abgeleitet (`strict: false`), je Pruefung und Gruppe, also feiner als die gebuendelten
Befunde im Bericht. Getestet werden alle sieben in `tests/catalog/test_golden_scanrunde.py`.
Was spec/09 als falsch belegt, steht trotzdem in der Liste, aber markiert
(`spec09`, `warum` in `expected_map_<slug>.json`, Erlaeuterung unter `hinweis_spec09`):
Q3 geteilte Systeme und Plattformen, Q4 Vorbedingungen (`dane_missing` in allen sieben,
Banner, TRACE, BREACH), Q8 Header an Weiterleitung, 403, 400 oder Vercel-Challenge, Q9
Positivbefunde ueber Hosts ohne Messergebnis, Q12 Positivbefunde ohne tragfaehigen Fakt,
Q13 Einstufung der Verwaltungsoberflaechen (E1), Q14 ZAP unter Konfidenz High, Q18
Lebenszyklus (WordPress 6.5.12, Zertifikatslaufzeiten nach E2). S6b aendert diese
Eintraege bewusst; `build-expected-order.py` erhaelt die Markierungen beim Neuerzeugen und
meldet jede, deren Eintrag wegfaellt. Reine Textmaengel stehen nicht an den Eintraegen.
S6b-1 hat Q3, Q9 und den Teil-2-Eintrag zu 40.99.150.120 aufgeloest (Erlaeuterung unter
`hinweis_s6b1`); danach waren 60 Markierungen offen: Q4 15, Q8 18, Q12 10, Q13 7, Q14 5,
Q18 4 und Teil 2 1 (Exchange-Patchstand bei castenow). S6b-2 hat 42 davon aufgeloest
(`hinweis_s6b2` je Liste, Test `test_nach_s6b2_bleiben_nur_die_q8_markierungen`); es
bleiben die 18 Q8-Markierungen (Header an Weiterleitung, Fehler- oder Challenge-Seite)
fuer die Scanner-Session S6c.

Was die Listen nicht zeigen, weil es fehlt: die Discovery verliert Hostnamen (spec/09 Q1:
eset und ftp bei lumbeck-wolter, archiv bei Junkerwerk, ftp und ftp.mail bei Hündgen,
24 Namen bei bergersysteme, as2 und control bei heuel), Port 25 sieht nmap nirgends (E5;
seit S6b-1 steht das als Einschraenkung "SMTP auf Port 25 vom Pruefstand aus nicht
pruefbar" in Kapitel 2.2). Exchange 2019 bei Hündgen ist seit S6b-2 ein
`software_eol`-Befund mit Quelle (Q18).

Regressionsfaelle der Dashboard-Techniktabelle (spec/09 Q11): c3d5724c und 31d67a02
(MariaDB mit Praefix 5.5.5-, PostgreSQL "9.6.0 or later"), 1fbc92b9 und 1f8bc977
(jQuery Migrate), `tests/v3/test_tech_rows_paritaet.py`. Die API-Snapshots halten den
Stand vor S6a2 fest, also die alten `tech_rows` mit EOL fuer MariaDB und PostgreSQL.

Tar-Groessen nach dem Entfernen der Bilder 28 KB bis 989 KB (heuel 0,94 MB, castenow
0,89 MB); der Export lief ueber Pipeline 3176, Jobs 22798 bis 22804.

## Bekannte Abweichungen

- `expected/junkerwerk.json` fuehrt `family` und `families`. Das Feld gibt es in
  `report-prototype/build/report_data.py` nicht; die Namen stammen aus dem
  Vokabular von `build/catalog_sim.py`, die Zuordnung steht im Generator.
  Positivbefunde haben in der Quelle keine ID, `VS-2026-P01` bis `P08` sind
  hier vergeben, `scale` und `level` bleiben leer.
- `negative.json` enthaelt fuer das Muster `NEG-MARIADB-55` acht statt der in
  spec/06 genannten fuenf Eintraege (a6df9d9d traegt denselben Datenbankbefund, 57b3ac85
  und 860d0d5a kamen nach S0c in den Snapshot). Der Grund steht in der Datei unter
  `hinweis_soll`. Ebenfalls dort: der Defekt dieses Musters sitzt in der
  Versionsableitung, nicht im Befundtext. Seit S6b-2 folgen die Sollzahlen aller alten
  Muster dem Snapshot (SPF 8, MariaDB 8, FTP 3, Titel 6), siehe unten.
- `expected/junkerwerk.json` fuehrt die Berichtsnummer seit S6a im Produktformat
  `VS-2026-0831-0bf1` statt der Prototyp-Nummer `VS-JW-2026-0831`; der Generator
  leitet sie ab (`s6a_report_id`), Grund in `reporter/v3/deltas.md` Punkt 14. Alle
  14 `report-data/*.json` und der HTML-Snapshot tragen die neue Nummer
  (`meta.report_id`); vorher kollidierten 0831 dreimal, 0920 dreimal und 0722 zweimal.
- S6a, Issue #30: Der Positivbefund von `remote_admin_closed` heisst "Keine
  Windows-Fernwartung (RDP) und keine Windows-Dateifreigabe (SMB) aus dem Internet
  erreichbar", und ein Host mit FTP auf 21, Verwaltungsoberflaeche oder SSH ausserhalb
  Port 22 mit Befund faellt heraus (`positive_conflicts`). In den Reportdaten entfaellt
  er deshalb fuer 14272c00, 45bb234c und 57b3ac85 (je ein Host mit Konflikt), bei
  2d2d4f39 und f77ccff2 steht "ausser 92.205.163.53"; 75338c97, 860d0d5a und a6df9d9d
  behalten ihn mit neuem Titel. Positivbefunde nennen je Host hoechstens drei virtuelle
  Hosts ("und weitere", Rest von spec/08 Punkt 13): 75338c97, 2572eebc, fb13a98f.
  Regressionssperre ohne Golden-Tar: `tests/v3/fixtures/huendgen_62c1e866.json`.
- S6a, Massnahmenplan: Zeilen mit gleichem Massnahmentext laufen zu einer Zeile mit
  beiden Befundlisten und beiden Effekten zusammen (`reporter/v3/plan.py`). Planzeilen
  176db198 8->7, 2d2d4f39 16->12, 4e6b6883 16->10, 860d0d5a 10->8, ae8d1d70 12->9,
  f77ccff2 16->10, fb13a98f 10->9; die Hebel auf Seite 2 folgen den ersten drei Zeilen.
  Die uebrigen sieben Auftraege hatten keine Doppelnennung.
- S6a, #15 Teil 2: `dkim_missing` ist ohne gefundenen Selektor nicht pruefbar
  (`dkim_selector_unknown`), nie "fehlt". Golden-Facts (Schema 1.0.4) tragen
  `dns[].dkim.probed` und `probed_basis`; alle vierzehn Tars belegen den Scanner-Stand ab
  ae5fa74 (`dns_security` mit `tls_rpt`), deshalb `scanner_stand` mit 62 Selektoren. In
  den Reportdaten entfaellt der Befund "Grundlegende Eintraege zur
  Absender-Authentizitaet fehlen" fuer 14272c00, 45bb234c und fb13a98f (DKIM war das
  einzige Mitglied), die IDs ruecken nach; bei 75338c97 bleibt er fuer vectiscan.de mit
  dem SPF-Mitglied. Die Einschraenkung nennt Anzahl und sechs Beispiele, Anhang
  "Eingesetzte Werkzeuge" die volle Liste. Soll-Listen `expected/dortmund-beach.json` und
  `expected/vectigal-tech.json` neu erzeugt (DKIM-Eintrag weg, IDs nachgerueckt).
  Regressionssperre an sieben echten Berichten mit "DKIM fehlt":
  `tests/catalog/test_dkim_missing.py`. `negative.json` ist bewusst nicht neu erzeugt:
  der Generator faende im inzwischen gewachsenen Snapshot auch fuer andere Muster mehr
  Eintraege (SPF 8 statt 7, MariaDB 8 statt 6, FTP 3 statt 2, Titel 6 statt 5); das ist
  eine eigene Pruefung.
- S6a2, spec/09 Q11: Faktenschema 1.0.5, Golden-Facts und Reportdaten aller Auftraege
  neu gebaut. (1) Namensgrenzen: `versions.classify` vergibt eine Familie nur, wenn der
  Name ausserhalb des Treffers nur neutrale Zusaetze traegt. In den Technologietabellen
  wird "jQuery 3.4.1" zu "jQuery Migrate 3.4.1" plus "jQuery" ohne Version (14272c00,
  2d2d4f39, 45bb234c, 4e6b6883, ae8d1d70 auf 85.22.47.41, f77ccff2), bei ae8d1d70 kommt
  auf 85.22.47.39 "jQuery UI" als eigene Zeile hinzu. Kalibriert an allen 121 Rohnamen
  der Tars und Snapshots; sonst aendert sich nur "ProFTPD or KnFTPD" (eigenes Produkt,
  in keinem Golden-Tar). (2) Quelle: die Spalte "Erkennung" nennt das liefernde Werkzeug
  statt pauschal webtech. Ein Eintrag aus `tech_profile.technologies` gehoert dem ersten
  Werkzeug der Scanner-Reihenfolge, das ihn meldet (phase1: nmap, webtech, CMS;
  tech_enricher: Header, zap_spider, httpx; beide deduplizieren ueber den Namen).
  "nmap, webtech" wird bei lumbeck-wolter und Junkerwerk zu "nmap"; mehrere Werkzeuge
  stehen nur, wo verschiedene Eintraege denselben Fakt ergeben (IIS: "Microsoft IIS
  httpd" von nmap, "Microsoft-IIS" von webtech, "IIS" von httpx). Konfidenz und
  Patch-Status keiner Zeile aendern sich. Befunde unveraendert, nur die Quellenangabe
  (Exchange bei 2d2d4f39, 4e6b6883, f77ccff2 mit cms_fingerprint statt webtech, MariaDB
  bei 45bb234c, nginx bei ae8d1d70 ohne webtech). HTML-Schnappschuss 0bf16342 neu
  geschrieben (Quelle, Faktenschema im Impressum). (3) `reports.tech_profiles[].tech_rows`
  entstehen im Katalogweg aus denselben Zeilen (`reporter/v3/dashboard.py`);
  Paritaetstest `tests/v3/test_tech_rows_paritaet.py`.
- S6b-1 (spec/09 Q2, Q3, Q9, Q10, Q15, Q16, Teil 3, E4, E5, Issue #33): Faktenschema
  1.0.6, Katalog 2026-09-25.1, Golden-Facts, Reportdaten aller 21 Auftraege, Soll-Listen
  der sieben Scan-Runden-Auftraege und von dortmund-beach, lumbeck-wolter,
  junkerwerk-rescan und vectigal-tech sowie der HTML-Schnappschuss neu gebaut. Je Q-Nummer:
  - Q3 (geteilte Systeme): `hosts[].shared` (hoster, platform) aus fremden Namen, rDNS und
    Nutzungsart bzw. CNAME auf eine Plattform. Befunde der Pruefungen in
    `catalog/tables.SHARED_OPERATOR_CHECKS` auf einem geteilten Server und alles
    Hostbezogene auf einer Plattform tragen "beim Hoster X" bzw. "beim
    Plattformbetreiber X" im Titel, einen Zustaendigkeitssatz und im Plan "Beim Hoster
    einfordern:". Buendel werden nach Zustaendigkeit getrennt; daher mehr Befunde:
    castenow 20->22, heuel 11->12, junkerwerk 15->16, bergersysteme 12->13 (Vorlaeufe
    ebenso: 2d2d4f39 28->30, 4e6b6883 und f77ccff2 29->31, 0bf16342, 2572eebc und
    860d0d5a je plus eins, fb13a98f 13->14). Alle 19 Q3-Markierungen getroffen, dazu 13
    weitere Eintraege (Soll-Feld `zustaendig`). Gegenproben ohne Zustaendigkeit:
    Junkerwerk 217.243.248.28 (eigene Leitung) und heuel 20.79.218.75 (Azure).
    Netzbetreibernamen ohne Zusatz nach einem Strich ("Hetzner Online AG").
  - Q9 und E4 (Abdeckung): nmap ohne offenen Port ist kein Messergebnis mehr
    (`no_open_ports` bzw. `unreachable_from_scanner`, wenn eine Passivquelle den Host
    innerhalb von sieben Tagen vor Scanende mit Diensten sah). Dienstpruefungen dieser
    Hosts sind nicht pruefbar, der Positivbefund des Auftrags entfaellt ganz (Entscheidung
    DC). Positivbefunde: bergersysteme-0923 52->39, heuel-0923 53->52; in den Reportdaten
    entfallen "Keine Datenbankdienste" und "Keine Windows-Fernwartung" bei 2d2d4f39 und
    75338c97, bei 860d0d5a zusaetzlich "Serversoftware mit laufender Herstellerpflege".
    Sechs Q9-Markierungen bei castenow waren falsch begruendet (bitwarden und umfrage haben
    offene Ports) und sind aufgehoben. "Vollstaendig" setzt die Leitwerkzeuge des Pakets
    voraus (`tables.LEAD_TOOLS`); aeltere Perimeter-Laeufe ohne `zap_active` stehen deshalb
    als "teilweise" (ae8d1d70, f77ccff2, 2d2d4f39, fb13a98f, 176db198, 0bf16342), wie der
    Hinweis auf Seite 3 sie schon vorher nannte. Drittanbieter (`hosts[].third_party`:
    von der Scan-Steuerung ausgelassen und alle Kundennamen per CNAME fremd) fallen aus dem
    Katalog und stehen in 2.1 als "Drittanbieter, nicht geprueft" (40.99.150.120 bei
    bergersysteme; loest den Teil-2-Eintrag P23).
  - Q10 (Einschraenkungen): eine Zeile je Ursache mit den betroffenen Pruefungen in
    Kundensprache, kein Werkzeugname (Gate `einschraenkung_ohne_pruefung`,
    `werkzeugname_im_kundentext`). testssl-Daten gelten fuer jeden VHost desselben
    IP:Port, dessen Name das Zertifikat abdeckt (`tls.assigned_from`); nur von httpx
    gesehene Dienste sind `tls_protocols_partial` bzw. `tls_ciphers_partial`. Folge:
    castenow und huendgen erhalten den Positivbefund "Transportverschluesselung ohne
    veraltete Protokolle und Verfahren" fuer die Namen, auf denen er gilt; bei heuel
    kommt `tls_no_13` auf ose.heuel.com dazu (heuel-0923 29->30 Befunde). Die Zahl der
    Einschraenkungszeilen sinkt, weil Folgezeilen eines Hosts mit Wurzelursache
    entfallen (bergersysteme 16->11, heuel 14->8, junkerwerk 15->9).
  - E5: Port 25 laut Passivquelle, vom Portscan nicht gesehen, ist eine feste
    Einschraenkung mit dem Dienstnamen aus dem Passivmodul (castenow, dortmund-beach,
    junkerwerk, bergersysteme); `passive_port_unverified` fuer Port 25 und fuer Hosts mit
    Wurzelursache ist erklaert und kein unverarbeiteter Eintrag mehr.
  - Q16 (Umfang): Hostnamen eindeutig gezaehlt (junkerwerk 8->7, heuel 12->11,
    bergersysteme 11->10 ohne den Drittanbieter). IPv4 und IPv6 mit gleichem rDNS sind eine
    Zeile in 2.1 (`more_ips`); IPv6 ohne Route hat keine Technologietabelle. Neue Liste
    "Pruefumfang je Zieldomain" (junkerwerk.hu: nur DNS- und E-Mail-Eintraege).
  - Q2 (Rollen): Rollen nur mit Beleg (`reporter/v3/roles.py`); keine Mail- oder
    Kalenderrolle ohne MX, SPF-Mechanismus, Autodiscover oder Exchange-Fakt am Host.
  - Q15: Feld `kurzname` im Kundenkontext, Herkunft je Feld in `meta.context_sources`.
  - Teil 3: Betroffen-Listen ein Eintrag je Name, Numerus im Katalogtext, keine
    Platzhalter, Bildschirmfotos ohne Dubletten (dortmund-beach 3->1, heuel 8->4,
    junkerwerk 4->3); Namen ohne eigenen Abruf erben kein Bild. Service-Karte nach Ampel.
  - Issue #33: Technik eines weiterleitenden VHosts gehoert dem Ziel (bergersysteme
    92.205.224.174 ohne Webflow, castenow umfrage ohne Drupal); OWA-Build aus einer
    Spider-URL nur am genannten Host (Exchange SE nicht mehr an 188.40.3.130); Plesk-Version
    aus dem nmap-Titel (18.0.80 bzw. 18.0.81); Schreibvarianten eines Produkts sind eine
    Zeile ("cloudflare" und "Cloudflare").
  - Nachtrag 3 (Entscheidungen DC 25.09.): Einleitungssatz Kapitel 2 und Hinweis Seite 2
    zaehlen Systeme mit den Adressen in Klammern (31d67a02: "3 Systeme mit 4 IP-Adressen",
    "Für 1 System (188.40.3.130 mit 2a01:4f8:d0a:3124::2)"); alle 21 Reportdaten neu.
    Dashboard-Profile: eine Adresse ohne eigene Messung haengt als `additional_ips` an der
    Leitadresse ihres Systems. Halbleere Seiten mit Ursache; der Kategorieblock in
    Kapitel 4 bricht ab mehr als sechs Zeilen nach der Kopfzeile um (f77ccff2 Seite 11
    nicht mehr halbleer, 1f8bc977 durch den Umfluss 34 statt 35 Seiten ohne halbleere
    Seite). Bekannt halbleer bleiben 2d2d4f39 Seite 27 und f77ccff2 Seite 27, beide vor
    einem Kapitelanfang mit erzwungenem Seitenwechsel (Merkposten S7).
- S6b-2 (spec/09 Q4 bis Q7, Q12 bis Q14, Q18, spec/08 Teil 2 Punkte 4, 5, 6, 14, 15, 17, 20
  und 21, offene Punkte nach S6a; Entscheidungen DC 25.09.): Faktenschema 1.0.7, Katalog
  2026-09-25.2, Golden-Facts, Reportdaten aller 21 Auftraege, alle elf abgeleiteten
  Soll-Listen, `negative.json`, Manifest und HTML-Schnappschuss neu gebaut. Je Q-Nummer:
  - Q4 (Texte je Regel): Titel, Befundtext, Auswirkung, Empfehlung und Verifikation kommen
    aus den getroffenen Regeln, jede Aussage mit Fakten-Bedingung (`Member.holds`,
    `Finding.provenance`, Gate `aussage_ohne_fakt`, Text-Fixtures je Bedingung). Buendel
    tragen nur den Sammeltitel mit `{rules}`. Soll-Listen: `dane_missing` entfaellt in allen
    sieben (MX in fremder, unsignierter Zone); BREACH und LUCKY13 stehen als
    `tls_weakness_reported` im Anhang, ohne CVE am Befund (castenow bitwarden und umfrage);
    `service_banner_version` ohne SSH-Banner, MariaDB-Handshake und die nmap-Untergrenze
    "9.6.0 or later" (lumbeck-wolter und Junkerwerk ohne Bannerbefund, heuel und
    bergersysteme ohne SSH); `http_trace_enabled` ist eine Werkzeugmeldung ("TRACE in der
    Antwort auf OPTIONS genannt", Junkerwerk .29); `http_alt_port` sagt "zusaetzlicher
    Webport" statt "Auslieferungsseite"; DMARC-Aussagen zur Meldeadresse nur ohne `rua`;
    `ftp_plaintext` nur mit Beleg, sonst `legacy_protocols_present` mit Aussage je
    Erzwingung; `db_exposed` beschreibt PostgreSQL mit Abweisung vor der Anmeldung getrennt
    von MariaDB mit Handshake (spec/09 Teil 2 LW, JW).
  - Q5: die erste Empfehlung steht auf der Dringlichkeit des Befunds, weitere Stufen relativ
    (`levels.relative_stages`); Test ueber alle 21 Auftraege.
  - Q6: eine Planzeile je Massnahmentext und Zustaendigkeit, Effekt und Hebeltitel aus
    `texts.plan` der Regel. Planzeilen: 1fbc92b9 6->12, c3d5724c 4->5, 31d67a02 9->11,
    3cf01f8d 6->11, 68d59573 9->9, 1f8bc977 12->18, 2e56abe1 8->10 (vorher mischten Zeilen
    verschiedene Texte; der Kategorieeffekt `narrative.PLAN_EFFECT` entfaellt).
  - Q7: Nachweis je beruehrtem Fakt eine Zeile "Bezeichnung: Wert" mit Werteuebersetzung,
    Werkzeug der Zeile ist das liefernde (DNSSEC, CAA, MTA-STS, TLS-RPT, DANE aus
    `dns_security`), keine Kuerzung im tragenden Feld, keine Dubletten, keine
    `scan_results:`-Fundstelle; DKIM "keine Selektoren gefunden, N geprueft"; die Fundstelle
    der WordPress-Benutzernamen aus wpscan (oEmbed statt fest `/wp-json/wp/v2/users`);
    wpscan-Schwachstellen je Kennung mit CVE im Nachweis (spec/08 Punkt 20).
  - Q12: Reputation positiv nur ohne Meldungen, Plattform- und CDN-Adressen nicht anwendbar
    (heuel 216.150.1.65 mit 26 Meldungen); WAF nur mit benanntem Produkt aus der eigenen
    Antwort (huendgen, castenow Generic, bergersysteme Weiterleitungsziel); TLS-Positive
    nicht auf Hosts mit ungeprueftem Mail-TLS (bergersysteme); "entfaellt" ist nicht
    bestanden (dortmund-beach, lumbeck-wolter verwaiste Eintraege).
  - Q13 (E1): Webmin mit Anmeldung auf einem System des Kunden ist Exposition kritisch
    (dortmund-beach Rot); Hosting-Panels beim Hoster `admin_panel_hoster` erhoeht (Plesk
    bei castenow und bergersysteme, bei castenow 8443 und 8880 ein Befund
    `admin_access`); Verwaltungsport ohne Fingerabdruck oder Fingerabdruck ohne
    Anmeldebeleg `admin_service_unconfirmed` erhoeht; Passivfund mit Kennung erhoeht mit
    der Pruefung als erster Empfehlung (Junkerwerk SonicWall), ohne Kennung nur
    Werkzeugmeldung (heuel 4433); die Cloudflare-Ports bei bergersysteme entfallen als
    CDN-Kante (Ignorierliste). A.2 aus
    `levels.ADMIN_EXPOSURE`.
  - Q14: ZAP-Regeln nur ab Konfidenz High; darunter `web_vulnerability_reported` im Anhang,
    Quelle nach Lauf ("passiv gemeldet von ZAP"). Die ZAP-Cookie-Meldungen 10010, 10011 und
    10054 stehen nicht mehr in der Ignorierliste (heuel login.seam, spec/09 Teil 2 HL).
  - Q18 (E2): Zertifikat bis sieben Tage Rot und Unverzueglich (castenow mailstore), acht
    bis 14 Tage Hygiene hoch, 15 bis 30 Tage `cert_expiring_later` mittelfristig (huendgen
    17 Tage); Exchange 2016 und 2019 mit Supportende 14.10.2025 und Quelle (huendgen
    15.2.1748); WordPress veraltet nur mit Kern-Schwachstelle, kein EOL bei Release nach dem
    EOL-Datum (dortmund-beach 6.5.12); Debian aus dem Paketsuffix mit LTS-Ende
    (dortmund-beach Debian 11); kein Positivbefund fuer Exchange SE ohne Patchstand
    (castenow, Junkerwerk).
  - spec/08 Punkt 6: Domains ohne MX meldet `mail_spoofing_unprotected`; `spf_*` und
    `dmarc_*` gelten nur mit MX; die Posture zeigt SPF `~all` als "softfail".
  - Punkt 21: whois lieferte in keinem der 21 Auftraege Daten; keine Einschraenkungszeile,
    kein `domain_expiring` im Bericht, bis der Scanner liefert (Issue fuer S6c).
  - Technik (Entscheidung DC 25.09., Frage 7): Technikzeilen nur mit Konfidenz hoch oder
    zwei Quellen, sonst Werkzeugmeldung im Anhang; "Neos Flow:neos" wird "Neos Flow".
    PostgreSQL "or later" und jQuery Migrate (nur httpx) stehen deshalb im Anhang.
  - Zaehlung: Prosa-Eingabe und Einleitung Kapitel 3 zaehlen Systeme (31d67a02: "3
    Systeme"); Gate `zaehlung_widerspruch`.
  - Anhang "Werkzeugbefunde ohne Bewertung": je Meldung eine Zeile mit ihrer eigenen Gruppe
    und dem deutschen Regeltitel als Hinweis (vorher die Sammelbezeichnung des Buendels);
    dazu die Technikzeilen unter der Schwelle. Zeilen: 1fbc92b9 2->21, 1f8bc977 7->30,
    2e56abe1 2->21, 4e6b6883 9->46.
  - `negative.json`: 98 Eintraege, davon 59 aus der Scan-Runde in 21 Mustern
    `NEG-S6B2-*` mit maschineller Pruefung (`pruefung`) gegen den neu erzeugten Bericht und
    Gegenprobe am ausgelieferten Bericht (`tests/v3/test_negative_scanrunde.py`).
    `NEG-MAIL-PLAINTEXT` zaehlt nur noch Auftraege, deren Dienste die Anmeldung vor TLS
    sperren (2 statt 4: securess und bergersysteme bieten die Anmeldung vor STARTTLS an,
    spec/08 Punkt 4).

## Abgleich spec/09 nach S6b-2

Jede in spec/09 als falsch belegte Aussage der sieben Auftraege mit ihrem Stand. "Erledigt"
nennt Session und Test, "offen" den Grund und die Session.

| Stelle | Aussage | Stand |
|---|---|---|
| Q1 | Discovery verliert Hostnamen | offen, Scanner (S6c) |
| Q2 | Mail-, Kalender- und Datenbankrollen ohne Fakt | erledigt S6b-1 (`roles.py`, Gate `rolle_ohne_fakt`) |
| Q3 | geteilte Systeme als Kundensystem | Bericht erledigt S6b-1 (Zustaendigkeit); aktive Pruefung nur gegen Kunden-VHosts (E3) offen, Scanner (S6c) |
| Q4 | Textbausteine je Buendel, Vorbedingungen, `dane_missing` | erledigt S6b-2 (Texte je Regel, `aussage_ohne_fakt`, Text-Fixtures, `NEG-S6B2-*`) |
| Q5 | Empfehlungsstaffel vor der Dringlichkeit | erledigt S6b-2 (`test_s6b2::test_erste_empfehlung_steht_auf_der_dringlichkeit`) |
| Q6 | Plan nach Prioritaet und Effekt | erledigt S6b-2 (`test_plan`, `test_s6b2`) |
| Q7 | Nachweis traegt die Behauptung nicht | erledigt S6b-2 (Selbstcheck `nachweis_*`, `test_spec08`) |
| Q8 | Header an Weiterleitung, Fehler- oder Challenge-Seite | offen, Scanner (S6c); 18 Markierungen |
| Q9 | Hosts ohne Messergebnis vollstaendig | erledigt S6b-1 |
| Q10 | Einschraenkungstabelle, TLS-Zuordnung | erledigt S6b-1; testssl an IP binden offen, Scanner (S6c) |
| Q11 | Techniktabelle Dashboard und PDF | erledigt S6a2 und S6b-2 (Schwelle, Rohbezeichner, `test_tech_rows_paritaet`) |
| Q12 | Positivbefunde ohne tragfaehigen Fakt | erledigt S6b-2 (`NEG-S6B2-WAF`, `-REPUTATION`, `-VERWAIST`, `test_s6b2`) |
| Q13 | Einstufung der Verwaltungsoberflaechen | erledigt S6b-2 nach E1 (`levels.ADMIN_EXPOSURE`, `NEG-S6B2-WEBMIN`, `-VERWALTUNG-*`) |
| Q14 | ZAP unter Konfidenz High traegt Befunde | erledigt S6b-2 (`NEG-S6B2-ZAP-UNTER-HIGH`) |
| Q15 | Firmenname und Kurzname | erledigt S6b-1 |
| Q16 | Adress- und Hostzuordnung | Bericht erledigt S6b-1; Werkzeuge an die IP binden, AAAA offen, Scanner (S6c) |
| Q17 | Scanner-Ausfaelle und Luecken | offen, Scanner (S6c) |
| Q18 | Lebenszyklus und Aktualitaet | erledigt S6b-2 (`test_facts_s6b2`, `NEG-S6B2-WORDPRESS`, `-ZERTIFIKAT-FRIST`, `-EXCHANGE-SE`) |
| Teil 2 DB | Fundstelle `wp-json/wp/v2/users` | erledigt S6b-2 (`users_found_by`) |
| Teil 2 DB | Wildcard `*.dortmund-beach.com` in Hostlisten | erledigt S6b-2 (2.1, Systemsaetze, Einschraenkungen) |
| Teil 2 DB | Bildschirmfoto pflege zeigt die WordPress-Startseite | offen, Scanner (S6c, Bildnachweis je Name) |
| Teil 2 DB | froxlor auf 443 ueber die IP (in spec/09 unsicher, ohne Regel) | offen: der Bericht sagt dazu nichts Falsches; froxlor-Titel als Fingerabdruck ist eine Regelfrage fuer DC (offene Frage S6b-2) |
| Teil 2 DB | 587 mit AUTH vor STARTTLS gruen | offen: SMTP-Regel nach E5 (spec/09 Teil 4), S6c |
| Teil 2 LW, JW | Rateangriffe bei PostgreSQL mit Abweisung | erledigt S6b-2 (`NEG-S6B2-POSTGRESQL-RATEANGRIFF`) |
| Teil 2 JW | LUCKY13 nur bei .29 | erledigt S6b-2 (beide als Hinweis im Anhang) |
| Teil 2 JW | RDP/SMB-Positiv fehlt fuer .29 | erklaert: entfaellt ganz, weil die IPv6-Adresse nicht pruefbar ist (Entscheidung DC S6b-1 zu Q9) |
| Teil 2 JW | "Datenbankportsträfe" | offen, Darstellung (S7) |
| Teil 2 HE | 444 Firmenportal nur von nmap gesehen | Text erledigt S6b-2 (kein "Auslieferungsseite"); Tiefenpruefung je Port offen, Scanner (S6c) |
| Teil 2 HE | Duda-Plattform "Ports schliessen" | erledigt S6b-1 (Plattformbetreiber) |
| Teil 2 BS | Cloudflare-Kante als Verwaltungsoberflaeche | erledigt S6b-2 (Q13) |
| Teil 2 BS | autodiscover Microsoft als Host | erledigt S6b-1 (Drittanbieter) |
| Teil 2 BS | gleicher Header-Sachverhalt mittel und niedrig | erledigt S6b-2 (Einstufung je getroffener Regel, HSTS fehlt ist mittel) |
| Teil 2 CA | Shoutcast als Auslieferungsseite | erledigt S6b-2 (Q4) |
| Teil 2 CA | mailstore "Access through untrusted domain" ohne Einschraenkung | offen, Scanner (S6c, zusammen mit Q8) |
| Teil 2 CA | Exchange "nachweislich gepflegte Version" | erledigt S6b-2 (`NEG-S6B2-EXCHANGE-SE-PFLEGE`) |
| Teil 2 CA | AUTO-OVERRIDE umfrage | offen, Scanner-KI #1 (S6c) |
| Teil 2 CA | Nachweis VS-015 mit www-Zertifikat | entfaellt: der Befund (BREACH) steht nicht mehr im Bericht |
| Teil 2 HL | Bildschirmfotos "Redirector" | offen, Scanner (S6c) |
| Teil 2 HL | Cookie-Meldungen an login.seam fehlen | erledigt S6b-2 (Anhang, Q14) |
| Teil 2 HL | Werkzeugmeldungen mit falschem "Betrifft" und englischem Titel | erledigt S6b-2 ("Betrifft" je Meldung, deutscher Regeltitel als Hinweis; der ZAP-Name bleibt als Zitat) |
| Teil 2 HL | FortiSSH gegen WingFTPServer (unsicher) | offen, nicht geklaert (S6c) |
| Teil 3 | Deckblatt "Version / 1.0" | erledigt S6b-2 (Auslieferungsversion, Erzeugung in der Fusszeile) |
| Teil 3 | halbleere Seiten | offen, Darstellung (S7) |

## Golden-Facts (S1)

`facts/<order>.json` ist die Ausgabe von `reporter/facts/` fuer jede Manifest-Order
mit Tar, gebaut aus dem Tar plus den `scan_results`-Zeilen in
`api-snapshot/<order>/results.json` und der Zielliste aus `api-snapshot/orders.json`.
`tests/test_facts_golden.py` baut jede Order neu und vergleicht mit der eingecheckten
Datei (Drift-Guard). Neubau nach jeder Aenderung an Parsern, Normalisierung, Schema
oder nach einem Sync von `reporter/eol_data_generated.py`:

```
cd report-worker && python -m reporter.facts --golden          # schreiben
cd report-worker && python -m reporter.facts --golden --check  # nur vergleichen, Exit 1 bei Abweichung
```

Die Dateien sind Text mit LF (`.gitattributes`), deterministisch (sortierte Schluessel,
keine Erzeugungszeit) und unter 1 MB je Order. Orders ohne Tar (die vier weiteren
NEG-SPF- und die drei NEG-EOL-Faelle) werden im Test direkt aus dem Snapshot gebaut
und nicht eingecheckt.

## Pflege

Jede neue Regel in S2 bekommt ihren Fall hier (spec/05 M7). Widerspricht ein
Kunde einem Befund, wird der Fall ein Eintrag in `negative.json`, bevor die
Regel enger wird.

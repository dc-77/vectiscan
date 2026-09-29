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
  - Seitenerwartung (`render/expected-pages.json`, ops-update-pages in der MR-Pipeline
    3208): Scan-Runde 1fbc92b9 22->24, 31d67a02 26->28, 3cf01f8d 19->21, 68d59573 25->23,
    die uebrigen drei unveraendert; castenow-Vorlaeufe 4e6b6883 46->45,
    f77ccff2 46->44. Halbleer vor einem Kapitelanfang bleiben 2d2d4f39 Seite 28 (vorher 27)
    und neu 4e6b6883 Seite 27, f77ccff2 nicht mehr (Merkposten S7, wie in S6b-1).
- Nachtrag 2 zu S6b-2 (Entscheidungen DC 26.09. zu den offenen Fragen 1 bis 3 und 6),
  Katalog 2026-09-26.1, Reportdaten aller 21 Auftraege, Soll-Listen und HTML-Schnappschuss
  neu gebaut; Fakten unveraendert.
  - Frage 1 (Hosting-Panel-Titel): `panel_title` erkennt froxlor, Plesk, cPanel und
    verwandte Panels am Seitentitel; der Titel steht fuer die Anmeldeseite. Auf einem System
    des Kunden `admin_service_exposed` (kritisch), beim Hoster `admin_panel_hoster`
    (erhoeht). Neue Aussagen fuer die Standardseite des Webservers (80/443 ueber die IP).
    Nur dortmund-beach aendert sich: 88.99.35.112:443 (froxlor) steht im selben Befund wie
    Webmin auf 10000 (Soll-Listen `dortmund-beach-0923` und `dortmund-beach`, Befundzahl
    gleich). Die spec/09-Markierung "unsicher" ist damit entschieden.
  - Frage 2 (Technikzeilen, ersetzt die Schwelle vom 25.09.): nmap, testssl,
    cms_fingerprint und wpscan stehen auch ohne Version in der Tabelle, httpx und webtech
    mit einer Version aus dem Werkzeugbeleg oder einer zweiten Quelle; ohne Version aus
    nur einer Quelle im Anhang. Eine Ziffernfolge ab sechs Stellen ohne Punkt gilt nicht als
    Version (Zeitstempel im Skriptpfad, "Bootstrap 1771057841" bei ae8d1d70). Zurueck in der
    Tabelle: PostgreSQL ohne Version und EOL (0bf16342, 2572eebc, 31d67a02, 57b3ac85,
    860d0d5a, a6df9d9d, c3d5724c), jQuery Migrate 3.4.1 (14272c00, 1f8bc977, 1fbc92b9,
    2d2d4f39, 45bb234c, 4e6b6883, ae8d1d70, f77ccff2), dazu BeTheme, Slider Revolution,
    Underscore.js, Elementor und Yoast SEO mit Version. Im Anhang bleiben bei heuel
    "Java/Servlet", "Neos Flow", "Neos CMS" und PHP ohne Version; "NEOS" aus
    cms_fingerprint steht in der Tabelle. Technikzeilen je Auftrag: 0bf16342 14->15,
    14272c00 12->16, 1f8bc977 19->21, 1fbc92b9 12->16, 2572eebc 13->14, 2d2d4f39 24->26,
    31d67a02 13->14, 45bb234c 9->12, 4e6b6883 24->26, 57b3ac85 8->9, 860d0d5a 13->14,
    a6df9d9d 8->9, ae8d1d70 19->22, c3d5724c 8->9, f77ccff2 24->26; die uebrigen gleich.
  - Frage 3 (Anhang je Meldung): eine Zeile je ZAP-Regel, testssl-Hinweis, Technik oder
    Regel ohne Meldungsnamen, mit Anzahl und hoechstens sechs Betroffenen plus "und n
    weitere"; die Einzelmeldungen stehen in `appendix.tool_messages` fuer den Export (S7).
    Frage 6: Meldungsname als Zitat, deutscher Regeltitel als Hinweis. Anhangzeilen je
    Auftrag: 4e6b6883 46->14 (44 Einzelmeldungen), 2d2d4f39 37->14, f77ccff2 32->12,
    ae8d1d70 31->12, 1f8bc977 30->15, 0bf16342 20->8, 2e56abe1 21->15, 1fbc92b9 und
    14272c00 21->17, 31d67a02 14->6, 860d0d5a 13->6, 2572eebc 10->4, 45bb234c 7->4,
    176db198 23->20, a6df9d9d 5->4, fb13a98f 4->3, c3d5724c und 57b3ac85 1->0 (die
    Technikmeldung steht jetzt in der Tabelle); 3cf01f8d, 68d59573 und 75338c97 gleich.
  - Seitenerwartung (ops-update-pages, MR-Pipeline 3213): der kuerzere Anhang spart eine
    bis zwei Seiten, 0bf16342 31->30, 176db198 22->21, 1f8bc977 34->33, 2d2d4f39 45->43,
    2e56abe1 24->23, 31d67a02 28->27, 45bb234c 23->22, 4e6b6883 45->43, 860d0d5a 28->27,
    ae8d1d70 36->34, f77ccff2 44->43; halbleer bleiben 2d2d4f39 Seite 28 und 4e6b6883 Seite
    27 (Merkposten S7).

- S6b-3 (spec/10 R1 bis R19 und E13; Entscheidungen DC 26.09. zu Q8, RDP/SMB, HSTS und
  Wortlaut R1), Fakten 1.1.0, Katalog 2026-09-26.2; Golden-Fakten, Reportdaten aller 21
  Aufträge, HTML-Schnappschuss und die elf abgeleiteten Soll-Listen neu gebaut.
  - R1 (Messbasis der Header): `security_headers_incomplete`, `csp_missing`, `csp_weak` und
    `header_duplicate` lesen `http.header_eval` und sind an einer Weiterleitung, Fehlerseite
    oder Sicherheitsabfrage nicht prüfbar (`headers_redirect_only`, `headers_error_only`,
    `headers_challenge_only`); die Einschränkungszeile nennt den Statuscode aus dem Fakt und
    das Ziel ("bergersysteme.com (301 auf www.bergersysteme.com)"). `hsts_missing` gilt an
    jeder Antwort. Endseiten aus `redirect_probe` (junkerwerk outlook, huendgen exchange,
    castenow owa und ubb-wiki), aus dem testssl-HTTP-Abschnitt (castenow bitwarden) und als
    Teilbeleg aus ZAP (junkerwerk autodiscover, castenow mail und mail2). Abweichung von
    spec/10: huendgen exchange hat eine Endseitenmessung (`logon.aspx`, redirect_probe), und
    junkerwerk autodiscover ist nicht "nicht prüfbar", sondern ein Teilbefund aus ZAP an
    `/owa/auth/logon.aspx` (X-Content-Type-Options und CSP fehlen, die übrigen Header sind
    unbekannt, der Nachweis sagt "nur einzelne Header belegt").
  - Q8 (Entscheidung DC 1): 15 der 18 Markierungen aufgelöst. Zwölf Einträge entfallen
    (bergersysteme csp und security_headers an bergersysteme.com und ftp, castenow csp an
    ubb-wiki, csp_weak und security_headers an mailstore, Positiv csp_missing an mailstore,
    heuel csp und security_headers an edi und online), drei bleiben als Befund, jetzt an der
    Endseite gemessen (huendgen exchange, junkerwerk autodiscover und outlook; Markierung
    `spec10: R1`). Als Q8 für S6c bleiben die drei `hsts_missing` an bergersysteme ftp (403),
    heuel edi (403) und heuel online (429); `test_nach_s6b3_bleiben_drei_q8_markierungen`.
  - R2: Aussagen je fehlendem Header (`missing_header_names`), eigene niedrige Variante nur
    Permissions-Policy, CSP je Direktive (script-src gegen style-src, Nonce und Hash),
    Wildcard-Satz nur mit `wildcard_directives`; Gate `header_nicht_fehlend`.
  - R3: Abdeckung "Transportverschlüsselung nur für 443 (SNI …) geprüft, nicht für Port …"
    mit Zeile "Transportverschlüsselung nur für einen Teil der TLS-Dienste geprüft"
    (dortmund-beach acht Ports, bergersysteme Plesk-Mailports); aktive Webanalyse "teilweise"
    ohne echten Inhalt am zap_active-Ziel und bei ZAP ohne Meldungen (huendgen, heuel ose,
    heuel online, junkerwerk .29 IIS-Standardseite); Hosts ohne nmap-Hostbericht "ohne
    Antwort, vom Prüfstand aus nicht erreichbar" (heuel 195.225.241.75, bergersysteme
    79.140.188.181; Grund `no_response` statt `no_open_ports`); neue Prüfung
    `service_cert_expired` (bergersysteme Plesk-Mailports beim Hoster); Werkzeugläufe ohne
    übersprungene und `ai_*`.
  - R4: testssl je IP:Port für alle virtuellen Hosts, Zertifikat über Fingerabdruck oder SAN
    (`cert_assigned_from`), Namensabgleich aus der SAN-Liste (heuel www); `blocked` nur mit
    belegter Sperre (bergersysteme 198.202.211.1 ohne Sperre und ohne Anhang-E-Satz);
    Faktenfamilien unterdrücken "Daten reichen nicht aus" neben einer Messung (castenow und
    dortmund-beach DMARC); Parkname dortmund-beach pflege `parked_name`; Familie
    `cert_trust` getrennt in Kette, Name und Selbstsignatur (sonst Widerspruch bei
    krause-computer und trunk-immobilien).
  - R5: Zeile "Gefunden, nicht geprüft" mit Namen und Adressen, Drittanbieter-Zeilen in 2.1
    (castenow und heuel autodiscover, lumbeck-wolter autodiscover), Phase 0 "Geprüft wurden n
    von m ermittelten Namen"; Gate-Warnung `namen_nicht_geprueft` (14 der 21 Aufträge).
  - R6: Verfahren-Positivaussage nur ohne CBC (castenow .4, junkerwerk, huendgen exchange
    und weitere verlieren sie); Reputation positiv nur, wenn alle gemessenen Adressen samt
    Plattform ohne Meldung sind (heuel ohne Positivbefund, Kapitel 3 nennt 216.150.1.65 mit
    26 Meldungen); URLhaus `no_data` ist kein Negativergebnis (Positiv `urlhaus_compromise`
    entfällt überall); Kategorie B grau "nicht bewertbar" ohne Lebenszyklusquelle (castenow,
    heuel); lumbeck-wolter und junkerwerk bleiben grün, weil Debian 12 mit LTS-Ende
    30.06.2028 und Quelle Debian LTS bewertbar ist, der Positivbefund nennt nur diese Zeile
    (Abweichung von spec/10, dort "grau" auf Grund von Debian 12 ohne Quelle); Zonentransfer
    je Domain (junkerwerk.hu mit `zone_transfer_junkerwerk.hu.txt`); Listen mit sechs Namen
    und "und n weitere"; Positivbefunde auf geteilten Systemen mit "beim Hoster X".
  - RDP/SMB (Entscheidung DC 2): nur ein RDP- oder SMB-Port-Fakt widerspricht dem
    Positivbefund. Die S6a-Konfliktregel (FTP, SSH ausserhalb 22, Verwaltungsoberfläche,
    `positive_conflicts`) ist mit dem Titel aus #30 gegenstandslos; "außer X" steht nur noch
    mit Port-Fakt, und dann entfällt der Positivbefund, weil der Befund im selben Bündel
    steht. Die Hündgen-Regressionssperre (`tests/v3/fixtures/huendgen_62c1e866.json`,
    `test_huendgen_ftp_host_bleibt_im_positivbefund`) prüft die neue Lesart: drei Hosts im
    Positivbefund, FTP-Befund daneben. castenow ohne "außer 92.205.163.53".
  - R7: POP3 ohne `USER` und mit leerem `SASL` vor `STLS` ist TLS-Zwang (lumbeck-wolter,
    junkerwerk, heuel 110); `mail_plaintext` positiv nur mit belegtem TLS-Zwang; Gate
    `positiv_widerspricht_befund`.
  - R8: Posture aus denselben Regelergebnissen; "TLS-RPT" und "DANE" getrennt, DANE
    "entfällt (MX beim Dienstleister)"; `hsts_short` unter Sicherheits-Header; Gate
    `posture_widerspricht_befund`.
  - R9 und HSTS (Entscheidung DC 3): `max-age=0` als "HSTS abgeschaltet" unter `hsts_missing`
    (dortmund-beach: `hsts_short` entfällt, `hsts_missing` neu), `hsts_short` im Bündel
    `web_header_hygiene`; Kennung vor "Zweck klären" (castenow Shoutcast und Icecast, huendgen
    444 mit vollem Titel "Web Applications Portal" aus dem nmap-Element); neue Prüfung
    `service_unidentified` (huendgen 1000 bis 1002, heuel 8443 statt `http_alt_port`);
    castenow 8001 mit Kennung aus dem Zertifikat (Beobachtung ohne Regel); Exchange 2019 mit
    Variante "Ablösung planen"; X-FEServer als interner Servername; Rollentexte
    "Redaktionszugang" (castenow ubb-wiki, WordPress) und Zusatz "nur eine Fehlerseite
    (400)" (castenow mailstore).
  - R10: E5 je Adresse; Gate `e5_fehlt`.
  - R11 (E8): eine Planzeile je getroffener Regel mit ihrer ersten Stufe und dem Effekt dieser
    Stufe (`Recommendation.effect` für DMARC, software_eol, ip_reputation und http_alt_port);
    Hebel nach Titel entdoppelt und mit "Beim Hoster einfordern:"; Planzeilen je Auftrag
    siehe unten (junkerwerk 31d67a02 11 -> 22).
  - R12: Beobachtungen ohne Regeltreffer als Liste statt Zusage; Anhang D "Grundlage sind die
    vollständigen Werkzeugausgaben"; Gate `zusage_im_kundentext`.
  - R13: `findings_data.customer_context` mit Wert und Quelle je Feld; Mitarbeiterzahl und
    Branche nur mit Quelle Kunde oder Admin in der Prosa-Eingabe; Betriebsform je System;
    "Unternehmensnetz" nur mit einem System am Anschluss; Prosa-Gate prüft Mitarbeiterzahl,
    Anschluss, Mehrfaktor ohne Bedingung und relative Fristen.
  - R14: Werkzeugzeilen mit deutschem Kopf ("IMAP-Fähigkeiten: …" ohne Füllwörter und
    Antwortmarken), "oder neuer (Untergrenze)", TRACE-Zeile nur bei `http_trace_enabled`,
    Kürzung an Kopf- oder Wortgrenzen, deutsches Datum, Quellen in 3.1 wie in Anhang C
    (crt.sh, ffuf, CMS-Erkennung, Weiterleitungsprüfung), MariaDB durchgängig, A.3 mit den
    wpscan-CVE (dortmund-beach 17, "Quelle wpscan, ohne Fremdbewertung"); Kennzahlen aus der
    Bilanz `phase3_correlation`; Gate `cve_ohne_a3`.
  - R15: deutscher Titel je ZAP-Regel, Anzahl in jeder Zeile, aktive Meldungen "nicht
    bestätigt, Konfidenz …", ZAP-Meldungen ohne anschlagende Regel (`covered_by`) im Anhang
    (castenow X-Powered-By, Header an Weiterleitungen), Spaltenbreiten.
  - R16: Rechtsform mit Bindestrich ("Berger EDV-Systemberatungs"); Spalte "Netzbetreiber
    (laut RIPE) / Rolle".
  - R17: Zuständigkeitskasten ohne Fremddomains ("auf demselben Server laut Passivquelle n
    weitere Domains anderer Kunden").
  - R18: "gültig bis 24.09.2026, 23:59 UTC; am Scantag 1 Tag Restlaufzeit", mit Berichtstag
    nach Ablauf "seit 24.09.2026 abgelaufen, sofern nicht erneuert"; Gate-Warnung
    `frist_vor_berichtsdatum`.
  - R19: neue Prüfungen `smtp_vrfy_enabled` (dortmund-beach 465, 587),
    `smtp_vrfy_enabled_passive` (dortmund-beach, bergersysteme, castenow Port 25),
    `wordpress_xmlrpc_enabled` (dortmund-beach), `login_over_http_passive` (bergersysteme
    62.217.52.162), `spf_authorizes_shared_host` (castenow 159.69.143.80 und junkerwerk
    188.40.3.130, beide Server laut Shodan mit Domains anderer Kunden); "Version beim
    Betreiber prüfen" (heuel Wing FTP, FortiSSH); Konfidenz mittel bei widersprechender
    Passivquelle (heuel FortiSSH gegen WingFTPServer); AUTH vor STARTTLS, readme, wp-cron und
    Ressourcen-Versionen als Beobachtung ohne Regel.
  - E13: Erneuerungsverlauf aus crt.sh als Nachweiszeile der Zertifikatsbefunde ("Erneuerung
    laut CT-Logs: bisher im Mittel 32 Tage vor Ablauf, 66 Zertifikate").
  - Zahlen je Auftrag (Befunde, Positivbefunde, Planzeilen, Anhangzeilen, Einschränkungen):
    dortmund-beach 1fbc92b9 12->14, 5->6, 12->20, 17->17, 6->6 (A.3 0->17); lumbeck-wolter
    c3d5724c 5->5, 6->7, 5->8, 0->0, 2->4; junkerwerk 31d67a02 15->16, 4->5, 11->22, 6->6,
    8->9; huendgen 3cf01f8d 11->12, 7->6, 11->16, 5->5, 4->6; bergersysteme 68d59573 9->12,
    6->5, 9->16, 2->2, 11->12; castenow 1f8bc977 19->20, 9->12, 18->24, 15->20, 9->12; heuel
    2e56abe1 10->10, 7->6, 10->16, 15->16, 7->12. Übrige: 0bf16342 16->17, 3->3, 15->30;
    14272c00 12->14, 5->6, 12->20; 176db198 8->7, 5->4, 8->13; 2572eebc 16->17, 5->5, 15->30;
    2d2d4f39 27->29, 6->7, 22->33; 45bb234c 11->11, 3->4, 11->15; 4e6b6883 28->29, 6->6,
    21->32; 57b3ac85 5->5, 6->7, 5->8; 75338c97 8->8, 3->1, 7->11; 860d0d5a 15->16, 4->5,
    11->22; a6df9d9d 10->11, 7->7, 10->16; ae8d1d70 19->18, 5->4, 17->27; f77ccff2 28->29,
    7->8, 21->32; fb13a98f 13->13, 5->4, 12->18.
  - Drift-Test junkerwerk: neue Gründe in `expected_coverage_differences` (`no_response`,
    `cert_chain_unknown`, `mx_external`, `zone_unsigned`, `headers_*`, `parked_name`,
    `mail_tls_unknown`) und die Header an outlook als `expected_member_differences`
    (Multi-Lauf nur Teilbeleg, Rescan Endseite). P08 der Prototyp-Liste nur noch mit
    `ip_reputation`, `spf_authorizes_shared_host` in `subsumed`.
  - Seitenerwartung (ops-update-pages, MR-Pipeline 3217): mehr Planzeilen je Regel (R11),
    Einschränkungszeilen und Anhangzeilen kosten eine bis vier Seiten. Scan-Runde 1fbc92b9
    24->28, c3d5724c 15->16, 31d67a02 27->29, 3cf01f8d 21->23, 68d59573 23->26, 1f8bc977
    33->35, 2e56abe1 23->24; übrige 0bf16342 30->33, 14272c00 24->28, 2572eebc 30->32,
    2d2d4f39 43->46, 45bb234c 22->23, 4e6b6883 43->47, 57b3ac85 15->16, 860d0d5a 27->30,
    a6df9d9d 20->22, ae8d1d70 34->35, f77ccff2 43->45, fb13a98f 25->26; 176db198 und
    75338c97 gleich. Halbleer vor einem Kapitelanfang: 2d2d4f39 Seite 30 (vorher 28),
    4e6b6883 Seite 29 (vorher 27), neu f77ccff2 Seite 28 (Merkposten S7).

- S6b-4 (spec/11 T1 bis T16, Teil 3, Entscheidungen E15 bis E23): Faktenschema 1.2.0,
  Katalog 2026-09-27.1. Neu gebaut: Golden-Fakten aller 21 Aufträge, Reportdaten, HTML-
  Schnappschuss und die elf abgeleiteten Soll-Listen; geänderte oder neue Einträge tragen
  `spec11` und `warum`, jede Liste `hinweis_s6b4` mit den entfallenen Einträgen. Die
  kuratierte `junkerwerk.json` behält ihre Liste; P04 in `expected_map.json` nur noch mit
  `dkim_missing` (Teil 3 DB P05). Abweichungen je T-Nummer:
  - T1: Kennung aus `imap-capabilities`, `pop3-capabilities`, `smtp-commands` und dem Banner
    in `servicefp` ("IMAP über TLS (Dovecot)", "SMTP (Exim)"), aus der Passivquelle
    ("ManageSieve (Dovecot Pigeonhole)"); "nicht identifiziert" nur noch an huendgen 1000 bis
    1002 (Regel `service_unidentified`, Karte nach Ampel gelb). Passivports außerhalb der
    Top 1000 heißen "außerhalb des geprüften Portbereichs" (lumbeck-wolter 4190, junkerwerk
    SonicWall 4433, bergersysteme und castenow Plesk 8880).
  - T2: Spaltenkopf "Netzbetreiber (laut AbuseIPDB)", Alias "Hetzner Online GmbH", Anschluss
    "(Anschluss Vodafone)" bei castenow, Plattformen mit "(CDN)" und Konzern ("A100 ROW GmbH
    (Amazon, CDN)"); Soll-Liste `spf_authorizes_shared_host` junkerwerk und rescan mit GmbH.
  - T3: Nachweis je Werkzeuglauf (header_check erste Antwort, Weiterleitungsprüfung,
    testssl, wpscan, ZAP je eigene Zeile, "bewertet an der Endseite" nur bei anderer
    Endantwort); XML-RPC mit Adresse und "belegt durch"; VRFY "in der EHLO-Liste"; Gate
    `nachweis_ohne_regelfakt`.
  - T4 (E20): `hsts_missing` nicht prüfbar an Fehlerseite und Sicherheitsabfrage; entfallen
    bergersysteme ftp (403), heuel edi (403) und online (429), die drei letzten
    Q8-Markierungen (`test_nach_s6b4_keine_q8_markierung_mehr`). heuel online bekommt aus
    redirect_probe die Positivaussagen HSTS gesetzt und ausreichend (max-age=63072000), der
    frühere heuel-Lauf 176db198 dagegen einen Befund "HSTS fehlt": dort lieferte die erste
    echte Antwort (Weiterleitung hinter Cloudflare) keinen Header. Titel "HSTS fehlt" oder
    "HSTS abgeschaltet (max-age=0)" (dortmund-beach), Verifikation "max-age über null";
    HSTS-Empfehlung aus `tls_legacy_protocols` entfernt; Positivbefund je Header statt je
    Port (castenow www, bitwarden, ubb-wiki, mailstore über redirect_probe und umfrage an der
    301; bergersysteme www; 75338c97 neu); ein nicht prüfbares HSTS an einer Fehlerseite hebt
    den Positivbefund anderer Namen nicht auf; Gate auf dieselbe Messung. In den API-Snapshot-
    Läufen ohne `reachable` gilt eine Antwort mit Headern auch für HSTS als Messung (Regel aus
    Schema 1.1.0): neue HSTS-Befunde in 176db198 (20.79.218.75), 45bb234c, ae8d1d70 und
    fb13a98f, der HSTS-Positivbefund kommt dort und in 4e6b6883 zurück.
  - T5 (E15): Berichtsdatum aus `orders.reviewed_at` in Europe/Berlin, sonst Tag der
    Erzeugung in Berliner Zeit; Fußzeile "Erzeugung n vom …". Die Golden-Reportdaten laufen
    weiter mit dem festen Stichtag 19.09.2026; `tests/v3/test_s6b4.py` baut die Fälle mit
    dem 27.09.2026.
  - T6 (E16): Datum je Adresse in der E5-Zeile (junkerwerk .130 23.09., .28 19.09.) und im
    Betroffenen der Passivbefunde ("gesehen am"); Regel der Gesamtbewertung unter A.1
    (`levels.OVERALL_RULE`), unverändert seit S3. Der Vorschlag aus E16 ist nicht umgesetzt,
    weil er huendgen auf HOCH höbe; alle sieben Gesamtbewertungen unverändert (DB, LW, JW, CA
    HOCH; HE, BS, HL MITTEL).
  - T7: Messadresse je Lauf (huendgen 52.59.120.70, heuel 216.150.1.129 und 216.150.16.65,
    castenow 3.174.98.123 und 18.239.50.54) mit Einschränkungszeile "DNS-Rotation"; AAAA
    derselben Namen im System und in der Zählung (lumbeck-wolter 1->2 Adressen,
    bergersysteme 6->8, 57b3ac85 und 176db198 ebenso); Gate-Warnungen
    `ipv6_ohne_inventar` (4 Aufträge) und `messadresse_ausserhalb_inventar` (9 Meldungen).
  - T8: Einschränkung je Host aus der Pfadsuche ("nur gegen Weiterleitung, Fehlerseite oder
    Sicherheitsabfrage, nicht belastbar", "abgebrochen" mit Abwehrmerkmal bei bergersysteme
    198.202.211.1); Phase 2 nennt die Enumeration nur bei einem belastbaren Lauf
    (dortmund-beach, junkerwerk .29, castenow bitwarden).
  - T9 (E18): Zählung nach registrierbarer Domain ohne Hoster-Domains (lumbeck-wolter 2->1
    flott.de, junkerwerk 3->2); Wortlaut "Auf demselben Server stehen laut Passivquelle n
    weitere Domains" ohne "anderer Kunden"; castenow 159.69.143.80 "Server von planwerk6.de
    im Rechenzentrum Hetzner Online GmbH"; Fremdnamen als "Fremddomain"; Shoutcast und
    Icecast auf dem Hoster-Server fallen aus der Auswertung (castenow `http_alt_port` und
    `service_banner_version` entfallen) und stehen als Satz im Zuständigkeitskasten.
  - T10: Kategoriesatz aus den getroffenen Regeln ("preisgegebene Angaben" nur mit
    Offenlegungsbefund), "n Befunde in m von 5 Kategorien", Rollentexte am Fakt
    ("Formulareingaben" nur mit gelaufener aktiver Webanalyse, "Unternehmensnetz" nur am
    Anschluss), MFA mit Bedingung und "prüfen, sonst ergänzen"; Prosa-Gate `FORMULAR`.
  - T11 (E22): Debian 12 "in Langzeitpflege (LTS) bis 30.06.2028 laut Debian" in 3.1 und im
    Positivbefund (junkerwerk jetzt mit Positivbefund; eine nicht erreichbare IPv6-Adresse
    hebt Positivbefunde anderer Hosts nicht mehr auf, deshalb auch RDP/SMB für junkerwerk);
    Passivbefunde auf E4-Hosts blau mit "vom Prüfstand aus nicht erreichbar" und Rolle aus
    dem Pfad (bergersysteme IIS 10.0 "Mail-Webzugang (/owa/)").
  - T12: Hebel je Befund höchstens einmal, Rangfolge bei gleicher Stufe (huendgen: Exchange
    vor "Zweck klären", Produkt im Hebeltitel), Header-Planzeile je Regel mit allen
    Befunden, VRFY "angeboten", `dmarc_quarantine` ohne `rua` zuerst "Meldeadresse", DB
    VS-004 mit allen CVE, Zielversionen und Plural (Soll-Listen: Titel geändert).
  - T13: Sammelbegriffe, Ursache aus der Scan-Steuerung ("Regel hosted-cms-webflow"), SNI nur
    aus eigenen testssl-Läufen, Vertrauenskette nur für den eigenen Namen (heuel www),
    Zeile für Webports ohne Web- und Header-Analyse, Fremdbewertungszeile nur mit Version
    ohne Abgleich (junkerwerk .130 dazu, castenow .53 heraus).
  - T14: Erneuerungslinie je SAN-Satz und Aussteller ("zuletzt 7 Tage vor Ablauf erneuert
    …, nächste Erneuerung nach diesem Muster um den 04.10.2026"); `cert_expiring` mit
    Variante "am Berichtsdatum abgelaufen, sofern nicht erneuert" in Titel, Hebel, Plan und
    Nachweis und dem gültigen Zertifikat an 195.50.179.4 und .6; Hinweis, wenn am
    Berichtsdatum höchstens zwei Wochen bleiben (Stufe bleibt nach E2 am Scantag).
  - T15: eine Zeile je Produkt über `TECH_ALIASES`, Patch-Status aus wpscan ("veraltet, 12
    bekannte Lücken, aktuell 28.5.10"), WordPress-Kern aus wpscan, Skript-URLs als zweite
    Quelle (jQuery Migrate huendgen, Ultimate Member 2.13.1 castenow), nmap `ostype` für
    Windows (junkerwerk .29), kein Cookiebot und kein Icecast; Anhang C: dortmund-beach
    17->14, huendgen 5->2 Werkzeugmeldungen.
  - T16: Posture aus denselben Regeln (castenow SPF Handlungsbedarf, Transport .5 und .6 mit
    den Zertifikatsbefunden über `pulls`), "Verwaiste Einträge" unauffällig bei gelaufener
    Abfrage; Service-Karte nach Ampel auch für `service_unidentified` und für Passivports mit
    Befund (junkerwerk 4433 gelb), Softwarebefunde am Port ihres Belegs (dortmund-beach 30000
    gelb); Gate auf alle Karten.
  - Teil 3: junkerwerk BEAST "vermutlich abgeschwächt", Titel "Zusätzliche Mail- und
    Dateidienste erreichbar (TLS erzwungen)" mit passendem ersten Satz, P04 mit .hu und den
    Selektoren; huendgen 8443 als Plattformhinweis ohne "Port schließen"; castenow Rollen
    "Anmeldung zur Website" und "Umfrageplattform (umfrageonline.com), leitet auf die Website
    weiter", X-Powered-By PHP/8.4.25 als neuer Befund an ubb-wiki, "liesmich.html"; heuel
    Rolle "Dateiaustausch (FTP, SFTP), Webanwendung mit Anmeldung", Bildunterschriften aus
    redirect_probe; lumbeck-wolter "SASL (leer)", "Produkt: MariaDB", Hinweiskasten mit den
    nicht geprüften Namen; bergersysteme VS-003 Betroffene einmal, Verifikation ohne Port 587,
    Reputation mit der CDN-Adresse; dortmund-beach DMARC mit Meldeadresse und Mailserver beim
    Dienstleister, SPF-Positivbefund nur bei `-all` oder `redirect=` (entfällt bei ~all in
    dortmund-beach, lumbeck-wolter, junkerwerk, castenow, heuel).
  - Zahlen je Auftrag (Befunde, Positivbefunde, Planzeilen, Anhangzeilen, Einschränkungen,
    IP-Adressen): dortmund-beach 1fbc92b9 14->14, 6->5, 20->19, 17->14, 6->6, 1->1;
    lumbeck-wolter c3d5724c 5->5, 7->7, 8->8, 0->0, 4->6, 1->2; junkerwerk 31d67a02 16->16,
    5->7, 22->21, 6->6, 9->10, 4->4; huendgen 3cf01f8d 12->12, 6->8, 16->16, 5->2, 6->8, 2->2;
    bergersysteme 68d59573 12->12, 5->6, 16->15, 2->1, 12->16, 6->8; castenow 1f8bc977
    20->18, 12->13, 24->20, 20->18, 12->14, 6->6 (neu "Content-Security-Policy gesetzt"); heuel 2e56abe1 10->9, 6->7, 16->15, 16->17,
    12->15, 6->6. Übrige: 0bf16342 17->17, 3->3, 30->28; 14272c00 14->14, 6->5, 20->19;
    176db198 7->8, 4->5, 13->15; 2572eebc 17->17, 5->6, 30->28; 2d2d4f39 29->27, 7->7, 33->28;
    45bb234c 11->11, 4->4, 15->15; 4e6b6883 29->27, 6->6, 32->28; 57b3ac85 5->5, 7->7, 8->8;
    75338c97 8->8, 1->2, 11->11; 860d0d5a 16->16, 5->7, 22->21; a6df9d9d 11->11, 7->7,
    16->16; ae8d1d70 18->18, 4->5, 27->25; f77ccff2 29->27, 8->8, 32->28; fb13a98f 13->13,
    4->5, 18->18. Gesamtbewertung überall unverändert.
  - Drift-Test junkerwerk: "gesehen am" und "vermutlich abgeschwächt" kommen aus den
    Rohdaten des einzelnen Laufs (Shodan-Datum, testssl-Ausgabe) und zählen nicht als Drift
    (`_LAUF_ZUSATZ`).
  - Seitenerwartung (ops-update-pages, MR-Pipeline 3221): Scan-Runde 1fbc92b9 28->29,
    31d67a02 29->30, 68d59573 26->27 (mehr Einschränkungszeilen und Positivbefunde), 1f8bc977
    35->33, 2e56abe1 24->23 (weniger Befunde und Planzeilen); c3d5724c und 3cf01f8d gleich.
    Übrige 14272c00 28->29, 176db198 21->23, 2d2d4f39 46->45, 45bb234c 23->22, 4e6b6883 47->44,
    f77ccff2 45->44. Halbleer vor einem Kapitelanfang nur noch 2d2d4f39 Seite 30; 4e6b6883
    und f77ccff2 ohne halbleere Seite.

- S6b-4n (Nachtrag S6b-4, spec/11 Teil 6, N1 bis N15, E24 und E25 als Vorschlag umgesetzt):
  Faktenschema 1.3.0, Katalog 2026-09-27.2. Neu gebaut: Golden-Fakten aller 21 Aufträge,
  Reportdaten, HTML-Schnappschuss und die elf abgeleiteten Soll-Listen; geänderte oder neue
  Einträge tragen `spec11` mit der N-Nummer (ein vorheriger T-Eintrag steht dahinter als
  "vorher …") und `warum`, jede Liste `hinweis_s6b4n` mit den entfallenen Einträgen. Die
  kuratierte `junkerwerk.json` behält ihre Liste; im Drift-Test neu die `X-AspNet-Version` an
  autodiscover als `expected_member_differences` (httpx im Rescan, N12). Abweichungen je
  N-Nummer:
  - N1: `Csp.script_rule` (script-src oder default-src). huendgen www und castenow ubb-wiki
    (nur frame-ancestors) tragen `csp_missing` in der Variante "Inhaltsrichtlinie nur mit
    frame-ancestors, keine Regel für Skriptquellen" statt des Positivbefunds; castenow www
    bleibt in der Katalogliste positiv, der Bericht unterdrückt den Positivbefund neben
    `csp_weak` am selben Namen (`bundles.POSITIVE_BLOCKED_BY`). P "Content-Security-Policy
    gesetzt" nennt bei castenow nur noch bitwarden, bei huendgen entfällt er.
  - N2 (E24): HSTS an 3xx und 400 ist eine Messung, an 429 und Challenge nie, auch kein
    Rückgriff auf die erste Antwort aus redirect_probe. Positivbefund mit Messort "gemessen an
    der Weiterleitung mit Status 301" und "gemessen an der Fehlerseite mit Status 400"
    (castenow umfrage, ubb-wiki, mailstore). Abweichung zum Wortlaut in spec/11: die Klammer
    "(301)" stünde im Bericht in der Klammer hinter dem Namen, der Status steht deshalb ohne
    zweite Klammer. heuel online ohne HSTS-Positiv (Soll-Liste heuel-0923), 176db198 ohne den
    HSTS-Befund an online. Gruppennamen der Header-Regeln nennen nur Aliasnamen mit eigener
    Header-Messung: bergersysteme ohne "+cdn", dazu dortmund-beach "+www", junkerwerk
    "+team", heuel "+heuel.com, jobs.heuel.com", castenow "+castenow.de" und huendgen
    "+huendgen-entsorgung.de" (Einträge mit N2 markiert; zwei Markierungen aus spec/10 R9
    und R19 bei dortmund-beach am neuen Gruppennamen nachgetragen).
  - N3: `HeaderEval.final_response` und `client_redirect`; gleiche Antwort über ETag (ohne
    `W/`, Anführungszeichen und Kompressionssuffix), Last-Modified oder Content-Length. heuel
    ose: ZAP je URL als Quelle, Referrer- und Permissions-Policy "nur an der
    Weiterleitungsseite gemessen" statt fehlend (Soll-Liste heuel-0923 ose ohne die beiden);
    castenow mail und mail2 "an der Endseite nicht gemessen". Gegenprobe junkerwerk outlook
    und huendgen www bleiben Endantwort.
  - N4: `login_form` nur, wenn die Endseite auf demselben Host liegt; webtech- und
    CMS-Einträge eines Hosts, dessen Web-Namen alle auf einen anderen Host weiterleiten, gehen
    an das Ziel (heuel 213.133.104.51 nur noch nmap-Technik, bergersysteme 92.205.224.174
    ohne Webflow und Cloudflare). Rolle "Weiterleitung auf <Ziel>" neben den eigenen Diensten
    (heuel dl und webportal: Dateiaustausch, Mailabruf und Einlieferung, Weiterleitung auf
    ose.heuel.com; bergersysteme 92.205.224.174). Bilder nur am Host, dessen Antwort sie
    zeigen (heuel online und webportal ohne eigenes Bild). Scan-Steuerung bei bergersysteme
    "wegen Weiterleitung auf die Webflow-Seite www.bergersysteme.com".
  - N5 (Entscheidung DC 27.09.): weitere A-Einträge in `additional_ips` mit `family`
    (huendgen 52.59.120.70, heuel 216.150.16.65, castenow 3.174.98.123, .30, .63). Neue
    Einschränkung "Weitere Adresse laut DNS, nicht geprüft" mit den dort gelaufenen
    Messungen; Posture "am Namen gemessen (<Adresse>)" (heuel 216.150.1.65, castenow
    3.174.98.120), ein Befund am Host bleibt Handlungsbedarf (huendgen 18.197.248.23);
    Positivbefunde, Anhang B und 3.1 mit "gemessen an <Adresse>"; Rotationszeile mit
    "Webabruf und Technologie-Erkennung". Abweichung zu spec/11: "Technologie-Erkennung
    (httpx)" ohne Werkzeugnamen, weil `werkzeugname_im_kundentext` httpx im Kundentext sperrt.
    Zählung "n IP-Adressen, davon m nur aus DNS oder ohne Antwort".
  - N6: Kategorie grün nur mit mindestens einer gemessenen Regel, sonst grau "Nicht
    bewertbar" (lumbeck-wolter D). `ip_reputation` auf Plattform- und CDN-Adressen nicht
    anwendbar, positiv nur ohne Meldung im Abfragefenster von 90 Tagen (Positivbefund ohne
    bergersysteme 198.202.211.1, huendgen 18.197.248.23, castenow 3.174.98.120; Soll-Listen
    ohne diese Positiveinträge). Zonentransfer mit Nachweis je Domain aus der eigenen Datei.
    Abweichung zu spec/11 (Entscheidung DC 27.09.): junkerwerk.hu behält den Positivbefund,
    weil das Tar `phase0/zone_transfer_junkerwerk.hu.txt` mit drei AXFR-Läufen enthält
    (`; Transfer failed.` an ns.udag.de, .net, .org); spec/11 sagt "kein AXFR-Lauf".
  - N7: `Dmarc.delegated_to` aus den dnsx-Ketten oder den Shodan-Domaindaten; bergersysteme
    VS-005 trennt dmarc@bergersysteme.com (eigene Domain, "auswerten") und die Adresse bei
    hornetdmarc.com ("beim Dienstleister anfordern") und nennt die CNAME-Delegation;
    dortmund-beach begründet den Betreiber-Satz mit SPF `mx`.
  - N8: Vorlagezertifikat nur bei gleichem SAN-Satz, gleichem Aussteller, gleicher
    Zuständigkeit und testssl mit vollständiger Kette: castenow mailstore nur 195.50.179.4,
    huendgen ohne Hinweis (Sectigo-Wildcard der Exchange-Linie). "sofern nicht erneuert" in
    Hebel, Effekt und Auswirkung.
  - N9: "fehlerbereinigt ab" aus `fixed_in`, "neueste laut wpscan" aus `latest_version`,
    "Verzeichnis von wpscan veraltet" bei fixed_in über latest (Slider Revolution 6.7.38 zu
    6.7.35); Produktnamen aus `PRODUCT_NAMES` in Betroffen und Plan (Soll-Listen dortmund-beach
    mit "BeTheme", "Slider Revolution"); `SoftwareFact.child_of`, BeTheme Child "nicht
    bestimmbar (eigenes Kindtheme, Elterntheme BeTheme, siehe VS-…)". Plakette in 3.1 nur
    "veraltet" oder "LTS", Anzahl, Zielversion und Datum in der Hinweisspalte; der
    Positivbefund zur Herstellerpflege sagt "(in Langzeitpflege bis 30.06.2028 laut Debian)"
    ohne zweite Klammer.
  - N10: Passivregel am selben Produkt nur als Portzusatz im ersten Satz und im Titel
    ("Verwaltungsoberfläche Plesk auf 443, 8443 und laut Passivquelle 8880", "VRFY angeboten
    (laut EHLO) auf 465, 587 und laut Passivquelle 25"), eine Stufe, eine Verifikation;
    Baustein-Schlüssel `key` für die Versionspreisgabe (junkerwerk VS-014 eine Auswirkung),
    X-FEServer unter "interner Name"; `service_cert_expired` nennt das Zertifikat einmal
    (Soll-Liste bergersysteme ohne Zertifikat je Port), "Mailclients" und "für die
    Maildienste" bei Mailports; castenow VS-001 Satzfolge der Auswirkung.
  - N11: Quelle je fremdem Namen (`SharedSystem.foreign_sources`), Satz "laut Passivquelle 2
    weitere Domains und laut Zertifikat 1 weitere Domain" (castenow .53) und "laut
    Passivquelle n weitere Domains" in `spf_authorizes_shared_host` (Soll-Listen junkerwerk,
    castenow). `secureserver.net` stand schon in `HOSTER_DOMAINS`; die "3" entstand aus
    tonausstrom.de (Zertifikat an 8000 und 8001). 8800 (Icecast) ohne Domainfakt: "die
    Zuordnung zu einer Domain ist nicht belegt", grau und nicht bewertet. Drittanbieter-Zeilen
    "(laut Namensauflösung und SPF)".
  - N12: Fundort in Anhang C ("an Nebenpfaden", "an der Sicherheitsabfrage"), Meldungen zu
    bewerteten Regeln am selben Host entfallen; ASP.NET-Version auch aus httpx (Soll-Listen
    castenow mail, mail2 und junkerwerk autodiscover mit X-AspNet-Version); Shodan-OS als zweite
    Quelle; Skript-Adressen (`gtm.js`, `fbevents.js`) und der Sitzungs-Cookie JSESSIONID aus
    redirect_probe als zweite Quelle (heuel GTM, Facebook Pixel, Java/Servlet jetzt in 3.1
    statt in Anhang C); Neos eine Zeile ("Neos", cms_fingerprint und httpx);
    `tls_weakness_reported` nur mit eigenem testssl-Lauf (entfällt an junkerwerk autodiscover,
    castenow mail und owa, heuel ose); URLhaus und SecurityTrails "(ohne Ergebnis)"; Anhang D
    "davon n gleiche Meldungen der Webanalyse zusammengeführt".
  - N13: "Protokolle und Verfahren nicht bewertet, Zertifikat aus dem Portscan"; Pfadsuche
    je Werkzeug (`PathSearchFact.tool_reasons`, `statistics`) mit Zeitlimit, fehlender
    Statistik und nie durchsuchter Anwendung; wafw00f-Zeitlimit in der Zeile "Zeitlimit der
    Prüfung überschritten" (huendgen 80.90.145.166, "Erkennung vorgelagerter Schutzsysteme"); E4-Zeile
    "Ergebnisse eigener Messungen liegen nicht vor; VS-… beruhen allein auf der
    Passivquelle"; ZAP mit Ursache und "ohne Meldungen" aus `CoverageFact.run_status`; kein
    "vollständig" bei Kurzlauf unter 60 Sekunden oder nur einem von mehreren VHosts
    (junkerwerk 217.243.248.28 jetzt teilweise); "abgebrochen, der Scanner vermutete in der
    Startseite (200) ein Abwehrmerkmal"; Ziel der aktiven Webanalyse nach Art der Antwort
    (junkerwerk cloud "einer Seite ohne eigenen Inhalt" mit Titel und Status statt "ohne
    Seiteninhalt (Status 200)", heuel edi "einer Fehlerseite", online "einer
    Sicherheitsabfrage"); Numerus bei einer AAAA-Adresse; Gate-Text
    `ipv6_ohne_inventar` "nicht im Scan-Inventar, im Bericht als ungeprüft ausgewiesen".
  - N14: Rollen aus SPF `a`, aktiv bestätigten Abruf- und Einlieferungsports ("Mailabruf und
    Einlieferung", mit SPF zusammengefasst "Mailabruf, Einlieferung und Versand laut SPF"),
    `db_exposed` ("Datenbanken erreichbar"), Passivpfad `/owa/` ("Mail-Webzugang laut
    Passivquelle") und Seitentitel weiterer Ports ("Anmeldeportal (Port 444)"), auch auf
    geteilten Systemen; `MAX_ROLES` 5. Die Rolle "Mailabruf und Einlieferung" erlaubt keine
    Mail-Rollenwörter (offene Abrufports belegen keine Postfächer des Unternehmens, spec/09
    Q2 lumbeck-wolter). Abweichung zu spec/11: dortmund-beach bekommt keine Rolle
    "Datenbanken erreichbar", der Server hat keinen Datenbankport (VS-001 ist Webmin und
    froxlor).
  - N15: Referrer-Policy nach der heutigen Voreinstellung; 587 "Anmeldung erst nach
    STARTTLS"; A.1-Ausnahme nur `cert_expiring`, abgelaufene Dienstzertifikate mit eigenem
    Satz; 53 "DNS", tcpwrapped "Dienst ohne Antwort"; "Hosteintrag aktualisiert am" für den
    Shodan-Hosteintrag, "gesehen am" nur mit Zeitstempel des Dienstes (Soll-Listen der
    Passivregeln, Drift-Test `_LAUF_ZUSATZ`); Numerus; eine Klammer für Titelzusatz und
    Betreiber ("(TLS erzwungen; beim Hoster Hetzner Online GmbH)"); kein doppeltes Präfix im
    Plan; Plattformzusatz hinter der Adresse; E25 (Vorschlag umgesetzt): Anmeldenamen nur als
    Anzahl und Fundweg (Soll-Listen dortmund-beach und castenow), Gate
    `anmeldename_im_kundentext`; Cloudflare-Ports mit Banner-Kennung, 8880 Plesk; ProFTPD und
    mod_sftp eine Zeile; Etracker wie Cookiebot ausgeblendet; heuel 4433 unter "Beobachtungen
    ohne Regeltreffer" mit dem Antwortkopf `Server: xxxx`; Satz zur CDN-Kante bei
    bergersysteme 198.202.211.1.
    Abweichung zu spec/11: bergersysteme 2052 und 2095 bleiben "unbekannt", weil der
    Shodan-Export die Banner vor dem Server-Header abschneidet (`Cache-Control: private,
    max-age=0, no-store, no-cache,`); nur 2053 und 2096 tragen "Server: cloudflare".
  - Zahlen je Auftrag (Befunde, Positivbefunde, Planzeilen, Anhangzeilen, Einschränkungen,
    Hosts in 2.1): dortmund-beach 1fbc92b9 14->14, 5->5, 19->19, 14->14, 6->7, 1->1;
    lumbeck-wolter c3d5724c 5->5, 7->7, 8->8, 0->0, 6->6, 2->2; junkerwerk 31d67a02 16->16,
    7->7, 21->21, 6->5, 10->12, 3->3; huendgen 3cf01f8d 12->12, 8->7, 16->17, 2->1, 8->10,
    2->2; bergersysteme 68d59573 12->12, 6->6, 15->15, 1->1, 16->16, 7->7; castenow 1f8bc977
    18->18, 13->13, 20->21, 18->14, 14->17, 7->7; heuel 2e56abe1 9->9, 7->7, 15->15, 17->12,
    15->17, 6->6. Übrige: 0bf16342 17->17, 3->3, 28->28, 9->7, 15->17; 14272c00 14->14, 5->5,
    19->19, 14->14, 6->7; 176db198 8->7, 5->5, 15->14, 22->20, 13->15 (HSTS an der Abwehrseite
    von online entfällt, N2); 2572eebc 17->17, 6->6, 28->28, 4->4, 17->18; 2d2d4f39 27->27,
    7->7, 28->29, 17->15, 19->22; 45bb234c unverändert; 4e6b6883 27->27, 6->6, 28->29, 17->15,
    18->21; 57b3ac85 unverändert; 75338c97 unverändert; 860d0d5a 16->16, 7->7, 21->21, 6->5,
    10->12; a6df9d9d, ae8d1d70 und fb13a98f unverändert; f77ccff2 27->27, 8->8, 28->29,
    15->14, 14->16. Gesamtbewertung überall unverändert.
  - Seitenerwartung (ops-update-pages, MR-Pipeline 3225): Scan-Runde 1f8bc977 33->35,
    2e56abe1 23->24, 3cf01f8d 23->24, c3d5724c 16->17 (Einschränkungszeilen, Rollen, weitere
    Adressen laut DNS); 1fbc92b9, 31d67a02 und 68d59573 gleich. Übrige 176db198 23->22,
    4e6b6883 44->47, 57b3ac85 16->17, 860d0d5a 30->31, f77ccff2 44->45, fb13a98f 26->27.
    Halbleer vor einem Kapitelanfang: 2d2d4f39 Seite 30 wie bisher, neu f77ccff2 Seite 30
    (Merkposten S7).

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
| Q8 | Header an Weiterleitung, Fehler- oder Challenge-Seite | Bericht erledigt S6b-3 (R1, 15 Markierungen aufgelöst); drei `hsts_missing` offen, Scanner (S6c) |
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
| Teil 2 DB | froxlor auf 443 ueber die IP (in spec/09 unsicher, ohne Regel) | erledigt Nachtrag 2 S6b-2 nach Entscheidung DC 26.09. (`panel_title`, kritisch auf dem System des Kunden) |
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

## Abgleich spec/10 nach S6b-3

Jede Aussage aus spec/10 Teil 1 und Teil 2 mit ihrem Stand. "Erledigt" nennt Stelle und Test,
"offen" den Grund und die Session. Die Aussagen gelten den sieben Aufträgen der Scan-Runde.

| Stelle | Aussage | Stand |
|---|---|---|
| R1 | Header-Regeln an 3xx, 4xx und Challenge | erledigt (Katalog `not_testable_when`, `test_facts_s6b3::test_keine_endseite`, Soll-Listen) |
| R1 | Endantwort aus redirect_probe, wpscan, ZAP | erledigt (`http_headers.measure`, `test_jw_outlook_endseite_aus_redirect_probe`) |
| R1 | Status und `location` im Nachweis | erledigt (Nachweis "Antwort: 302 · weitergeleitet auf") |
| R1 | `csp_weak` nach script-src und style-src | erledigt (`csp_weak_pass_style_nonce`) |
| R1 | header_check folgt Weiterleitungen, doppelte Header zusammenführen | offen, Scanner (S6c) |
| R2 | Texte je fehlendem Header, Permissions-Policy allein niedrig, Gate | erledigt (Text-Fixtures, `header_nicht_fehlend`) |
| R2 | Wildcard-Satz ohne Fakt | erledigt (`wildcard_directives`) |
| R3 | TLS nur 443 mit SNI, übrige Ports als Zeile | erledigt (`coverage.tls_untested_ports`, `test_s6b1::test_tls_teilweise_nur_fuer_ungepruefte_ports`) |
| R3 | aktive Webanalyse nur mit echtem Inhalt, ZAP ohne Meldungen teilweise | erledigt (`coverage._zap_active_state`) |
| R3 | leere nmap-Ausgabe "ohne Antwort" | erledigt (`test_ohne_hostbericht_ohne_antwort`) |
| R3 | Posture "teilweise geprüft" | erledigt (`chapters._result_state`) |
| R3 | abgelaufenes Zertifikat an Mailports beim Hoster | erledigt (`service_cert_expired`, `test_bs_plesk_mailports_mit_abgelaufenem_zertifikat`) |
| R3 | Werkzeugläufe ohne skipped und `ai_*` | erledigt (`report_data._counts`) |
| R3 | testssl je Port mit `--starttls` | offen, Scanner (S6c) |
| R4 | testssl je IP:Port an alle VHosts, Zertifikat über SAN und Fingerabdruck | erledigt (`test_testssl_gilt_fuer_alle_vhosts_eines_ports`) |
| R4 | `blocked` nur mit belegter Sperre, kein Anhang-E-Satz | erledigt (`test_bs_198_202_211_1_ohne_sperre`) |
| R4 | "Daten reichen nicht aus" neben Messung, Gate | erledigt (`families.py`, `einschraenkung_widerspricht_befund`) |
| R4 | Header aus testssl (castenow bitwarden) | erledigt (`test_ca_bitwarden_ueber_testssl`) |
| R4 | Parkname dortmund-beach pflege | erledigt (`parked_name`) |
| R4 | heuel 217.72.203.132 Posture | erledigt (unauffällig; nur die Kette von www ist ungeprüft, eigenes Zertifikat) |
| R5 | Zeile "Gefunden, nicht geprüft", Phase 0 "n von m", Gate-Warnung | erledigt (`test_gefundene_namen`, `namen_nicht_geprueft`) |
| R5 | Discovery-Parser (erstes Feld, Teilausgabe) | offen, Scanner (S6c); Auslieferung nach Nachscan (DC) |
| R6 | Cipher-Positiv nur ohne CBC | erledigt (`test_ca_cbc_angeboten`, Soll-Listen) |
| R6 | Reputation mit Plattform- und CDN-Adressen | erledigt (`bundles.reputation_reported`, heuel Kapitel 3) |
| R6 | URLhaus `no_data` | erledigt (`test_urlhaus_ohne_daten_ist_kein_negativergebnis`) |
| R6 | Kategorie B grau, Herstellerpflege mit Quelle | erledigt (castenow, heuel grau; lumbeck-wolter, junkerwerk grün mit Debian 12 LTS und Quelle) |
| R6 | Zonentransfer je Domain | erledigt (`test_zonentransfer_je_domain`) |
| R6 | RDP/SMB "außer" nur mit Fakt | erledigt (Entscheidung DC 2, `test_bundles`) |
| R6 | Positivbefunde beim Hoster, sechs Namen | erledigt (`operator_labels`, `test_viele_hosts_ohne_rdp_und_smb_ohne_ausser`) |
| R7 | POP3 TLS-Zwang, Gate | erledigt (`test_pop3_ohne_user_und_sasl_vor_stls`, `positiv_widerspricht_befund`) |
| R8 | Posture aus Regelergebnis, DANE entfällt, Gate | erledigt (`posture_widerspricht_befund`) |
| R9 | Passivtexte, Kennung, Dienste ohne Kennung, Backport, HSTS, mail_plaintext, X-FEServer, Postfächer, Rollentexte | erledigt (Text-Fixtures, `service_unidentified`, `roles.py`) |
| R10 | E5 je Adresse, Gate | erledigt (`test_e5_zeile_je_adresse`) |
| R11 | Plan je Regel und Stufe, Effekt der Stufe, Hebel | erledigt (`test_jeder_befund_steht_genau_einmal_im_plan`) |
| R12 | Zusagen, Gate | erledigt (`zusage_im_kundentext`) |
| R13 | Kundenkontext im Export mit Quelle | erledigt (`findings_data.customer_context`, `facts.context`) |
| R13 | Zahlen ohne Quelle, Betriebsform, MFA, Gate | erledigt (`prose._kunde`, `gate.context_claims`) |
| R13 | "Polyethylen-Schaum" gegen Rohdaten (junkerwerk) | offen: Branchentext der Recherche; Prosa entsteht beim requeue, Prüfung im Gegenlesen spec/11 |
| R14 | Übersetzungstabelle, Capabilities, Kürzung, Datum, MariaDB, A.3, Kennzahlen | erledigt (`werkzeug_zeile`, `test_cve_ohne_a3_greift`) |
| R15 | ZAP-Titel, Anzahl, Konfidenz, Low/Medium im Anhang, Spaltenbreite | erledigt (`tables.ZAP_TITLES`, `uncovered_zap_messages`) |
| R15 | `top_alerts` im Export vollständig mit Konfidenz; "CSP: Wildcard Directive" fehlt in den Daten | offen, Scanner und Export (S6c) |
| R16 | Rechtsform mit Bindestrich, "laut RIPE" | erledigt |
| R16 | Kurznamen huendgen, bergersysteme, heuel | offen, Claude nach dem Merge (Admin-API, E10) |
| R17 | Fremddomains | erledigt (`operators.sentence`) |
| R18 | absolutes Datum, Berichtstag, Gate-Warnung | erledigt (`test_frist_vor_berichtsdatum_castenow_mailstore`) |
| R18 | Prozess E12 | offen, DC |
| R19 | VRFY, XML-RPC, Anmeldung über HTTP, SPF geteilt, Version beim Betreiber, Konfidenz mittel, unprocessed | erledigt |
| R19 | XML-RPC bei castenow | offen: kein Fakt in den Rohdaten (wpscan meldet dort kein xmlrpc) |
| R19 | AUTH vor STARTTLS als Regel | offen, S6c-Fakt (Beobachtung ohne Regel bis dahin) |
| R20 | Darstellung | offen, S7 |
| E13 | Erneuerungsverlauf aus CT-Logs | erledigt (`test_erneuerungsverlauf_aus_crtsh`, Nachweiszeile) |
| Teil 2 DB | Technikzeilen Slider Revolution und BeTheme doppelt, Webmin und froxlor fehlen | offen, S7 (Technikzeilen, Alias-Tabelle) |
| Teil 2 DB | WordPress "Lifecycle prüfen" neben "aktuell"; Nachweis VS-004 nach Schwere, Zielversion | offen, S7 |
| Teil 2 DB | Eingangs-Mailserver und DMARC-`rua` fremd, E5-Datum `last_update` | offen, S6c (Fakten) |
| Teil 2 DB | Service-Karte 30000 grün trotz VS-003; Dateiname `v3` gegen "Version 1" | offen, S7 |
| Teil 2 LW | R7, R10, R6, R12, R13, R14, R17 | erledigt wie oben; Kennzahl Werkzeugläufe ohne übersprungene erledigt |
| Teil 2 JW | archiv (R5), X-FEServer (R9) | erledigt |
| Teil 2 JW | `tech_profiles[0]` intern mit Exchange-Build und `aiStrategy` | offen, Dashboard und Admin (nicht PDF), nicht Teil von S6b-3 |
| Teil 2 JW | Service-Karte .130 grün ohne Tiefenprüfung, 4433 grau; SonicWall-Datum; "Von der Scan-Steuerung übersprungen" für .28 | offen, S7 und S6c |
| Teil 2 JW | RDP/SMB für .28 und .29 | geklärt, unverändert: die IPv6-Adresse ist nicht geprüft (`target_invalid_ipv6`, Issue #8), nicht prüfbar zählt nicht als bestanden (S6, spec/08 Punkt 7); Soll-Liste P01 `positives_unterdrueckt` |
| Teil 2 JW | junkerwerk.hu ohne Hostsuche, "Tiefenprüfung (7 Hostnamen)", P03 ohne .hu, LUCKY13 | offen, S6c und S7 |
| Teil 2 HE | Backport-Text (R9), 444 (R9), X-FEServer (R9), Erneuerungshistorie (E13) | erledigt |
| Teil 2 HE | zweite Plattformadresse, 8443 Plattformdienst, stille Ausfälle, `/ecp` | offen, S6c |
| Teil 2 HE | Cookiebot als Serversoftware, A100 ROW ohne Amazon | offen, S7 |
| Teil 2 BS | R4, R3, R9, R5, R1 | erledigt wie oben |
| Teil 2 BS | VS-003 IIS auf E4-Host als Gelb im Patch-Status | offen, S7 (Rolle "Mail-Webzugang laut Passivquelle") |
| Teil 2 BS | IPv6, Cloudflare doppelt, jQuery ohne Version, CDN-Standardports | offen, S6c und S7 |
| Teil 2 BS | 79.140.188.181 "keine Antwort" | erledigt (R3) |
| Teil 2 CA | R1, R2, R6, R4, R18, R9, R13, R5, R17 | erledigt wie oben |
| Teil 2 CA | VS-003 Empfehlung mit dem erneuerten Wildcard-Zertifikat, Netzbetreiber Vodafone | offen, S7 |
| Teil 2 CA | SPF `a` auf geteilten Agenturserver | erledigt (`spf_authorizes_shared_host`) |
| Teil 2 CA | Fremddienste in `zap_extra_urls`, stille Ausfälle, testssl umfrage an .123, BREACH an 301 | offen, S6c |
| Teil 2 HL | R6, R1, R3, R4, R5, R7, R10, R16 | erledigt wie oben; Kurzname nach dem Merge |
| Teil 2 HL | 8443 ohne Dienstantwort | erledigt (`service_unidentified`) |
| Teil 2 HL | VS-004 ohne Host im Titel doppelt auf Seite 2 | nicht mehr sichtbar (Kategorie A nennt zuerst den Dienst ohne Kennung, der zweite Titel trägt "beim Hoster"); Host im Titel offen, S7 |
| Teil 2 HL | Java/Servlet an 213.133.104.51, Neos CMS im Anhang, SRI auf `latest`, Fremdbewertungszeile | offen, S7 |
| Teil 2 HL | help-ev.de "auf derselben Adresse" | erledigt (R17) |
| Teil 2 HL | "(insgesamt 4 Einträge)" mit drei Namen | erledigt (R6) |

## Abgleich spec/11 nach S6b-4

Jede Aussage aus spec/11 Teil 1 (Reste), Teil 2, Teil 3 und Teil 5 mit ihrem Stand. "Erledigt"
nennt Stelle und Test (Tests ohne Pfad in `tests/v3/test_s6b4.py`, `tests/test_facts_s6b4.py`,
`tests/gate/test_v3_checks_s6b4.py`), "offen" den Grund und die Session. Die Aussagen gelten
den sieben Aufträgen der Scan-Runde; Golden-Stichtag 19.09.2026, Fälle mit Berichtsdatum am
27.09.2026.

| Stelle | Aussage | Stand |
|---|---|---|
| R1 | Nachweisquelle `header_check` bei Werten aus redirect_probe oder ZAP | erledigt (T3) |
| R1 | HL VS-003 HSTS an der Vercel-429 | erledigt (T4, Soll-Liste heuel-0923) |
| R1 | HL VS-002 "bewertet an login.seam" ohne Messung dort | erledigt (T3, Zeile je Werkzeuglauf) |
| R3 | Messung an zweiter Adresse | erledigt (T7) |
| R3 | JW .28 "vollständig" bei 10 s ZAP | offen: die Laufzeit ist kein Fakt für die Tiefe; ZAP-Konfidenz und -Umfang kommen mit S6c |
| R3 | CA umfrage "aktive Webanalyse vollständig" an einer 301 | erledigt ("nur an …, einer Weiterleitung auf einen anderen Namen (Status 301)") |
| R3 | SNI-Listen aus fremden VHosts, BS Scan-Steuerung | erledigt (T13) |
| R4 | CA bitwarden "Webdienst antwortete nicht" | erledigt (Zeile "Erste Header-Messung ohne Antwort; Seite über die TLS-Prüfung bewertet") |
| R4 | HL Vertrauenskette nennt heuel.com mit | erledigt (`test_vertrauenskette_nur_fuer_den_eigenen_namen`) |
| R4 | BS E4-Hosts "der Portscan fand keinen offenen Port" | erledigt ("der Portscan erhielt keine Antwort") |
| R5 | Numerus bei einem gefundenen Namen (JW) | erledigt (`coverage` Zeile "Gefunden, nicht geprüft") |
| R5 | LW Hinweiskasten ohne die ungeprüften Namen | erledigt (`test_lw_nachweis_und_hinweiskasten`) |
| R5 | eset im SPF-Netz des Kunden | offen: Nachscan nach E19 (S6c, zweite Scan-Runde) |
| R6 | JW Kategorie B grün ohne Quelle | erledigt (T11) |
| R6 | CDN-Adressen fehlen in der Reputationsliste (CA, BS) | erledigt (`ip_reputation` ohne `applicable_when`, `test_bs_zertifikatsliste_einmal_und_reputation_mit_cdn`) |
| R6 | P05 "SPF vorhanden" neben Softfail (DB, LW) | erledigt (`spf_missing` positiv nur bei `-all` oder `redirect=`) |
| R6 | Zonentransfer-Positiv ohne AXFR-Rohausgabe | offen: Rohausgabe im Export (S6c) |
| R7 | LW "SASL" ohne "(leer)" | erledigt |
| R8 | CA SPF softfail, Transport unauffällig, HL Header an der 429, Gate | erledigt (T16) |
| R8 | HL "✔ 217.72.203.132" neben der Vertrauensketten-Einschränkung | erledigt (Zertifikatsregeln ziehen die Zeile nur auf Handlungsbedarf, `pulls`; die Kette steht als Einschränkung) |
| R9 | 993 und 995 "nicht identifiziert" | erledigt (T1) |
| R9 | HSTS-Titelbaustein ohne Variante, HSTS in zwei Regeln (JW VS-005 und VS-009) | erledigt (T4; HSTS-Empfehlung aus `tls_legacy_protocols` entfernt) |
| R9 | Auswirkungs-Dubletten `admin_panel_hoster` und `admin_service_exposed_passive` | erledigt (T12) |
| R9 | CA ubb-wiki "Redaktionszugang" | erledigt (Rolle "Anmeldung zur Website") |
| R9 | HE VS-011 erster Satz führt X-FEServer unter "Version" | offen, S7: die Betroffenenliste steht je Befund, nicht je Aussage |
| R10 | JW .28 mit dem Datum von .130 | erledigt (T6) |
| R11 | Header-Planzeile je Befund, VRFY zwei Zeilen, Hebel 1 und 2 aus einem Befund, DMARC ohne `rua` | erledigt (T12) |
| R13 | "Unternehmensnetz" bei DB und BS, MFA ohne Bedingung, "Formulareingaben" ohne Webanalyse | erledigt (T10) |
| R13 | Firmennamen mit Quelle `recherche` | Gate-Warnung erledigt (E23); Namen setzt Claude nach dem Merge (Admin-API) |
| R14 | `Webabruf · argument:host_inventory` | erledigt (Nachweis nennt `phase0/host_inventory.json`) |
| R14 | "Capabilities flags: 65534 Some (Auszug)" | offen, S7 (Kürzung an Wortgrenze, der Rest des nmap-Skripts ist abgeschnitten) |
| R14 | `AUTH=CRAM-MD5A0001` (BS, CA) | erledigt (Antwortmarke nach Ziffer) |
| R14 | rohe Quellennamen in 3.1 (`cms_fingerprint`, `redirect_probe`, `zap_spider`) | offen, S7 (Anzeigenamen der Quellen) |
| R14 | "Keine Fremdbewertung" trotz wpscan (CA) und ohne .130 (JW) | erledigt (T13) |
| R14 | BEAST-Rohtext englisch (JW) | erledigt für das Urteil ("laut testssl vermutlich abgeschwächt"); die Ausgabezeile bleibt wörtlich |
| R14 | roher nmap-Rest `10000/tcp open snet-sensor-mgmt`, `1000/tcp open cadlock` | offen, S7 (Werkzeugzeile unter der Detailzeile) |
| R15 | BREACH und LUCKY13 mit Sammelsatz, ZAP-Unterregeln unter einem Titel | offen, S7 |
| R15 | "Konfidenz niedrig" und Anzahlen | offen, S6c (Export) |
| R15 | "ohne zweite Quelle" bei Skript-URLs und JW Windows | erledigt (T15) |
| R15 | X-AspNet-Version doppelt bewertet und "nicht eingeflossen" (JW) | offen, S7 |
| R16 | "laut RIPE" | erledigt (T2, E17) |
| R17 | Zählung mit your-server.de, Fremdnamen in Nachweisen | erledigt (T9) |
| R18 | CA VS-003 widersprüchlich, HE VS-004 ohne Hinweis, Berichtsdatum vom Vortag | erledigt (T14, T5) |
| R19 | DB VS-014 Nachweis, VS-012 "beantwortet", liesmich.html, Ultimate Member, 993/995 | erledigt (T3, T12, Teil 3, T15, T1) |
| R20 | Darstellung | offen, S7 |
| T1 | Kennung aus Capabilities, `smtp-commands`, Banner und Shodan-Modul | erledigt (`test_kennung_aus_protokollskript_und_banner`, `test_imaps_und_pop3s_mit_kennung_statt_nicht_identifiziert`) |
| T1 | "nicht identifiziert" nur mit Regel, Farbe nach Ampel | erledigt (`test_nicht_identifiziert_nur_mit_regel_und_nach_ampel`) |
| T1 | "außerhalb des geprüften Portbereichs" | erledigt (`test_passivport_ausserhalb_des_portbereichs`) |
| T1 | `-sV --version-all` für `?`-Ports | offen, Scanner (S6c) |
| T2 | "laut AbuseIPDB", Alias Hetzner, Anschlussbetreiber | erledigt (`test_netzbetreiber_in_2_1`) |
| T2 | RDAP als Fakt | offen, Scanner (S6c, #35) |
| T3 | Nachweis je Werkzeuglauf, "bewertet an der Endseite" nur bei Endantwort | erledigt (`evidence._http`) |
| T3 | XML-RPC mit wpscan-Beleg, VRFY in der EHLO-Liste, Gate | erledigt (`nachweis_ohne_regelfakt`) |
| T4 | HSTS nicht an 4xx, 429, Challenge; erste echte Antwort aus redirect_probe | erledigt (`build._hsts_measured`, Soll-Listen) |
| T4 | Titel je Variante, Verifikation `max-age` über null | erledigt (`test_hsts_titel_je_variante`, Text-Fixtures) |
| T4 | HSTS in einer Regel, Positiv je Header (E20) | erledigt (`PER_RULE_POSITIVE_BUNDLES`) |
| T4 | Gate auf dieselbe Messung | erledigt (`test_hsts_neben_header_an_der_sicherheitsabfrage_greift`) |
| T5 | Berichtsdatum nach E15, Erzeugungsdatum in der Fußzeile | erledigt (`test_berichtsdatum_in_berliner_zeit`, `test_worker_berichtsdatum.py`) |
| T6 | E5-Datum je Adresse | erledigt (`test_e5_datum_je_adresse`) |
| T6 | Gesamtbewertungsregel dokumentiert und in A.1 | erledigt (`levels.OVERALL_RULE`, Katalog-Changelog 2026-09-27.1); Regel unverändert, siehe E16 |
| T7 | Messadresse je Fakt, Zeile DNS-Rotation | erledigt (`test_tls_messadresse_je_lauf`, `test_dns_rotation_als_einschraenkung`) |
| T7 | AAAA ins Inventar, Gate-Warnung | erledigt im Bericht (`test_aaaa_im_system_und_in_der_zaehlung`, `ipv6_ohne_inventar`); aktive Prüfung über IPv6 offen, Scanner (S6c) |
| T7 | Werkzeuge an die Inventar-IP binden | offen, Scanner (S6c) |
| T8 | Einschränkungszeile aus feroxbuster- und ffuf-Statistik, "übersprungen" nur bei `ai_skip` beider | erledigt (`test_urteil_der_pfadsuche`, `test_pfadsuche_mit_urteil`) |
| T8 | Pfadsuche auf die `final_url` | offen, Scanner (S6c) |
| T9 | Zählung, Wortlaut, Betreiber aus rDNS, Fremdnamen maskiert | erledigt (`test_zaehlung_und_wortlaut_ohne_andere_kunden`, `test_fremdnamen_im_bericht_maskiert`) |
| T9 | "Server der Webagentur planwerk6.de" | teilweise: "Server von planwerk6.de im Rechenzentrum Hetzner Online GmbH"; "Webagentur" ist aus den Rohdaten nicht belegt |
| T9 | Vertragsform LW, JW, HL | offen, DC mit dem Kunden (E18) |
| T10 | Sätze aus getroffenen Kategorien, Rollen- und Auswirkungstexte am Fakt, MFA bedingt | erledigt (`test_kategorien_nur_aus_getroffenen_regeln`, `test_rollentexte_am_fakt`) |
| T11 | Lebenszyklusquelle sichtbar, "in Langzeitpflege bis" | erledigt (`test_langzeitpflege_mit_quelle_in_3_1`) |
| T11 | E22 für BS | erledigt (`test_passivbefund_auf_e4_host_als_blauer_hinweis`) |
| T12 | Dubletten, Hebel je Befund, VRFY, Header-Planzeile, DMARC ohne `rua`, E4-Wortlaut | erledigt (`test_hebel_je_befund_hoechstens_einmal` und folgende) |
| T13 | Sammelbegriffe, Ursache aus der Steuerung, SNI, Fremdbewertungszeile | erledigt (`test_ursache_aus_der_scan_steuerung`, `test_fremdbewertungszeile_nur_mit_version_ohne_abgleich`) |
| T14 | E13 je Linie mit erwartetem Datum | erledigt (`test_erneuerungslinie_je_aussteller`, `test_erneuerungsmuster_im_nachweis`) |
| T14 | `cert_expiring` "am Berichtsdatum abgelaufen", gültiges Zertifikat an .4 und .6 | erledigt (`test_am_berichtsdatum_abgelaufen_sofern_nicht_erneuert`) |
| T14 | Hinweis bei unterschrittener Grenze | erledigt als Hinweis im Befund; die Stufe bleibt nach E2 am Scantag (`test_stufenwechsel_bis_zum_berichtsdatum`) |
| T15 | Alias, Patch-Status aus wpscan, Skript-URLs, Fremddienste | erledigt (`test_eine_zeile_je_produkt_mit_wpscan_status`, `test_fremde_und_eingebundene_dienste_nicht_in_3_1`) |
| T16 | Posture je Regel, Service-Karte, Gate auf alle Karten | erledigt (`test_posture_aus_denselben_regeln`, `test_service_karte_ueber_den_softwareport`, `test_softfail_neben_gelbem_befund_greift`) |
| Teil 3 DB | Dubletten in 3.1, WordPress "aktuell" | erledigt (T15) |
| Teil 3 DB | Webmin und froxlor fehlen in 3.1 | offen, S7: ohne Version keine Technikzeile nach der Regel vom 26.09.; beide stehen als Befund VS-001 |
| Teil 3 DB | VS-004 alle CVE, Zielversionen, Plural | erledigt (`test_wordpress_erweiterungen_alle_cves_und_zielversionen`) |
| Teil 3 DB | MX und `rua` beim Dienstleister, P05 nur bei `-all` | erledigt (`test_db_dmarc_beim_dienstleister_und_p05_nur_bei_hardfail`) |
| Teil 3 DB | E5-Datum `last_update`, 30000 grün | erledigt (T6, T16) |
| Teil 3 DB | VS-014, VS-012, pflege-Zeile | erledigt (T3, T12, T13) |
| Teil 3 DB | Anhang C URLhaus trotz `no_data`, VS-010 "interne Servernamen", Anhang D "Doppelmeldungen" | offen, S7 |
| Teil 3 DB | Betriebsform "kunde" für den Hetzner-Server | offen, DC (E23, Kundenkontext) |
| Teil 3 LW | IPv6, Zählung, 993/995/Exim/4190, Kategorien, Hinweiskasten, LTS, SASL, MariaDB | erledigt (T7, T9, T1, T10, Teil 3, T11) |
| Teil 3 LW | P06 "SPF und DKIM hinterlegt" neben Softfail | erledigt (Positivbefund nur noch "DKIM vorhanden") |
| Teil 3 LW | VS-004 Auswirkung nennt DANE neben "DANE entfällt"; Posture "Zertifikate nicht prüfbar" trotz nmap-Mailport-Zertifikaten; autodiscover doppelt; Kürzung im Wort | offen, S7 |
| Teil 3 JW | VS-002 Datum und Portbereich, VS-010 Variante, P04 .hu und Selektoren, BEAST, Posture Verwaiste Einträge | erledigt (`test_jw_*`) |
| Teil 3 JW | Service-Karte 4433 grau trotz Gelb | erledigt (Passivport mit Befund nach Ampel, `test_jw_sonicwall_mit_datum_und_portbereich`) |
| Teil 3 JW | RDP/SMB-Positiv für .28 und .29 | erledigt (nicht erreichbare IPv6-Adresse hebt ihn nicht mehr auf) |
| Teil 3 JW | `tech_profiles[0]` intern, junkerwerk.hu ohne Hostsuche, "Tiefenprüfung (7 Hostnamen)", LUCKY13 ohne team | offen, S6c und S7 |
| Teil 3 JW | X-AspNet-Version doppelt, SPF `a` für .hu nie aufgelöst | offen, S7 und S6c |
| Teil 3 HE | 52.59.120.70, 8443 Plattformhinweis, Hebelreihung, Cookiebot, A100 ROW mit Amazon | erledigt (T7, `test_he_8443_als_plattformhinweis`, `test_he_hebelreihung_lebenszyklus_vor_zweck`, T15, T2) |
| Teil 3 HE | stille Ausfälle, `/ecp` und `/EWS` | Einschränkung erledigt (T8); Pfade offen, Scanner (S6c) |
| Teil 3 HE | P01 bis P03 "wie drei Orte", "Keine Fremdbewertung" für .23 ohne Version | erledigt für die Fremdbewertungszeile (T13); P01 bis P03 offen, S7 |
| Teil 3 HE | 444 blau ohne Rolle, `Outlook Web App:15.2.1748` roh, Anhang D Satz | offen, S7 |
| Teil 3 BS | IIS E4 (E22), Kategorien, IPv6, Cloudflare, jQuery, Scan-Steuerung, SNI, Pfadsuche, HSTS-Positiv www, Netzbetreiber, VS-001 Dubletten, VS-003 einmal und ohne 587, Reputation mit CDN | erledigt |
| Teil 3 BS | CDN-Standardports 2052 bis 2096 und 8880 ohne Hinweis auf die Kante | offen, S7 |
| Teil 3 BS | "Formulareingaben" bei übersprungener Webanalyse | erledigt (T10) |
| Teil 3 CA | VS-003 mit Wildcard-Zertifikat, Vodafone, T8, T7, T9, T3, T12, T16, T15 | erledigt |
| Teil 3 CA | bitwarden (R4), ubb-wiki-Rolle, umfrage-Rolle, X-Powered-By an der Endseite, liesmich.html, VS-011 und VS-016 | erledigt (`test_ca_rollen_und_liesmich`, `test_fremde_dienste_im_zustaendigkeitskasten`) |
| Teil 3 CA | BREACH an der 301, drei OWA-Fotos, umfrage-Foto, Hinweiskasten "4 statt 3 Systeme", VS-003-Kopf am Seitenfuß | offen, S7 |
| Teil 3 CA | Vorabmeldung mailstore (E21) | offen, DC |
| Teil 3 HL | VS-003 an der 429, VS-002 Nachweis, 216.150.1.65, Vertrauenskette nur www, 993/995, Netzbetreiber, Rolle 20.79.218.75, Kategorien, HSTS-Titel, Pfadsuche, SNI, Bildunterschriften, Posture | erledigt |
| Teil 3 HL | VS-005 ohne Host im Titel, Java/Servlet an 213.133.104.51, Neos, SRI auf `latest`, Fremdbewertungszeile mit OpenSSH 9.2p1 | offen, S7 |
| Teil 3 HL | E5-Datum als Host-`last_update` | erledigt (T6, Zeitstempel des Dienstes) |
| Teil 3 HL | control.heuel.com "liegen nicht vor", Port-21-Zeile, P02 ohne "beim Hoster", CSP und Timestamp an online | offen, S7 |
| E15 | Berichtsdatum | erledigt (T5) |
| E16 | Gesamtbewertung | Regel benannt und in A.1, Changelog; der Vorschlag (HOCH auch bei Gelb In Kürze am Kundensystem) ist nicht umgesetzt, weil er huendgen auf HOCH höbe; offene Frage an DC |
| E17 | Netzbetreiber laut AbuseIPDB | erledigt (T2) |
| E18 | Zählung und Wortlaut | erledigt (T9); Vertragsform offen, DC |
| E19 | Nachscan | offen, zweite Scan-Runde nach S6c |
| E20 | HSTS-Positiv je Header | erledigt (T4) |
| E21 | Vorabmeldung CA mailstore | offen, DC |
| E22 | Passivbefunde auf E4-Hosts blau | erledigt (T11) |
| E23 | Firmenname aus der Recherche | Gate-Warnung erledigt; bestätigte Namen setzt Claude nach dem Merge |

## Abgleich spec/11 Teil 6 nach S6b-4n

Jede Aussage aus spec/11 Teil 6 (N1 bis N15, Regressionsstand, E23 bis E26) mit ihrem Stand.
"Erledigt" nennt den Test (ohne Pfad in `tests/v3/test_s6b4n.py`, `tests/test_facts_s6b4n.py`,
`tests/gate/test_v3_checks_s6b4n.py`), "offen" den Grund und die Session. Golden-Stichtag
19.09.2026, Fälle mit Berichtsdatum am 27.09.2026.

| Stelle | Aussage | Stand |
|---|---|---|
| N1 | HE www: CSP-Positiv bei `frame-ancestors 'self'` ohne Skriptregel | erledigt, Variante von `csp_missing` (`test_n1_csp_nur_frame_ancestors_ist_befund`, Fixture `csp_missing_fail_nur_frame_ancestors`, Text-Fixture `csp_missing`) |
| N1 | CA P08 nennt ubb-wiki (nur frame-ancestors) und www (Gelb `csp_weak`) | erledigt (`test_n1_csp_positiv_nicht_neben_csp_weak`) |
| N2 | CA P09 mailstore (400) und umfrage (301) neben "Endseite nicht bewertet" | erledigt nach E24, Messort im Positivbefund, HSTS nicht in der Zeile (`test_n2_hsts_positiv_mit_messort`, `test_n2_hsts_nicht_unter_endseite_nicht_bewertet`); Wortlaut "mit Status 301" statt "(301)", siehe Abweichungen |
| N2 | HL P06 online aus der ersten Antwort in redirect_probe | erledigt (`test_n2_hsts_nicht_an_der_sicherheitsabfrage`, `test_hsts_nie_an_der_sicherheitsabfrage`) |
| N2 | HL Anhang C "HSTS nicht gesetzt" an der Abwehrseite | erledigt, Fundort "an der Sicherheitsabfrage" (N12) |
| N2 | BS VS-007 "(+cdn.bergersysteme.com)" ohne Messung | erledigt (`test_n2_gruppenname_ohne_ungemessenen_alias`); gilt für alle Header-Gruppen |
| N3 | HL VS-002 "bewertet an der Endseite" mit den Headern der ersten Antwort | erledigt (`test_n3_ose_nicht_an_der_endseite_bewertet`, `test_hl_ose_ohne_endantwort`, Gate `test_endseite_ohne_endantwort_greift`) |
| N3 | HL online `server: Vercel` und `location` neben `final_url` www | erledigt, keine Endantwort, kein HSTS-Fakt (E24) |
| N3 | Gegenprobe JW und HE `logon.aspx` mit Endseiten-Headern | erledigt (`test_endantwort_nach_http_weiterleitung_bleibt`, `test_endseite_mit_endantwort_bleibt`) |
| N3 | CA VS-009 mail und mail2 nur XCTO fehlend, Referrer- und Permissions-Policy nicht gemessen | erledigt (`test_n3_ca_mail_nicht_gemessen_statt_fehlend`) |
| N3 | Scanner: redirect_probe exportiert die Header der Endantwort | offen, S6c (Scanner unberührt) |
| N4 | HL 213.133.104.51 "Webanwendung mit Anmeldung (dl, webportal)" | erledigt, Rolle "Weiterleitung auf ose.heuel.com" plus eigene Dienste (`test_n4_redirector_mit_eigenen_diensten`, `test_anmeldeform_nur_am_eigenen_host`) |
| N4 | HL Anhang C: Java/Servlet, GTM, Facebook Pixel am Weiterleitungshost | erledigt (`test_n4_technik_des_ziels_nicht_am_redirector`, `test_technik_des_weiterleitungsziels_nicht_am_redirector`) |
| N4 | JW `tech_profiles[0].cms "Microsoft Exchange"` am Hetzner-Host (nur Export) | erledigt für die Berichts- und Dashboard-Zeilen aus den Fakten (188.40.3.130 ohne Exchange); das Rohfeld `cms` im Scanner-Export ändert S6c |
| N4 | BS Scan-Steuerung `hosted-cms-webflow` auf dem Plesk-Server | erledigt im Bericht, Grund "wegen Weiterleitung auf die Webflow-Seite" (`test_n4_scan_steuerung_mit_grund`, `test_bs_plesk_server_ohne_webflow`); KI-Regelwahl nicht aus Weiterleitungszielen offen, S6c |
| N4 | Bildquellen nur aus Antworten desselben Hosts | erledigt (`test_n4_bild_nur_am_eigenen_host`) |
| N5 | 2.1 "vollständig" für HL 216.150.1.65, Posture "✔" an Inventaradressen, "✘ 18.197.248.23" | erledigt, "am Namen gemessen an <Adresse>" und Posture "am Namen gemessen (<Adresse>)"; Befund am Host bleibt Handlungsbedarf (`test_n5_posture_am_namen_gemessen`) |
| N5 | Anhang B, P02 und 3.1 unter der Inventaradresse | erledigt ("gemessen an <Adresse>", `test_n5_positiv_nennt_messadresse`) |
| N5 | HL 216.150.16.65 fehlt im Inventar | erledigt, Zeile "Weitere Adresse laut DNS, nicht geprüft" (`test_n5_weitere_adresse_laut_dns`, `test_weitere_adressen_mit_familie`); Entscheidung DC: alle zweiten A-Einträge |
| N5 | Rotationszeile um "Technologie-Erkennung (httpx)" | erledigt als "Webabruf und Technologie-Erkennung" ohne Werkzeugnamen (`test_n5_rotationszeile_mit_technologie_erkennung`) |
| N6 | LW Kategorie D grün ohne Messung | erledigt, grau "Nicht bewertbar" (`test_n6_kategorie_ohne_messung_grau`) |
| N6 | JW P06 junkerwerk.hu ohne AXFR-Lauf | Abweichung, Entscheidung DC 27.09.: das Tar enthält den Lauf für .hu, der Positivbefund bleibt mit Nachweis je Domain (`test_zonentransfer_mit_eigenem_lauf`, `test_n6_zonentransfer_je_domain_mit_eigenem_lauf`) |
| N6 | BS P06 Reputation mit der CDN-Kante (`lastReportedAt 2026-09-21`) | erledigt, `ip_reputation` auf CDN und Plattform nicht anwendbar, Abfragefenster 90 Tage (`test_n6_reputation_ohne_plattformadressen`, Fixtures `ip_reputation_na_plattform*`, `ip_reputation_pass_gemeldet_*`) |
| N6 | Gate "Positiv gegen Rohfakt" | erledigt, `positiv_ohne_rohfakt` (`test_positiv_ohne_rohfakt_greift_ohne_eigenen_axfr_lauf`, `test_positiv_ohne_bejahte_regel_greift`) |
| N7 | BS VS-005 zweite Adresse in der eigenen Domain, "beim Empfänger dieser Adresse anfordern" | erledigt (`test_n7_meldeadressen_je_domain_getrennt`, Text-Fixture `dmarc_none`) |
| N7 | Betreiber-Satz aus dem MX statt aus der Delegation oder SPF `mx` | erledigt (`test_dmarc_delegation_aus_cname`, `test_n7_betreibersatz_aus_spf_mx`) |
| N8 | HE VS-004 Vorlage aus der Sectigo-Linie | erledigt (`test_n8_kein_hinweis_aus_fremder_linie`, `test_keine_vorlage_aus_fremder_linie`) |
| N8 | CA VS-003 Vorlage 195.50.179.6 mit unvollständiger Kette | erledigt (`test_vorlage_nur_mit_vollstaendiger_kette`) |
| N8 | CA Hebel, Planeffekt und Auswirkung ohne "sofern nicht erneuert" | erledigt (`test_n8_sofern_nicht_erneuert_in_hebel_effekt_und_auswirkung`, Text-Fixture `cert_expiring`) |
| N9 | DB Slider Revolution "aktuell 6.7.35" gegen "mindestens 6.7.38" | erledigt (`test_n9_zielversion_getrennt_und_verzeichnis_veraltet`) |
| N9 | DB betheme-child "aktuell laut wpscan" ohne `latest_version` | erledigt (`test_n9_kindtheme_nicht_bestimmbar`, `test_kindtheme_mit_elterntheme`) |
| N9 | Plaketten überdrucken die Hinweisspalte (DB, LW, JW) | erledigt (`test_n9_plakette_nur_veraltet_oder_lts`) |
| N10 | BS VS-001 zwei Stufen, zwei Verifikationen, Titel wie zwei Oberflächen, "laut Zertifikat oder Passivquelle" im Plural | erledigt (`test_n10_plesk_ein_titelbaustein_und_eine_stufe`) |
| N10 | CA "Dazu gehören die eigenen Webseiten" am Hoster-Satz | erledigt (`test_n10_ca_satzfolge_der_auswirkung`) |
| N10 | DB VS-012 VRFY doppelt | erledigt (`test_n10_vrfy_eine_auswirkung_und_passivport_im_ersten_satz`) |
| N10 | JW VS-014 Auswirkung doppelt, X-FEServer unter "Version" | erledigt (`test_n10_x_feserver_nicht_unter_version`) |
| N10 | BS VS-003 Betroffenenliste zweimal, "Mail- und Dateiclients", Hebel "für alle TLS-Dienste" | erledigt (`test_n10_zertifikat_einmal_und_mailclients`, Text-Fixture `service_cert_expired`) |
| N11 | CA .53 "3 weitere Domains laut Passivquelle" | erledigt, Zählung je Quelle (`test_fremdnamen_je_quelle`, `test_n11_fremddomains_nach_quelle`); `secureserver.net` war schon Hoster |
| N11 | 8800 Icecast ohne Domainfakt als Fremddienst, 8000, 8001, 8800 grün | erledigt, grau, 8800 "Zuordnung nicht belegt" (`test_fremddienst_nur_mit_domainfakt`, `test_n11_fremddienste_grau_in_der_servicekarte`) |
| N11 | 2.1 .80 "geteiltes System beim Hoster" neben Hetzner, VS-006 "Server von planwerk6.de" | erledigt ("Server von planwerk6.de, laut Passivquelle geteilt"; `test_n11_betreiber_des_servers`) |
| N11 | "Microsoft 365" in der Spalte "laut AbuseIPDB" (LW, HL, CA) | erledigt ("(laut Namensauflösung und SPF)") |
| N12 | ZAP "HSTS nicht gesetzt" an robots.txt, sitemap.xml oder der Abwehrseite neben HSTS-Positiv | erledigt, Fundort in der Zeile |
| N12 | "CSP Header Not Set" neben P08 (CA) | erledigt (`test_n12_keine_anhangzeile_zu_bewerteter_regel`) |
| N12 | "X-AspNet-Version nicht eingeflossen" neben VS-014; CA mail und mail2 ohne Wert | erledigt (`test_aspnet_version_mit_quelle`) |
| N12 | "ohne zweite Quelle" trotz Shodan `os` (HE, CA), Skript-URLs und Cookies (HL) | erledigt (`test_betriebssystem_aus_shodan_als_zweite_quelle`, `test_skript_und_cookie_als_zweite_quelle`) |
| N12 | Neos "nicht in der Technologietabelle" (HL) | erledigt (`test_n12_neos_eine_zeile_mit_zweiter_quelle`) |
| N12 | LUCKY13 "3 Meldungen" mit autodiscover ohne eigenen testssl-Lauf (JW) | erledigt, 2 Meldungen an cloud und outlook; `tls_weakness_reported` nur mit eigenem Lauf (Fixture `tls_weakness_reported_pass_uebernommen`) |
| N12 | URLhaus und SecurityTrails als eingesetzt bei `no_data` | erledigt, "(ohne Ergebnis)" (`test_n12_werkzeuge_ohne_daten`) |
| N12 | Anhang D "Doppelmeldungen mehrerer Werkzeuge und Durchgänge" | erledigt (`test_n12_anhang_d_aus_zusammengefuehrten_meldungen`) |
| N13 | "Verschlüsselung und Zertifikat nicht bewertet" bei Zertifikat aus nmap (BS, HL Port 21) | erledigt (`test_n13_zertifikat_aus_dem_portscan`) |
| N13 | Pfadsuche-Zeile fehlt bei Timeout (DB, LW), bitwarden, ose, JW .29 | erledigt (`test_n13_pfadsuche_bei_zeitlimit`, Zeilen je Werkzeug) |
| N13 | wafw00f-Timeout ungenannt (HE) | erledigt, Zeile "Zeitlimit der Prüfung überschritten" mit "Erkennung vorgelagerter Schutzsysteme" |
| N13 | BS E4 "Ergebnisse zu diesen Hosts liegen deshalb nicht vor" neben Passivbefunden | erledigt (`test_n13_e4_ohne_eigene_messungen`) |
| N13 | HE ZAP ohne Ursache, "nur teilweise" bei `complete` und 0 Meldungen | erledigt (`test_n13_zap_ohne_meldungen`, `test_zap_active_mit_laufergebnis`) |
| N13 | JW "nur an cloud … ohne Seiteninhalt (Status 200)" unverständlich | erledigt (`test_n13_ziel_der_aktiven_webanalyse_nach_art_der_antwort`) |
| N13 | "vollständig" beim 10-Sekunden-Kurzlauf (JW .28, CA .4) | erledigt (`test_n13_kurzlauf_nicht_vollstaendig`) |
| N13 | BS www "abgebrochen (Abwehrmerkmal der Seite)" bei normaler 200 | erledigt (`test_n13_waf_vermutung_bei_normaler_startseite`) |
| N13 | IPv6 und E4-Adressen als geprüft gezählt (LW, BS) | erledigt, "davon m nur aus DNS oder ohne Antwort" (`test_n13_zaehlung_nur_aus_dns`) |
| N13 | Numerus "Die Adressen stehen als AAAA-Eintrag" bei einer | erledigt (`test_n13_zaehlung_nur_aus_dns`) |
| N13 | Gate-Text `ipv6_ohne_inventar` "nicht im Inventar" | erledigt (`test_ipv6_ohne_inventar_nur_ipv6_und_neuer_wortlaut`) |
| N14 | DB und JW ohne "E-Mail-Versand laut SPF" beziehungsweise "Mailabruf" | erledigt (`test_n14_rollen_aus_fakten`) |
| N14 | "Datenbanken erreichbar" trotz Rot VS-001 (DB, LW, JW) | erledigt für LW und JW; Abweichung DB: kein Datenbankport, VS-001 ist Webmin und froxlor |
| N14 | HE 444 "Web Applications Portal" ohne Rolle | erledigt ("Anmeldeportal (Port 444)") |
| N14 | BS .166 ohne "Mail-Webzugang laut Passivquelle" | erledigt (`test_n14_rollen_aus_fakten`) |
| N15 | Referrer-Policy-Auswirkung überholt | erledigt (`test_n15_referrer_policy_heutige_voreinstellung`) |
| N15 | 587 "TLS erzwungen" statt "Anmeldung erst nach STARTTLS" (LW, CA) | erledigt (`test_n15_starttls_statt_tls_erzwungen`) |
| N15 | A.1-Ausnahme umfasst abgelaufene Zertifikate, BS VS-003 Gelb | erledigt (`test_n15_a1_ausnahme_nur_fuer_ablaufende_zertifikate`) |
| N15 | `53 DOMAIN`, `106 TCPWRAPPED`, `https-alt` ohne `?` | erledigt (`test_n15_dienstnamen`, nmap-Nachweis mit `?`) |
| N15 | "gesehen am" für das Shodan-Host-`last_update` | erledigt (`test_n15_hosteintrag_statt_gesehen`) |
| N15 | Numerus ("1 weitere gefundene Name", "hat offene Ports" bei einem, "welcher Dienst auf dem Port" bei drei) | erledigt (`test_n15_numerus_eines_namens`, `service_unidentified` mit `{m:}`) |
| N15 | Doppelklammern in Titeln (JW VS-010) | erledigt (`test_jw_zusaetzliche_dienste_mit_tls_zwang` in `test_s6b4.py`) |
| N15 | Doppeltes Präfix "Beim Plattformbetreiber einfordern: Beim Plattformbetreiber erfragen" (HE) | erledigt (`test_n15_doppeltes_praefix_im_plan`) |
| N15 | HE P01 bis P03 und P08 lesen sich wie drei Orte; CA "beim Plattformbetreiber umfrageonline.com" als eigenes Listenelement | erledigt, Plattformzusatz in der Klammer hinter der Adresse |
| N15 | Beobachtungsliste 587 doppelt (DB) | erledigt |
| N15 | CA VS-018 Anmeldename im Kundentext (E25) | erledigt (`test_n15_e25_anmeldenamen_nur_als_anzahl`, Gate `test_anmeldename_im_kundentext_greift`) |
| N15 | BS 2052, 2053, 2095, 2096 "unbekannt" trotz Cloudflare-Banner, 8880 "HTTPS" statt Plesk | erledigt für 2053, 2096 und 8880, Satz zur CDN-Kante; offen für 2052 und 2095: der Shodan-Export schneidet deren Banner vor dem Server-Header ab (S6c) |
| N15 | ProFTPD und mod_sftp zwei Zeilen (LW) | erledigt (`test_n15_proftpd_eine_zeile_und_etracker_ausgeblendet`) |
| N15 | Etracker bleibt, Cookiebot entfernt (HE) | erledigt (`test_n15_proftpd_eine_zeile_und_etracker_ausgeblendet`) |
| N15 | HL 4433 in Anhang C, aber nicht in `unprocessed` | erledigt, unter "Beobachtungen ohne Regeltreffer" mit Antwortkopf |
| N15 | HL online-Zertifikat 28 Tage am Berichtsdatum (Vercel erneuert selbst) | offen, keine Änderung: `cert_expiring_later` misst am Scantag (31 Tage, Schwelle 30); ob Fristen dieser Regel am Berichtsdatum gelten, ist eine Frage an DC |
| Regressionsstand | R14 (`argument:host_inventory`, "Some (Auszug)", rohe Quellennamen in 3.1) | offen, S7 |
| Regressionsstand | R20 | offen, S7 |
| E23 | Firmennamen bestätigen | offen, DC |
| E24 | HSTS an Weiterleitungen und Fehlerseiten | Vorschlag umgesetzt (N2) |
| E25 | Personennamen im Kundentext | Vorschlag umgesetzt (N15, Gate `anmeldename_im_kundentext`) |
| E26 | Freigabe vor dem Nachscan | Entscheidung DC, nicht Teil der Session |
| Startprompt | AXFR-Rohausgabe im API-Export | offen, S6c (Scanner unberührt) |

## Die drei Fixtures der S6c-Proben (S6d)

Eigene Testauftraege vom 28.09.2026 (Claude ueber die API, keine Deliverables), die ersten Tars mit
den Rohfeldern aus `docs/S6C-NEW-RAW-FIELDS.md`. Aufgenommen mit `add-order-to-snapshot.py` und dem
Matrix-Job `ops-export-golden-tars` (Pipeline 3240, Jobs 24842 bis 24844). Soll-Listen abgeleitet
(`strict: false`), getestet in `tests/test_s6d_probeauftraege.py`.

| Auftrag | Ziel | Soll-Liste | Befunde rot/gelb/blau | Positive | TLS-Eintraege (davon je Port/SNI) | Gate F/W |
|---|---|---|---|---|---|---|
| 4394b0b7 | dortmund-beach.com | `dortmund-beach-0928` | 1/8/7 | 5 | 8 (7) | 0/1 |
| f9a2a2f6 | junkerwerk.de, junkerwerk.hu | `junkerwerk-0928` | 1/9/8 | 5 | 12 (10) | 0/1 |
| cd28d260 | castenow.de | `castenow-0928` | 0/11/10 | 9 | 16 (10) | 0/2 |

Warnungen: `auftraggeber_fehlt` (Testauftraege ohne Kundenkontext), bei castenow dazu
`messadresse_ausserhalb_inventar` (DNS-Rotation umfrage). Datenfallen der Proben:

- **testssl-Exit-Code ist eine Befundzahl.** dortmund-beach `testssl_21/143/465/587/993/995` stehen mit
  Exit 7 oder 8 auf `failed`, die JSON-Dateien sind vollstaendig (235 Eintraege bei 587). Die Abdeckung
  wertet seit S6d die Ausgabe (`tool_coverage.testssl_run_state`), der Scanner seit C4 ebenfalls.
- **rdap lief nie.** Alle drei Proben: erste Zeile `ok`/`no_ips`, zweite `skipped`/`not_in_package`
  (Verdrahtungsfehler im IP-Durchgang, in S6d als C6 behoben). Die Spalte bleibt "laut AbuseIPDB";
  die RIR-Quelle ist nur mit dem Fixture `tests/fixtures/facts/rdap_ripe_hetzner.json` belegt (die
  RIPE-Antwort aus `scan-worker/tests/test_rdap_s6c.py`, 116.202.77.64 lumbeck-wolter).
- **Endantwort-Header von redirect_probe sind verunreinigt.** castenow mail: `final_response_headers`
  sind die einer Schriftdatei (`segoeui-regular.ttf`, last wins ueber alle Ressourcen). Ohne das
  Kennzeichen `final_response_source: document` (C7) bleiben sie ungenutzt; die Endseite kommt aus
  `header_check.redirect_eval` (curl, `logon.aspx` mit 200).
- **junkerwerk 188.40.3.130:** die Sperrerkennung um 16:15 fand keine Sperre, ab 16:30 scheiterten
  testssl 443, header_check und redirect_probe; die sieben Per-Port-Laeufe haben trotzdem Daten.
  Ursache laut S6c-Messung der Burst der Per-Port-Sonden (C3: nacheinander mit Pause).
- **smtp_ehlo** lief an 465 und 587 in allen drei Proben in ein Zeitlimit; es gibt keine
  `smtp_ehlo_<port>.json`. AUTH vor STARTTLS bei dortmund-beach 587 kommt deshalb aus nmap
  smtp-commands; der EHLO-Pfad ist mit einem veraenderten Bundle getestet.
- **XML-RPC bei castenow:** die Sonde meldet an ubb-wiki Status 403, `xmlrpc_enabled: false`; kein
  Befund. Bei dortmund-beach lief die Sonde in ein Zeitlimit (wpscan meldet XML-RPC weiter).
- **whois der Zusatzdomain:** junkerwerk.hu scheiterte wie junkerwerk.de, die Zeile trug aber kein
  Domain-Etikett ("FAILED: whois_no_data") und zaehlt deshalb zum Primaerziel. Der Scanner setzt das
  Etikett seit S6d auch an Zeilen ohne Daten.

## Abgleich S6c-Rohfelder nach S6d

Jeder Punkt aus dem Startprompt S6d (Teil A bis C) mit Stand und Test. Tests ohne Pfad in
`tests/test_facts_s6d.py`, `tests/v3/test_s6d.py`, `tests/test_s6d_probeauftraege.py`,
`tests/test_testpaths_s6d.py`, scan-worker-Tests in `scan-worker/tests/test_*_s6d.py`. Fakten 1.4.0,
Katalog 2026-09-29.1.

| Punkt | Aussage | Stand |
|---|---|---|
| A1 | Netzbetreiber aus rdap mit Quelle RIR, Spalte "laut <RIR>" in 2.1 und Anhang B | erledigt (`test_a1_netzbetreiber_laut_rir_mit_rdap_fixture`, `test_a1_spaltenkopf_und_anhang_b_laut_ripe_mit_rdap`); Kopf mit Quelle, wenn alle Zeilen dieselbe haben, sonst Quelle je Zelle; Anhang B ohne neue Spalte, Betreiber in der ersten Zeile je Host (Layout bleibt S7a) |
| A1 | ohne rdap-Lauf weiter "laut AbuseIPDB", Alias-Tabelle und Anschlussbetreiber bleiben | erledigt (`test_a1_ohne_rdap_bleibt_abuseipdb`, `test_netzbetreiber_ohne_rdap_laut_abuseipdb`); gilt fuer alle 24 Fixtures, weil keines eine `rdap.json` traegt |
| A2 | TLS je Port und je SNI als eigene `tls[]`-Eintraege, `assigned_from` nur ohne eigenen Lauf | erledigt (`test_a2_eigener_eintrag_je_port_mit_starttls`, `test_a2_sni_lauf_eigener_eintrag`, `test_a2_alte_fixtures_behalten_die_zuordnung_ueber_das_zertifikat`) |
| A2 | Abdeckung "geprueft TLS-Ports je Host" aus den echten Laeufen, `failed` mit Grund als Einschraenkung | erledigt (`test_a2_gescheiterter_lauf_ohne_fakt_mit_grund`, `test_a2_gescheiterter_port_mit_ursache_in_der_einschraenkung`, `test_a2_abdeckung_nennt_die_gemessenen_ports`); vollstaendiger Lauf trotz Exit 7/8 ist `ok` (`test_a2_vollstaendiger_lauf_trotz_exit_code_ist_ok`) |
| A2 | Positivbefunde und Befunde je Port aus dem Lauf dieses Ports, Betroffenenliste einmal je Port | erledigt an den Proben (dortmund-beach VS-006 TLS 1.0 an 465 und 587 aus den eigenen Laeufen, CVE-2011-3389 in A.3 aus `testssl_465`/`_587`); `service_cert_expired` bleibt fuer Ports ohne eigenen TLS-Fakt, mit Lauf greift `cert_expired` am Port. Kein Fixture mit abgelaufenem Mailzertifikat und Per-Port-Lauf |
| A2 | ein TLS-Fakt macht einen Mailport nicht zum "Webserver" | erledigt (`test_a2_mailport_mit_tls_fakt_wird_kein_webserver`); testssl-Dienst (smtp, imap, pop3, ftp) ist eine Kennung (`kennung_source testssl`), Erweiterung zu A3 |
| A3 | Kennung aus imap-/pop3-capabilities, smtp-commands, ssl-cert und `nmap_versionall.xml` | erledigt (`test_a3_versionall_mit_kennung_ersetzt_die_tabellenangabe`, `test_a3_versionall_ohne_ergebnis_aendert_nichts`); an den Proben lieferte der Nachlauf keine neue Kennung (dortmund-beach Zeitlimit, junkerwerk 993/995 wieder `imaps?`/`pop3s?`) |
| A4 | Fakten `smtp_auth_before_starttls` und `smtp_vrfy` aus `smtp_ehlo_<port>` (ersetzt die Passivquelle) | erledigt (`test_a4_ehlo_sonde_ersetzt_nmap`); an den Proben ohne EHLO-Antwort (Zeitlimit) bleibt nmap die aktive Quelle (`test_a4_ohne_ehlo_antwort_bleibt_nmap`) |
| A4 | Katalogregel `smtp_auth_before_starttls` (Gelb, Mittelfristig, Entscheidung DC 29.09.), unprocessed-Art entfaellt | erledigt, Regel aktiv und laut Passivquelle im Buendel `smtp_auth`, Passivport als Portzusatz im Titel ("auf 587 und laut Passivquelle 25"), E22-Hinweis (`test_a4_auth_vor_starttls_als_gelber_befund_mit_passivport`, `test_a4_passivvariante_allein_bei_bergersysteme`, `test_a4_keine_unverarbeitete_beobachtung_mehr`, Fixtures `smtp_auth_before_starttls_*`, Text-Fixture); E5-Zeile bleibt |
| A5 | `wordpress_xmlrpc_enabled` aus `xmlrpc_probe.json` zusaetzlich zu wpscan, Nachweis nennt die Sonde | erledigt (`test_a5_aktive_xmlrpc_sonde_traegt_den_befund`, `test_a5_abgelehnte_sonde_kein_befund`, `test_a5_sonde_bei_castenow_mit_ablehnung`); castenow ohne Befund, weil die Sonde 403 bekam |
| A6 | "bewertet an der Endseite" nur mit Endantwort-Headern; Endantwort aus dem neuen Feld | erledigt: HTTP-Weiterleitungen aus `header_check.redirect_eval.final`, clientseitige aus `redirect_data.final_response_headers` nur mit `final_response_source: document` (C7); Nachweis mit erster Antwort und Endseite (`test_a6_endantwort_von_header_check_nach_http_weiterleitung`, `test_a6_endseite_von_header_check_im_nachweis`, `test_a6_endantwort_der_weiterleitungspruefung_nur_mit_kennzeichen`) |
| A6 | `redirect_eval` mit Status und location in der Einschraenkung; HSTS an der ersten Antwort (E24) | erledigt: nicht bewertbare Endantwort desselben Namens als "Endantwort <Status>" in der Zeile (umfrage nennt das Ziel www, keinen Status); HSTS unveraendert |
| A7 | Konfidenz und Risiko je Meldung, Konfidenzfilter Q14 wirksam | erledigt; Q14 galt schon je Meldungstyp (hoechste Konfidenz, S6b-2), jetzt innerhalb des Fundorts |
| A7 | Meldungen an 429, 4xx und Nebenpfaden nicht der Zielseite zugerechnet, mit Pfad im Anhang; Anhang C mit URL je Meldung | erledigt (`test_a7_fundort_aus_dem_statuscode`, `test_a7_castenow_meldungen_tragen_status`, `test_a7_anhang_c_mit_adresse_je_meldung`); ZAP-Regeln mit Befund (csrf, session_in_url, sri, cors, directory_listing) nur `alert.location == "target"`. Abweichung: ein Meldungstyp mit Instanzen an Zielseite und Nebenpfad bleibt eine Meldung mit den Adressen der Zielseite; die Nebenpfad-Instanzen dieses Typs erscheinen nicht getrennt im Anhang. `web_vulnerability_active` ohne Fundortfilter (aktive Einschleusung gilt auch an einer Fehlerseite) |
| A8 | `provider_block_probe` als Fakt, Einschraenkung mit Dauer und betroffenen Pruefungen, Abdeckung "Portscan vollstaendig; danach abgewiesen" | erledigt (`test_a8_gemessene_sperre_ist_blockade`, `test_a8_gemessene_sperre_mit_dauer_und_ports`); Dauer aus `waited_s` (C3), aelter aus der Zahl der Versuche |
| A8 | ohne Sperre kein Text | erledigt (`test_a8_ohne_sperre_kein_sperrtext_aber_hinweis_auf_spaete_abweisung`); junkerwerk 188.40.3.130 behaelt die abgeleitete Ursache "Verbindungen nach dem Portscan abgewiesen" mit dem Satz, dass die Sperrerkennung keine Sperre fand |
| A9 | Zonentransfer-Positiv nur mit dem Fakt der jeweiligen Domain | erledigt; "kein Lauf" ergibt `not_tested_reason` ohne Positivbefund (`test_a9_zonentransfer_ohne_lauf_mit_grund`); in f9a2a2f6 lief der AXFR fuer junkerwerk.hu (`test_a9_zonentransfer_je_domain_mit_eigenem_lauf`), der Positivbefund hat dort einen eigenen Fakt |
| A9 | `found_not_in_inventory` fuer "gefunden, nicht geprueft" mit Gate-Warnung | erledigt (`test_a9_gefundene_namen_aus_discovery_health`); an den Proben ist die Liste leer |
| A9 | Hostsuche je Zieldomain im Pruefumfang je Domain | teilweise: die veraltete Mehrziel-Warnung entfaellt (`test_a9_keine_veraltete_mehrziel_warnung`); die Zeile je Domain nennt die Hosts der Zusatzdomain ueber das Inventar, eine eigene Angabe "Hostsuche lief" aus `tool_counts.enum_<domain>` ist Darstellung (S7a) |
| A10 | Abfragefenster im Reputations-Positivbefund | erledigt (`test_a10_positivbefund_mit_abfragefenster`, `test_a10_ohne_feld_wie_bisher`) |
| A11 | no_ipv6_route, ZAP unreachable, whois ohne Daten, Zeitlimits von ferox und ffuf als Einschraenkung je Ursache | erledigt: whois neu als "Registrierungsdaten der Domain nicht abrufbar" (`test_a11_whois_und_ehlo_als_einschraenkung`, `test_whois_ohne_daten_steht_nicht_im_bericht` angepasst); EHLO-Sonde ohne Antwort in der Zeile "Ablehnung einer Anmeldung vor STARTTLS nicht belegt" mit Port und Ursache; die neuen Werkzeuge erzeugen keine Sammelzeile (`test_a11_neue_werkzeuge_ohne_sammelzeile`); no_ipv6_route, ZAP und Pfadsuche mit den Bausteinen aus S6b-1 bis S6b-4n |
| A12 | alle Dateien aus der Uebergabetabelle gelesen, 0 `file_unknown_or_unparsable` an den Proben | erledigt (`test_a12_keine_unbekannten_dateien_an_den_probeauftraegen`, `test_keine_unbekannten_dateien`) |
| B1 (#16) | Schwachstellenzahl und CVE-Kennungen nur aus dem wpscan-Feed, Kennungen nach Schwere | erledigt: Zahl = Eintraege im Feed, Reihenfolge nach NVD-CVSS aus den threat-Fakten, sonst Feed-Reihenfolge mit "Schweregrad im Feed nicht angegeben" (Entscheidung DC 29.09.; wpscan liefert in keinem der 24 Tars eine Schwere, `enrichment.json` ist leer, Issue #26) (`test_b1_zahl_und_kennungen_aus_dem_feed`, `test_b1_schwere_im_feed_nicht_angegeben`) |
| B2 (#18) | httpx-Abdeckung je VHost | erledigt (`test_b2_httpx_abdeckung_je_vhost`); der VHost kommt aus `input`/`url` der JSONL-Zeile, demselben Schluessel wie bei `httpx_<slug>.json` (der Dateiname steht in der Zeile nicht, er ist nur ein Eindeutigkeitsmerkmal) |
| B3 (#4) | Validierungstests in den testpaths, Pipeline zaehlt die Tests | erledigt: Tests liegen seit S5 in `tests/validation`; Sperre `tests/test_testpaths_s6d.py` fuer report-worker und scan-worker; `junitxml` mit `artifacts:reports:junit` in `test-report-worker` und `test-scan-worker` |
| C1 (#22) | otx, securitytrails je Domain mit `_domain` | erledigt im Scanner (`test_passive_domains_s6d.py`), Berichtsseite liest die Domaindateien (`test_c1_otx_und_securitytrails_je_domain`, `test_c1_domaindateien_werden_gelesen`); whois-Zeilen ohne Daten tragen jetzt ebenfalls das Etikett (`test_zeilen_ohne_daten_tragen_das_etikett`) |
| C2 (#19) | NAT64-Adressen erkennen, im Inventar mit Grund, nicht als IPv6-Ziel | erledigt (`test_nat64_s6d.py`, handgebaut nach dem S2b-Beleg; `test_c2_nat64_adresse_ist_kein_ipv6_des_systems`) |
| C3 | Per-Port-Sonden auf gedrosselten Hosts nacheinander mit Pause, konfigurierbar, Messung danach | erledigt (`test_throttle_probes_s6d.py`); `VECTISCAN_THROTTLE_PROBE_PAUSE_S` (5), `VECTISCAN_THROTTLE_PROBE_ORDER` (asc), zweite Messung `provider_block_probe_p2`; Wirkung erst in der Testrunde messbar |
| C4 | `testssl_<port>` mit `failed` traegt einen Grund | erledigt (`test_testssl_status_s6d.py`): `no_tls_on_port`, `tls_connect_refused`, `starttls_failed`, `incomplete_output`, `invalid_json`, `no_output_file`, `usage_banner`; ein vollstaendiger Lauf ist `ok` unabhaengig vom Exit-Code |
| C6 | rdap mit den Inventar-IPs (S6c-Defekt, Entscheidung DC 29.09.) | erledigt (`test_passive_domains_s6d.py`: IP-Durchgang faehrt rdap, keine Doppelzeilen, dns_security nicht erneut) |
| C7 | Endantwort von redirect_probe nur aus Hauptframe-Navigationen (Entscheidung DC 29.09.) | erledigt (`test_redirect_probe_document_s6d.py`), Kennzeichen `final_response_source` |

Aenderungen an den 21 alten Fixtures aus vorhandenen Daten (Soll-Listen neu erzeugt, Markierungen
erhalten):

- **A4:** AUTH vor STARTTLS wird Befund: aktiv (nmap smtp-commands) bei dortmund-beach 14272c00 und
  1fbc92b9 (587, dazu Port 25 laut Passivquelle im selben Befund), castenow 2d2d4f39, 4e6b6883 und
  f77ccff2 (92.205.163.53:25), trunk-immobilien 45bb234c, securess ae8d1d70 (zwei Hosts),
  krause-computer fb13a98f; nur laut Passivquelle bei castenow 1f8bc977 und bergersysteme 68d59573
  (Port 25). Bei bergersysteme nennt die E4-Zeile den neuen Passivbefund mit.
- **A7:** Anhang C nennt je Meldung die Adresse mit Pfad (alle Fixtures mit ZAP-Meldungen im Anhang);
  Zahl der Zeilen und Meldungen unveraendert. Keine Befundaenderung durch den Fundortfilter.
- **A11:** vectigal-tech 75338c97 bekommt "Registrierungsdaten der Domain nicht abrufbar" (whois
  `failed`/`no_data` aus S2b); die uebrigen alten Fixtures fuehren whois als `ok` mit "no_data" und
  bleiben ohne Zeile.
- **A1:** Anhang B nennt den Netzbetreiber "laut AbuseIPDB" in der ersten Zeile je Host (alle
  Fixtures mit Anhang B).
- **A2, A3, A5, A6, A8, A9, A10:** keine Aenderung an den alten Fixtures (Rohfelder fehlen dort).

Seitenerwartung (`render/expected-pages.json`) aus `ops-update-pages` der MR-Pipeline.

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

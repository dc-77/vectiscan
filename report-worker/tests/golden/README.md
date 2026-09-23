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

# 4 Roh-Tars: API-Pipeline auf dem Branch ausloesen, die zehn Matrix-Jobs
#   ops-export-golden-tars starten, die Artefakte golden-tars/ nach tars/ entpacken.
#   Ein Auftrag je Job, weil der Artefakt-Upload dieser GitLab-Instanz schon bei
#   wenigen hundert Kilobyte mit 413 abbricht. Dieselbe Grenze trifft git push
#   ueber HTTPS; der Branch geht ueber SSH raus.

# 5 Manifest neu schreiben (liest tars/ und negative.json)
python3 scripts/golden/build-manifest.py
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

## Bekannte Abweichungen

- `expected/junkerwerk.json` fuehrt `family` und `families`. Das Feld gibt es in
  `report-prototype/build/report_data.py` nicht; die Namen stammen aus dem
  Vokabular von `build/catalog_sim.py`, die Zuordnung steht im Generator.
  Positivbefunde haben in der Quelle keine ID, `VS-2026-P01` bis `P08` sind
  hier vergeben, `scale` und `level` bleiben leer.
- `negative.json` enthaelt fuer das Muster `NEG-MARIADB-55` sechs statt der in
  spec/06 genannten fuenf Eintraege. Der Grund steht in der Datei unter
  `abweichungen`. Ebenfalls dort: der Defekt dieses Musters sitzt in der
  Versionsableitung, nicht im Befundtext.
- `expected/junkerwerk.json` fuehrt die Berichtsnummer seit S6a im Produktformat
  `VS-2026-0831-0bf1` statt der Prototyp-Nummer `VS-JW-2026-0831`; der Generator
  leitet sie ab (`s6a_report_id`), Grund in `reporter/v3/deltas.md` Punkt 14. Alle
  14 `report-data/*.json` und der HTML-Snapshot tragen die neue Nummer
  (`meta.report_id`); vorher kollidierten 0831 dreimal, 0920 dreimal und 0722 zweimal.

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

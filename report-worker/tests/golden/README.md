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
| `api-snapshot/<order>/` | `order.json`, `findings.json`, `results.json` je Auftrag, 39 Auftraege |
| `expected/junkerwerk.json` | 15 Befunde und 8 Positivbefunde des Prototyps als Soll-Liste |
| `negative.json` | belegbar falsche Befunde aus ausgelieferten Reports; kein Check darf sie erzeugen |

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
`parse_scan_data`. Unter Windows werden `0bf16342` und `2572eebc` uebersprungen:
sie fuehren Hosts unter IPv6-Adressen, und der Doppelpunkt ist dort kein
zulaessiges Pfadzeichen. Vollstaendig laeuft der Test unter Linux, also im
CI-Job `test-report-worker`, der sich auf einer API-Pipeline manuell starten
laesst.

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

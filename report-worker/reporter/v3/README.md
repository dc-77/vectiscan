# reporter.v3: Reportdaten (Session S3)

Aus `facts.json` (S1) und dem Ergebnis des Pruefkatalogs (S2) entsteht hier das
Datenmodell des Reports. Struktur und Feldnamen sind exakt die des Prototyps
(`report-prototype/build/report_data.py` DATA), damit der Renderer aus S4 ohne Umbau
darauf rendert.

Das Paket erfindet nichts. Einstufungen kommen aus dem Katalog, Zahlen aus den Fakten,
Befundtexte aus den Katalogtexten, Rahmentexte aus `narrative.py`. Genau vier Felder
schreibt ein Sprachmodell, und auch die nur, wenn sie ein Gate passieren.

## Aufruf

```bash
cd report-worker
python -m reporter.v3 tests/golden/facts/<order>.json -o report-data.json
python -m reporter.v3 --golden <order_id> --no-prose        # Fakten selbst laden
python -m reporter.v3 --golden-all [--check]                # Golden-Daten bauen/pruefen
```

Programmatisch:

```python
from reporter.v3 import build_report_data, check_report_data

data = build_report_data(facts, catalog_output, order=order, customer_context=ctx)
defekte = check_report_data(data)     # leer heisst in Ordnung
```

Ohne `ANTHROPIC_API_KEY` laeuft alles mit Katalogtexten durch. Das ist kein Fehler,
sondern der Normalfall in Tests und Entwicklung.

## Dateien

| Datei | Inhalt |
|---|---|
| `models.py` | pydantic-Modell `ReportData` mit den zehn Abschnitten des Prototyps |
| `levels.py` | Einstufung zu Farbe, Dringlichkeit und Ampelwert |
| `bundles.py` | Konsolidierung: Pruefergebnisse werden Sachverhalte |
| `findings.py` | Befunde, Positivbefunde, Nachweisbloecke, Fremdreferenzen |
| `ids.py` | `VS-<Kuerzel>-<Jahr>-<lfd>` bzw. `VS-<Jahr>-<lfd>` |
| `plan.py` | Massnahmenplan und die drei Hebel |
| `chapters.py` | meta, glance, business, scope, architecture |
| `appendix.py` | Anhaenge A bis F |
| `narrative.py` | Erzaehltexte als Vorlage mit Zahlen-Slots |
| `tables.py` | Impressum, Pakete, Werkzeugliste, Skalen, Posture-Bloecke |
| `orthography.py` | echte Umlaute statt Umschrift, Fremdtext glaetten |
| `prose.py` | ein KI-Aufruf fuer vier Felder, mit Cache und Kostenprotokoll |
| `gate.py` | Ausgabepruefung dieser vier Felder |
| `selfcheck.py` | `check_report_data`, portiert aus dem Gate des Prototyps |
| `golden.py` | Golden-Reportdaten bauen und gegen Drift pruefen |
| `deltas.md` | begruendete Abweichungen vom Prototyp |

## Vom Pruefergebnis zum Befund

Der Katalog liefert ein Ergebnis je Pruefung und Gruppe, fuer den Junkerwerk-Auftrag
sind das 52 Fehlschlaege. Der Bericht zeigt Sachverhalte, nicht Pruefungen. Zwei
Schritte fuehren dorthin:

1. **Buendel** (`reporter/catalog/bundles/*.yaml`, siehe README des Katalogs) fassen
   Pruefungen zusammen, die derselbe Handgriff behebt. `merge_by` bestimmt, ob je Host,
   je Domain oder einmal fuer den ganzen Auftrag zusammengefuehrt wird.
2. **Pruefungen ohne Buendel** ergeben je einen Sachverhalt ueber alle ihre Gruppen
   hinweg, hostuebergreifend (spec/03 Regel 1).

Skala, Einstufung und Kategorie eines Buendelbefunds kommen vom schwersten
fehlgeschlagenen Mitglied. Die Dringlichkeit ist die dringlichste Empfehlungsstufe der
beteiligten Texte; daraus entsteht auch der Massnahmenplan.

Positivbefunde laufen immer ueber den ganzen Auftrag zusammen. Eine Gruppe, in der ein
Mitglied fehlgeschlagen ist, liefert keinen Positivbefund, und eine Gruppe ohne ein
einziges gesehenes Item auch nicht: "kein Datenbankdienst" auf einem Host ohne jeden
Dienst ist keine Aussage.

## Herkunft der Felder

| Abschnitt | Woher |
|---|---|
| `meta` | `facts.scan` (Domains, Zeitfenster), `facts.hosts/fqdns` (Zahlen), `order` und `customer_context` (Kunde, Kuerzel), `CATALOG_VERSION`, `catalog_digest`, `FACTS_SCHEMA_VERSION` |
| `glance.categories` | Kategorie A bis E aus dem Katalog, Status vom schwersten Befund der Kategorie |
| `glance.overall_text` | deterministisch; **KI-Feld 1** |
| `glance.context`, `coverage_warning` | `narrative.py` mit Zahlen aus den Fakten |
| `business.observed[].system` | Rollen je Host aus Diensten und Software |
| `business.observed[].meaning` | Rollentext; **KI-Feld 3** |
| `business.implication` | generischer Absatz; **KI-Feld 2** (nutzt `customer_context`) |
| `scope.hosts` | `facts.hosts` plus Abdeckung aus `facts.coverage` |
| `scope.limitations` | Abdeckungszeilen und `not_testable`-Gruende, Text aus `tables.COVERAGE_REASONS` |
| `architecture.tech` | `facts.software` mit normalisierter Version und EOL-Stand |
| `architecture.services` | `facts.services`, Farbe aus der Befundzuordnung des Ports |
| `architecture.posture` | vier feste Bloecke, Items zeigen auf Pruefungen |
| `architecture.screens` | `facts.fqdns[].screenshot_key`; die Bilddatei holt S4 aus MinIO |
| `findings[].found/verify` | Katalogtexte, Platzhalter mit den zusammengefuehrten Werten |
| `findings[].impact` | Katalogtext `texts.meaning`; **KI-Feld 4** |
| `findings[].evidence` | Faktreferenzen aus dem Katalogergebnis (Werkzeug, Fundstelle, Auszug) |
| `findings[].threat`, `appendix.cve_refs` | `facts.threats`: Fremdwerte (NVD-Score, KEV) und seit S5b auch CVEs, die ein Werkzeug genannt hat |
| `plan`, `glance.levers` | Empfehlungsstufen der fehlgeschlagenen Pruefungen |
| `appendix.inventory` | `facts.services` und `facts.passive` |
| `appendix.tools` | Werkzeuge, die laut `facts.coverage` gelaufen sind, ohne Versionsnummer |
| `appendix.tool_findings` | Buendel mit `target: appendix` |

## Anhang A.3: zwei Faelle, benannt (S5b)

A.3 zitierte bis S5b nur CVEs mit Fremdbewertung. Da die Phase-3-Anreicherung in keinem
Produktionslauf je einen Fremdwert geliefert hat (`cves_enriched` 0 ueber 42 Auftraege,
`phase3/enrichment.json` ueberall `{}`), blieb der Anhang leer und die testssl-CVEs
tauchten nirgends auf. Jetzt gilt:

- **Fremdbewertet** (NVD-Basiswert oder KEV): Basiswert und Quelle stehen in der Zeile.
- **Vom Werkzeug genannt** (`source` in `findings.WERKZEUG_QUELLEN`, heute `testssl`):
  Basiswert leer, Quelle ist das Werkzeug, die Einstufung steht im verwiesenen Befund.
  Der Satz in A.2 sagt das ausdruecklich, damit ein leerer Basiswert nicht als
  "unbewertet" gelesen wird.
- **Weder noch**: wird nicht zitiert.

Ein werkzeuggestuetzter Threat wird nur bei den Befunden zitiert, deren fehlgeschlagene
Pruefungen genau dieses Werkzeug brauchen (`ThreatIndex.for_results`). Ohne diese Bindung
stuende eine TLS-CVE unter dem Header-Befund desselben Hosts, weil beide an Port 443
haengen. Dieselbe CVE kann in mehreren Befunden zitiert werden; A.3 fuehrt sie einmal und
nennt alle Befunde, der Selbstcheck prueft Zugehoerigkeit statt Gleichheit.

`CveRef.name` bleibt leer: die Bezeichnung kaeme aus der NVD-Antwort, und die gibt es
nicht. Der Prototyp fuellt die Spalte, dieser Bericht bislang nicht.

## Die vier Prosa-Felder

Ein Aufruf, `claude-opus-4-7`, Eingabe sind fertige Befunde und aggregierte Fakten als
JSON, nie Rohdaten. Jedes Feld laeuft einzeln durch `gate.check_field`:

1. Zahlen, Hostnamen, CVE-Nummern und Versionsangaben nur aus der Eingabe.
2. Keine Einstufungswoerter im Text.
3. Laengenlimit je Feld.
4. Keine Gedankenstriche, keine Platzhalter, keine Zusagen, Sie-Form, echte Umlaute.

Faellt ein Feld durch, bleibt der deterministische Text stehen; Feld und Regel stehen im
Log und in `meta.prose_rejected`. Die uebrigen Felder werden trotzdem uebernommen.

**Abweichung von der Determinismus-Vorgabe:** `claude-opus-4-7` nimmt keinen
`temperature`-Parameter mehr an (siehe `reporter/claude_client.py`). Die Vorgabe
temperature 0 laesst sich mit diesem Modell nicht erfuellen. Determinismus kommt
stattdessen aus dem Redis-Cache (Namensraum `reporter_v3`, der Schluessel enthaelt
`CATALOG_VERSION` und `FACTS_SCHEMA_VERSION`), dem Gate und dem Katalog-Fallback.
Kosten gehen wie bisher nach `ai_call_costs` (`ki_step = report_prose_v3`).

## Golden-Daten und Bump-Regel

`tests/golden/report-data/<order>.json` entsteht allein aus den eingecheckten Fakten und
dem Katalog, ohne Auftragsdaten und ohne KI, mit festem Berichtsstichtag. Nach jeder
gewollten Aenderung an Katalog, Buendeln oder diesem Paket:

```bash
python -m reporter.v3 --golden-all
```

`tests/v3/test_golden_all.py` vergleicht und schlaegt bei ungewollter Drift an.

## Was hier nicht passiert

Rendern und PDF (S4), Gate strict, `report_blocked` und die Admin-Defektliste (S5), der
Schalter `VECTISCAN_REPORT_ENGINE` und das Entfernen der alten Reparaturkette (S6),
Rahmenwerk-Tags und Export (S7). `reporter/v3` ist Bibliothek und CLI; der
Produktionspfad in `reporter/worker.py` ist unveraendert.

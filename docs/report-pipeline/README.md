# Report-Pipeline (v3)

Stand 22.09.2026, Session S6. Der Bericht entsteht seit der Umschaltung so:

```
Roh-Tar aus MinIO
  │
  ├─ 1 Fakten        reporter/facts/       facts.json, ein Schema, versioniert
  ├─ 2 Prüfkatalog   reporter/catalog/     73 Prüfungen als YAML, Ergebnis je Gruppe
  ├─ 3 Reportdaten   reporter/v3/          Sachverhalte, Kapitel, Anhänge, Prosa
  ├─ 4 Renderer      reporter/pdf/v3/      Jinja2 und WeasyPrint
  └─ 5 Gate          reporter/gate/        Defektliste beider Engines, strict blockiert
```

**Kein Befund ohne Fakt aus einem Werkzeug.** Ein Sprachmodell schreibt Prosa
und recherchiert den Kundenkontext; es entscheidet weder über Befunde noch über
deren Einstufung, und es vergibt keine CVSS-Werte. Die Einstufung eines Befunds
kommt aus der Prüfung, die ihn erzeugt hat, die Farbe und die Dringlichkeit aus
einer einzigen Abbildungstabelle.

## Die fünf Schritte

| Schritt | Modul | Was dort entsteht | Tiefe |
|---|---|---|---|
| Fakten | `report-worker/reporter/facts/` | `facts.json`: Hosts, Dienste, TLS, HTTP, DNS, Software, Abdeckung, Passivquellen, jeweils mit Werkzeug, Fundstelle und wörtlichem Auszug | [README](../../report-worker/reporter/facts/README.md) |
| Prüfkatalog | `report-worker/reporter/catalog/` | ein Ergebnis je Prüfung und Gruppe: `fail`, `pass`, `not_testable`, `not_applicable`, dazu Betroffene, Nachweis und Positivaussagen | [README](../../report-worker/reporter/catalog/README.md), [Entscheidungstabelle](../../report-worker/reporter/catalog/decisions.md) |
| Reportdaten | `report-worker/reporter/v3/` | Sachverhalte aus den Ergebnissen, Kapitel 1 bis 6, Maßnahmenplan, Anhänge, Dashboard-Liste | [README](../../report-worker/reporter/v3/README.md) |
| Renderer | `report-worker/reporter/pdf/v3/` | das PDF, Paketvarianten, Bildauflösung aus MinIO | [README](../../report-worker/reporter/pdf/v3/README.md) |
| Gate | `report-worker/reporter/gate/` | Defektliste auf der Order, `report_blocked` bei einem Fehler unter `strict` | [README](../../report-worker/reporter/gate/README.md) |

Die READMEs neben dem Code sind die technische Wahrheit. Dieses Verzeichnis
beantwortet nur die Fragen, die sich über alle fünf Schritte stellen.

## Schalter

Drei Umgebungsvariablen, gelesen an genau einer Stelle
(`report-worker/reporter/engine.py`). Ein unbekannter Wert ist ein Startfehler,
kein stiller Rückfall.

| Variable | Werte | Vorgabe | Wirkung |
|---|---|---|---|
| `VECTISCAN_REPORT_ENGINE` | `catalog`, `legacy` | `catalog` | woher die Befunde kommen |
| `VECTISCAN_REPORT_LAYOUT` | `v3`, `v2`, `v1` | `v3` | welcher Renderer setzt |
| `VECTISCAN_VALIDATION_LEVEL` | `strict`, `warn`, `off` | `strict` | wie scharf das Gate ist |

`engine=catalog` mit `layout=v2` oder `v1` ist eine Fehlkonfiguration: der alte
Renderer liest das Datenmodell der alten Kette, und das entsteht unter `catalog`
nicht. `engine=legacy` mit `layout=v3` bleibt erlaubt, so lief die Produktion
zwischen S4 und S6.

**Rückweg bei einem Vorfall**, drei Zeilen in der `.env` des Servers:

```
VECTISCAN_REPORT_ENGINE=legacy
VECTISCAN_REPORT_LAYOUT=v2
VECTISCAN_VALIDATION_LEVEL=warn
```

Der alte Weg verschwindet eine Release nach S6. Was er kostet, steht unten.

## Versionen im Bericht

Zwei Versionen sagen, gegen welchen Stand ein Bericht entstanden ist:

- `CATALOG_VERSION` (`reporter/catalog/version.py`, Format `JJJJ-MM-TT.n`) steigt
  bei jeder Änderung an `checks/`, `bundles/`, `ignore.yaml` oder `tables.py`.
  Zur Laufzeit wird zusätzlich ein Digest über genau diese Dateien gebildet,
  damit eine Änderung ohne Bump im Audit sichtbar bleibt.
- `FACTS_SCHEMA_VERSION` (`reporter/facts/schema.py`, semver) steigt, wenn sich
  das Faktenschema ändert. Jeder Bump verlangt den Neubau der Golden-Fakten.

Beide stehen im Impressum des PDF und zusammen in `reports.policy_version`
(`Katalog <version> / Fakten <version>`). Die alte Severity-Policy
(`reporter/severity_policy.py`) füllt diese Spalte nur noch im Legacy-Weg.

## Was der Bericht nicht behauptet

- Keine Zusagen zu Prüfstandards, zur Rolle von Sprachmodellen oder zur
  Vollständigkeit. Der Wächter dazu ist
  `report-worker/tests/test_no_legacy_claims.py`.
- Keine eigenen CVSS-Werte. Ein Basiswert erscheint nur als Fremdreferenz zu
  einer zitierten CVE (Anhang A.3).
- Kein Positivbefund, solange die Prüfung für einen betroffenen Host nicht
  prüfbar war. Nicht prüfbar ist nicht bestanden.
- Keine Aussage über Systeme, die der Scan nicht erreicht hat. Die Lücken
  stehen in Kapitel 2, nicht im Kleingedruckten.

## Kosten je Bericht

Zwei KI-Aufrufe, beide auf `claude-opus-5`, beide mit Redis-Cache:

| Aufruf | Modul | Zweck | Messwert |
|---|---|---|---|
| Prosa | `reporter/v3/prose.py` | vier Textfelder, jedes durch ein Wort- und Längen-Gate | rund 0,25 USD |
| Recherche | `reporter/v3/research.py` | Firmenname, Branche, Mitarbeiterzahl, Systemzwecke, jeweils mit Fundstelle | rund 0,29 USD |

Ohne `ANTHROPIC_API_KEY` läuft beides leer durch und der Bericht steht
vollständig aus Katalogtexten. Der Legacy-Weg kostet zum Vergleich rund
1,85 USD je Bericht (Opus 4.7, KI#5 mit Reparaturkette).

## Golden-Fixtures

`report-worker/tests/golden/` hält vierzehn Produktionsläufe als Roh-Tar samt
abgeleiteten Fakten, Reportdaten und Soll-Listen. Jede Änderung am Katalog, an
den Fakten oder am Renderer läuft dagegen.

```
python -m reporter.facts --golden        # Fakten neu bauen
python -m reporter.v3 --golden-all       # Reportdaten neu bauen
python -m reporter.pdf.v3 --write-snapshot   # HTML-Schnappschuss
python -m pytest                          # alles
```

Einzelheiten und der Weg, einen Auftrag aufzunehmen:
[tests/golden/README.md](../../report-worker/tests/golden/README.md).

## Freigabe und Auslieferung

Ein Bericht geht nach `pending_review`, und nur ein ausdrückliches
`POST /api/admin/orders/:id/approve` setzt ihn auf `report_complete`. Erst
dieser Status löst die Fertig-Mail mit Download-Verweis aus
(`api/src/lib/ws-manager.ts`). Eine Ausschlussliste allein ist keine Freigabe,
und `POST /api/orders/:id/regenerate-report` verlangt Admin-Rechte.

Blockiert das Gate, steht die Order auf `report_blocked`, es gibt kein PDF und
keinen Upload; die Defektliste liegt in `orders.report_defects` und steht im
Admin-Review unter `/admin/review/<orderId>`.

## Die alte Pipeline

Die Dokumentation des Wegs bis S6 liegt unter
[`docs/archive/report-pipeline-v2/`](../archive/report-pipeline-v2/). Sie
beschreibt die KI-erzeugten Befunde, die Reparaturkette und den
ReportLab-Renderer. Solange `engine=legacy` erreichbar ist, gilt sie für diesen
Weg; danach ist sie Historie.

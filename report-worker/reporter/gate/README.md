# reporter/gate — das Berichts-Gate (S5)

Ein Bericht, den niemand vor der Auslieferung geprüft hat, ist eine Behauptung.
Dieses Paket macht daraus einen Arbeitsablauf: es sammelt die Defekte beider
Engines in einer Liste, hält den Bericht unter `strict` an und legt die Liste
dorthin, wo der Admin sie sieht.

## Was hier liegt

| Datei | Inhalt |
|---|---|
| `defects.py` | `Defect` (Engine, Prüfung, Stufe, Meldung, Befund-ID) und die Adapter für beide Engines; `payload()` baut den Inhalt von `orders.report_defects`. |
| `v3_checks.py` | Die vier Prüfungen aus S5, die über das Datenmodell hinausgehen. |
| `__main__.py` | Das Gate von Hand fahren, mit gezielter Beschädigung für die Abnahme. |

Die inhaltlichen Prüfungen des Datenmodells stehen weiter in
`reporter/v3/selfcheck.py`, die Prüfungen am fertigen PDF in
`reporter/pdf/v3/checks.py`. Hier wird nichts davon wiederholt, nur
zusammengeführt.

## Zwei Engines, eine Liste

Der v2-Strang (`reporter/validation/gate.py`) und der v3-Strang (Prüfkatalog,
Selbstcheck, Render-Prüfungen) melden beide. Der Admin soll eine Liste sehen,
nicht zwei; woher ein Eintrag kommt, steht deshalb am Eintrag (`engine`).

## Stufen

`error` hält den Bericht unter `VECTISCAN_VALIDATION_LEVEL=strict` an,
`warning` nie. Die Einordnung ist bewusst:

| Fall | Stufe | Begründung |
|---|---|---|
| Selbstcheck des Datenmodells | Fehler | Lückenhafte IDs, fehlende Empfehlungen, Platzhalter im Text: der Bericht wäre falsch. |
| Abdeckungskapitel ohne Angabe | Fehler | Der Bericht behauptet sonst implizit eine vollständige Prüfung. |
| Tech-Zeile widerspricht Befund | Fehler | Der Kunde sieht den Widerspruch im selben PDF. |
| Schrift nicht eingebettet | Fehler | WeasyPrint setzt still mit einer Ersatzschrift weiter, dann stehen wieder ae und ue statt Umlauten. |
| Gedankenstrich im Fließtext | Fehler | Hausregel für Kundentexte. |
| Halbleere Seiten | Warnung | Sie hängen an der Datenmenge und sind je Auftrag in `tests/golden/render/expected-pages.json` bekannt (S4). |
| Mehr als fünf Beobachtungen ohne Regel | Warnung | Ein Hinweis auf fehlende Prüfungen, kein Fehler im Bericht. |
| Auftraggeber fehlt | Warnung | Der Bericht bleibt lesbar, nennt den Kunden aber generisch. |

## Wo die Liste landet

In `orders.report_defects` (Migration 046), nicht in einer `reports`-Zeile ohne
PDF: eine solche Zeile wäre in jeder Abfrage sichtbar, die den letzten Bericht
sucht (Download-Token, Mailversand, `has_report`), und der Kunde bekäme einen
Downloadverweis auf nichts. `reports.validation_warnings` bleibt unverändert und
wird im `warn`-Pfad weiter geschrieben.

Geschrieben wird die Liste bei jedem Lauf, auch wenn nichts blockiert. Sonst
sieht der Admin im Review nicht, dass ein Lauf sauber war.

## Von Hand fahren

```bash
# Nur nachsehen
python -m reporter.gate --order <uuid>

# Abnahme: Daten gezielt beschaedigen und die Order anhalten
python -m reporter.gate --order <uuid> --damage abdeckung --apply
```

Beschädigt wird immer nur die Kopie im Speicher. `--apply` setzt Status und
Defektliste; zurück geht es über "Regenerieren nach Fix" im Admin-Review. In der
Pipeline steht dafür der manuelle Job `ops-gate-blocked`.

## Was nicht hierher gehört

Neue fachliche Prüfungen über Fakten gehören in den Prüfkatalog
(`reporter/catalog/checks/*.yaml`), nicht hierher. Dieses Paket prüft den
fertigen Bericht, nicht die Infrastruktur des Kunden.

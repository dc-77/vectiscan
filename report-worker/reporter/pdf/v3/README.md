# reporter.pdf.v3: Renderer (Session S4)

Aus `reporter.v3.ReportData` (S3) wird hier HTML und daraus mit WeasyPrint ein PDF.
Vorlage und Gestaltung stammen unveraendert aus dem abgenommenen Prototyp
(`report-prototype/build/template.html.j2`); `tests/pdf_v3/test_prototyp_paritaet.py`
weist das nach, indem es beide Vorlagen zur Laufzeit auf dieselben Daten anwendet.

## Aufruf

```bash
cd report-worker
python -m reporter.pdf.v3 --golden <order_id> -o bericht.pdf
python -m reporter.pdf.v3 --golden <order_id> --html-only -o bericht.html  # ohne WeasyPrint
python -m reporter.pdf.v3 --source <tar|verzeichnis> -o bericht.pdf
python -m reporter.pdf.v3 --order <order_id> --upload      # Tar aus MinIO, PDF nach scan-debug/v3/
python -m reporter.pdf.v3 --selftest                       # Abnahme im Abbild
```

Programmatisch:

```python
from reporter.pdf.v3 import render_html, render_report_v3

html, variant, warnungen = render_html(data)                  # braucht kein WeasyPrint
ergebnis = render_report_v3(data, "bericht.pdf", resolver=…)  # RenderResult
```

`reporter/worker.py` ruft bei `VECTISCAN_REPORT_LAYOUT=v3` `render_report_v3` direkt
auf; eine Adapterfunktion in der Aufrufform von v2 gibt es bewusst nicht, weil v3 ein
anderes Datenmodell liest.

`RenderResult` traegt `pages`, `words_per_page`, `sparse_pages`, `defects` und
`warnings`, seit S6b-1 auch `fill`, `kicker_pages`, `heading_pages`, `overflow` und
`layout_ok`. Der Renderer blockiert nicht: `defects` kommen aus
`reporter.v3.selfcheck.check_report_data` und werden gemeldet, nicht durchgesetzt. Ob
eine Order deswegen nicht ausgeliefert wird, entscheidet das Gate in Session S5.
`strict=True` wirft stattdessen `RenderGateError`; das nutzen CLI und Selbsttest.

## Dateien

| Datei | Inhalt |
|---|---|
| `render.py` | Jinja-Umgebung, Filter, URL-Fetcher, WeasyPrint-Aufruf, `RenderResult` |
| `context.py` | Datenmodell zu Vorlagenvariablen: Aufteilung von Kapitel 6, Verteilung, Anhangsbuchstaben |
| `variants.py` | Paketvariante: Titel, Fusszeile, welche Kapitel erscheinen |
| `screenshots.py` | Aufloesung der Bildnachweise gegen MinIO, Platzhalter |
| `checks.py` | Render-Pruefungen: halbleere Seiten, eingebettete Schriften, Gedankenstriche, Layout-Boxen (S6b-1) |
| `text.py` | die wenigen Saetze, die dem Renderer gehoeren |
| `pipeline.py` | Auftrag zu Reportdaten (Fakten, Katalog, v3) fuer Worker und Ops-Job |
| `templates/report.html.j2` | die Vorlage |
| `assets/fonts/` | Inter, mitgeliefert (siehe README dort) |
| `assets/screenshot-placeholder.svg` | Kachel, wenn ein Bildnachweis fehlt |

## Abweichungen vom Prototyp

1. **`autoescape=True`.** Der Bericht traegt Fremdtext aus den Fakten: Seitentitel,
   WHOIS-Felder, woertliche Werkzeugausgaben. Der Prototyp setzte ohne Maskierung und
   hat dadurch nachweislich Text verloren: im Verifikationsbefehl eines Befunds stand
   `</dev/null 2>/dev/null`, und der HTML-Parser hielt `</dev/null 2>` fuer ein Tag und
   warf es weg. Die vier `|safe`-Stellen sind auf Schleifen und zwei Filter umgestellt,
   das erzeugte Markup ist dasselbe. `undefined=StrictUndefined` kommt dazu, damit ein
   fehlendes Feld kracht statt als Luecke im Kundenbericht zu erscheinen.
2. **Kein hart verdrahteter Auftraggeber und kein hart verdrahtetes Paket.** Der
   Prototyp trug "Perimeter" an vier und "junkerwerk.de einzeln, drei Scandurchgaenge"
   an zwei Stellen im Markup. Beides kommt jetzt aus den Daten. `test_template_text.py`
   prueft die Vorlage gegen die Kundennamenliste aus `tests/textlint.py`.
3. **Kapitel 6 wird ab 21 Befunden geteilt** (Entscheidung DC): die 15 dringendsten im
   Hauptteil, der Rest vollstaendig und mit denselben Feldern im Anhang zu Kapitel 6.
   Kapitel 4 und Anhang A.2 zeigen weiterhin alle Befunde, und Kapitel 1 nennt immer
   Gesamtzahl und Verteilung. Weggelassen wird nichts.
4. **Anhangsbuchstaben werden berechnet.** Bei WebCheck faellt das Service-Inventar
   weg; feste Buchstaben liessen dort eine Luecke. `A` bleibt in jedem Fall bei den
   Bewertungsmassstaeben, deshalb bleibt die im Fliesstext zitierte Referenz `A.3`
   gueltig.
5. **`appendix.tool_findings`** (aus S3, Buendel mit `target: appendix`) bekommt eine
   Tabelle unter der Werkzeug-Ueberschrift. Ohne sie verschwaende diese Information
   still aus dem Bericht.
6. **Kein poppler.** Seitenzahl aus WeasyPrint, Wortzahl je Seite aus pypdf.

## Bildnachweise

`architecture.screens[].key` ist der MinIO-Schluessel (`<order>/<ip>__<vhost>.png` im
Bucket `scan-screenshots`). Die Vorlage schreibt `src="vectiscan-screenshot:<key>"`;
`render.py` faengt dieses Schema im URL-Fetcher ab und reicht alles andere, vor allem
die Schriftdateien, an WeasyPrint weiter. Netzzugriffe sind ausgeschlossen
(`allowed_protocols=("file", "data")`).

Fehlt ein Bild, erscheint eine Platzhalterkachel gleicher Groesse. Loest **kein**
einziger Schluessel auf, entfaellt Kapitel 3.4 ganz: ein Raster aus lauter
Platzhaltern ergaebe eine halbleere Seite. Die Golden-Tars enthalten keine Bilder
(S0c), die Tests laufen deshalb ohne.

## Seitenzahlen und halbleere Seiten

`tests/golden/render/expected-pages.json` haelt je Golden-Auftrag Seitenzahl und die
bekannten halbleeren Seiten. Eine *neue* halbleere Seite ist ein Fehler, eine bekannte
nicht. Fuer den Referenzauftrag (Junkerwerk, drei Laeufe) gilt die Vorgabe aus S4
unveraendert: keine halbleere Seite.

Kapitel 1.2 und Kapitel 2 fliessen an, erzwingen also keinen Seitenanfang, genau wie
Kapitel 4, 5 und die Anhaenge. Sonst passte Kapitel 1.1 bei datenreichen Auftraegen
nicht auf eine Seite und liess zwei Zeilen auf der naechsten stehen. Ueber die elf
Golden-Auftraege halbiert das die halbleeren Seiten von 14 auf 7, sechs Auftraege
haben gar keine mehr (Entscheidung DC, 20.09.). Die verbleibenden sieben sind
Ausklaenge langer Abschnitte und haengen an der Datenmenge, nicht an der Gestaltung.

Seit S6b-1 (spec/09 Teil 3) liest `checks.layout_scan` die Layout-Boxen von WeasyPrint
statt der Wortzahl: halbleer ist eine Seite mit weniger als 50 % Fuellhoehe
(`FILL_MIN`, ohne Deckblatt und letzte Seite), jede wird als Warnung gemeldet. Dazu
kommen ein Kicker ohne Ueberschrift auf derselben Seite, eine Ueberschrift als letztes
Element einer Seite und eine Box ausserhalb des Satzspiegels (`OVERFLOW_TOLERANCE`). Im
Produktionslauf sind das Warnungen; in der Golden-Render-Suite (`pruefe`, Entscheidung
DC) sind Kicker ohne Ueberschrift und Boxen ausserhalb des Satzspiegels Fehler. Die
Boxen sind keine oeffentliche API: fehlt ein Attribut, meldet der Renderer das als
Warnung, die Golden-Suite als Fehler. Die Vorlage haelt Kicker, Ueberschrift und
Tabellenkopf zusammen (`break-after: avoid`, `<thead>`), der Block Anhang D bis F steht
ohne erzwungenen Umbruch davor.

Seit Nachtrag 3 (Entscheidung DC 25.09.) nennt die Pruefung je halbleerer Seite die
Ursache (`RenderResult.sparse_causes`, Warnung und Ausgabe von `--update-pages`): den
freien Rest in mm und womit die Folgeseite beginnt, einen nicht umbrechbaren Block mit
Name und Hoehe, einen Kapitelanfang mit erzwungenem Seitenwechsel oder umbrechbaren
Inhalt. Regel: ist es ein einzelner Block, darf er nach seiner Kopfzeile umbrechen
(Kategorieblock in Kapitel 4 ab mehr als `CAT_KEEP` Zeilen, f77ccff2 Seite 11); vor
einem Kapitelanfang bleibt die Luecke stehen und ist ein Merkposten fuer S7 (1f8bc977
Seite 25, 2d2d4f39 Seite 27, je 165 mm frei).

Neu festschreiben nach einer gewollten Aenderung:

```bash
python -m reporter.pdf.v3 --update-pages    # Seitenzahlen, braucht WeasyPrint
python -m reporter.pdf.v3 --write-snapshot  # HTML-Schnappschuss, braucht kein WeasyPrint
```

## Was hier nicht passiert

Das blockierende Gate, `report_blocked` und die Admin-Defektliste (S5); der Umschalter
`VECTISCAN_REPORT_ENGINE`, der Wechsel der Vorgabe auf v3 und das Entfernen der alten
Reparaturkette (S6); Rahmenwerk-Anhaenge und Export (S7). `VECTISCAN_REPORT_LAYOUT=v3`
waehlt den Renderer in `reporter/worker.py`, Vorgabe bleibt `v1` im Code und `v2` in
`docker-compose.yml`.

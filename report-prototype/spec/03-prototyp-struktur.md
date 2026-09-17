# Report-Prototyp v3: Struktur, Datenquellen, Übernahme in die Applikation

Ziel dieses Dokuments: Claude Code soll den Prototyp (`build/`) in den report-worker
übertragen können, ohne den Report neu zu erfinden. Der Prototyp folgt
`02_Report_Aufbau_Neudesign.md` (drei Schichten, Triage statt CVSS-Sortierung, keine
Aufwände) und der Konsolidierten Struktur (Rot/Gelb/Grün/Blau × Dringlichkeit, fünf
Risikokategorien, Cover ohne Risikoindikator, Compliance-Mapping nur im Compliance-Paket).

## Dateien

| Datei | Zweck |
|---|---|
| `build/report_data.py` | Kuratierte Datenbasis (reine Daten, deutsch). Struktur = Ziel-Datenmodell für `report_mapper`/v3. |
| `build/template.html.j2` | Jinja2-Template mit eingebettetem CSS (VectiScan-Farben aus `branding.py`, Inter, DejaVu Sans Mono). |
| `build/build_report.py` | Gate-Checks (IDs lückenlos, Titel eindeutig, keine eigenen CVSS-Werte, zitierte CVE-Scores = Referenztabelle, Plan-Referenzen, Werkzeuge ohne Version), Render, WeasyPrint, Sparse-Page-Check. |
| `build/assets/*.jpg` | Sechs Screenshot-Kacheln (800×450, JPEG): OWA, IIS, OpenOTP aus dem Scan vom 31.08.; www.de, www.hu, nachhaltigkeit am 17.09. nachgeholt (`scripts/take-screenshots.py`, Playwright). Im Report ohne Datum. |
| `out/vectiscan-junkerwerk-perimeter-2026-08-31-v1.0.pdf` | Auslieferungsfähiger Report, 25 Seiten. |
| `out/report-data.json` | Dieselben Daten als JSON (für Tests/Fixtures). |

Build: `cd report-prototype/build && python3 build_report.py --raster` (WeasyPrint 69, jinja2;
Fonts: Inter Static-TTF, DejaVu Sans Mono). Renderer-Wechsel von ReportLab auf WeasyPrint ist eine
Entscheidung für Claude Code; das Template ist so gebaut, dass es auch als Vorlage für ReportLab-
Flowables dient (jede Sektion ist ein klar abgegrenzter Block).

## Seitenaufbau (25 Seiten bei 15 Befunden)

| Seite | Schicht | Inhalt | Datenquelle im Prototyp | Quelle in der Pipeline |
|---|---|---|---|---|
| 1 | Cover | Titel, Kunde, beide Domains, Host-/Hostnamen-Zahl, Meta, kein Risikoindikator | `meta` | `orders`, `scan_targets`, Katalog |
| 2 | 1 | Gesamtbewertung (dunkler Block), Ampel 5 Kategorien (Status + 4-Segment-Balken + Klartext), Top-3-Hebel | `glance` | `layer1_aggregator` (Kategorien, Hebel), Overall = max Kategorie |
| 3 | 1 | Kontext (Scope in einem Absatz), Abdeckungs-Hinweis, beobachtete Systeme → Bedeutung, „Was das für Sie bedeutet" | `glance.context`, `business` | `business_context` (datengetrieben aus vhost-Titeln, Tech, DNS), C3-Coverage |
| 4 bis 5 | 2 | Prüfumfang (Host-Tabelle mit Abdeckungsstatus), nicht im Scope, Einschränkungen (Tabelle), Zahlen-Kacheln, 4 Phasen, KI-Hinweis, kann/kann nicht | `scope` | `host-inventory`, `scan_results.status/skipReason`, `header_check.reachable`, `v2_data.build_methodology_stats` |
| 6 bis 8 | 2 | Tech-Stack je Host (Komponente, Version, Erkennung+Konfidenz, Patch-Status, Hinweis), Hinweise inkl. Reputation, Service-Karte, Posture (4 Blöcke), 3.4 Gesichtete Web-Oberflächen (2×3 Screenshot-Kacheln mit Host, Bedeutung, Aufnahmedatum) | `architecture` | `tech_table_builder` (bereinigt), `nmap`, `dns_records`, `dns_security`, `testssl`, `header_check`, `abuseipdb/otx/urlhaus` |
| 8 bis 10 | 2 | Befund-Landschaft nach Kategorie (ID, Dringlichkeit, Titel), Positivbefunde mit Kategorie | `findings`, `positives` | `befund_landschaft`, `positive_findings` |
| 10 bis 11 | 2 | Maßnahmenplan (Priorität, Maßnahme, Befunde, Effekt) + Zeitstufen-Legende | `plan` | `MASSNAHMEN_CLUSTER`, Recommendations mit Dringlichkeitsstufe statt „Tag 1-3" |
| 12 bis 22 | 3 | Befund-Details: Kopf (ID, Titel), Meta (Status, Dringlichkeit, Kategorie, Einstufung Exposition oder Hygiene), Betroffen + Quelle, Was wurde gefunden, Nachweis, Threat Intelligence (nur mit CVE), Auswirkung, gestufte Empfehlung, Verifikation, interne Referenz | `findings[]` | `findings_data.findings[]` + `verification_templates` + `severity_provenance` |
| 22 bis 25 | Anhang | A Triage, Einstufungsskalen, CVE-Referenzen; B Service-Inventar; C Werkzeuge (ohne Versionsnummern); D bis F auf der letzten Seite, Impressum am Seitenfuß | `appendix` | `appendix.py`, `SCAN_TOOLS`, Statistik aus `phase3_correlation` |

## Regeln, die der Prototyp umsetzt (und die die Pipeline übernehmen sollte)

1. **Ein Befund pro Sachverhalt, hostübergreifend.** 3306 und 5432 sind ein Befund; Header-Lücken auf
   OWA und IIS sind ein Befund. IDs erst nach Konsolidierung vergeben, lückenlos, nach Kategorie sortiert.
2. **Triage statt Severity-Wort, kein eigener CVSS.** Jeder Befund trägt `status` (rot/gelb/blau),
   `urgency` (Unverzüglich/In Kürze/Mittelfristig/Strategisch) und eine Einstufung: `scale: exposure`
   (kritisch/erhöht) für erreichbare Dienste, `scale: hygiene` (hoch/mittel/niedrig) für Abweichungen.
   CVSS-Werte nur als Fremdreferenz bei zitierten CVEs (NVD/ZDI, mit Quelle), gesammelt in Anhang A.3;
   der Gate-Check verweigert eigene Vektoren und prüft zitierte Scores gegen die Referenztabelle.
   Entscheidung DC 17.09.2026: selbst vergebene Scores kosten Reputation, wenn jemand nachrechnet.
3. **Quelle am Befund.** `source` nennt Werkzeug und ob aktiv oder passiv; Passivbefunde bekommen
   immer einen Verifikationsschritt und keinen CVSS.
4. **Abdeckung explizit.** `scope.hosts[].coverage` (voll/teil/keine) aus `reachable`-Flags und leeren
   Tool-Outputs; Einschränkungen als eigene Tabelle in Kapitel 2, Warnbox auf Seite 3.
5. **Tech-Tabelle ohne Rauschen.** Keine „Port 110 | unbekannt"-Zeilen; Shodan nur als Quelle mit
   Kennzeichnung „passiv"; Versionsstrings normalisiert (MariaDB-Präfix, „or later" → unbekannt);
   Patch-Status nur aktuell/veraltet/unbekannt/Lifecycle prüfen.
6. **Positivbefunde mit Kategorie** und Beleg, am Ende der Landschaft, nicht im Detailteil.
7. **Maßnahmenplan referenziert jeden Befund genau einmal**, Gate prüft das.
8. **Kein Aufwand, keine Kosten, kein „KI-gestützt".** KI-Einsatz in einem Satz mit konkreter Aufgabe.
9. **Sprache:** Sie-Form, deutsche Anführungszeichen, keine Gedankenstriche, Zahlen mit Punkt,
   Datum TT.MM.JJJJ; Umlaute echt (kein ae/ue/oe).
10. **Cover ohne Risiko, Klassifizierung im Fuß jeder Seite**, Seitenzahl „Seite n von N".
11. **Werkzeugliste ohne Versionsnummern** (nmap, nicht nmap 7.93); Gate prüft das.
12. **Screenshots als Sichtnachweis, nicht als Beleg:** 2×3 kleine Kacheln in Kapitel 3, jede mit
    Host und Bedeutung, ohne Aufnahmedatum (DC 17.09.2026); Login-Masken dürfen gezeigt werden.
    Fehlende Aufnahmen werden nachgeholt (hier: www.junkerwerk.de, www.junkerwerk.hu, nachhaltigkeit
    am 17.09.2026), die Herkunft steht nur intern in `report_data.py`/dieser Spec. Bei 403/Fehlerseiten
    Ausschnitt oben links.
13. **Impressum („Erstellt von") am Fuß der letzten Seite**, D bis F darüber (Flex-Spalte, 252 mm).

## Layout-Entscheidungen (WeasyPrint)

- A4, Ränder 22/18/20/18 mm, laufender Kopf mit Wortmarke und Kunde/Domains, Fuß mit Klassifizierung.
- Inter für Text, DejaVu Sans Mono für Nachweise; Tabellen mit `table-layout:fixed` und expliziten
  Spaltenbreiten (Summe 168 mm); Silbentrennung nur in Tabellenzellen (`hyphenate-limit-chars 14 6 6`).
- Kapitel 1 bis 3 und 6 beginnen auf neuer Seite; Kapitel 5 und die Anhänge fließen an
  (verhindert halbleere Seiten). Befundkopf + Meta + „Betroffen" sind unteilbar; Nachweisblöcke unteilbar.
- Farben nach Web-CI (`frontend/src/app/globals.css`, nicht mehr `branding.py`-Cyan): Cover-Grund
  `#0C1222`, Slate `#0F172A` (Überschriften), Teal `#2DD4BF` (Cover, Wortmarke „scan"), Teal-Line `#14B8A6`
  (Kapitellinien, Bullets), Teal-Text `#0F766E` (Kicker, Labels auf Weiß); Status wie Web-Tones
  Rot `#EF4444`, Gelb `#F59E0B`, Blau `#3B82F6`, Grün `#22C55E`, Grau `#94A3B8` für Flächen, Pill-Text
  eine Stufe dunkler. `branding.py` sollte auf diese Werte nachgezogen werden (WP7).
- Logo: Shield aus `frontend/src/components/VectiScanLogo.tsx` als Jinja-Makro (Kopf 4,2 mm, Cover 9 mm,
  Cover-Hintergrund 150 mm bei 7 % Deckung unten rechts angeschnitten, Impressum 12 mm); Wortmarke
  lowercase „vecti" + „scan" in Teal, Inter Bold, Laufweite -0,02 em.
- Service-Karte als Inline-Chips mit farbiger linker Kante; Posture als 4-spaltige Tabelle mit ✔/✘/○.

## Entschieden (DC, 17.09.2026)

- CVSS nur als Fremdreferenz (Regel 2).
- Screenshots ja, klein, 2 bis 3 nebeneinander, als Sichtnachweis (Regel 12).
- Werkzeuge ohne Versionsnummern (Regel 11).
- „Erstellt von" ans Seitenende der letzten Seite (Regel 13).
- OpenOTP-Portal ist das Standard-Portal von OpenOTP (Registrierung, Geräte anmelden, Self-Service);
  Text auf Seite 3 entsprechend.

## Offene Entscheidungen für DC

1. Compliance-Indikatoren auf Seite 2 (DSGVO Art. 32, BSI Basisabsicherung) sind im Prototyp
   weggelassen, weil die Konsolidierte Struktur das Mapping auf das Compliance-Paket beschränkt.
   Falls gewünscht: eine Zeile unter der Ampel.
2. Renderer: WeasyPrint (HTML/CSS, schnelle Iteration) oder ReportLab beibehalten. Der Prototyp
   ist HTML/CSS; eine Portierung der Flowables ist Aufwand, aber machbar.
3. Befund-ID-Schema: Prototyp nutzt `VS-2026-NNN` wie die App; `references/report_structure.md`
   sieht `{CLIENT_PREFIX}-{YEAR}-{NN}` vor.
4. Screenshot-Pipeline in der App: Nachaufnahmen brauchen einen zweiten Playwright-Lauf nach dem
   Scan (anderer Quell-IP-Pool oder Freischaltung), sonst fehlen die Website-Kacheln, sobald ein
   Hoster den Scanner blockt.

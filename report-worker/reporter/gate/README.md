# reporter/gate — das Berichts-Gate (S5)

Ein Bericht, den niemand vor der Auslieferung geprüft hat, ist eine Behauptung.
Dieses Paket macht daraus einen Arbeitsablauf: es sammelt die Defekte beider
Engines in einer Liste, hält den Bericht unter `strict` an und legt die Liste
dorthin, wo der Admin sie sieht.

## Was hier liegt

| Datei | Inhalt |
|---|---|
| `defects.py` | `Defect` (Engine, Prüfung, Stufe, Meldung, Befund-ID) und die Adapter für beide Engines; `payload()` baut den Inhalt von `orders.report_defects`. |
| `v3_checks.py` | Die Prüfungen, die über das Datenmodell hinausgehen (S5 bis S6b-4n). |
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
| Kein Werkzeuglauf mit Ergebnis | Fehler | Fällt der Lader aus, steht jede Zeile auf `empty` oder `unknown`; der Bericht liest sich dann wie eine unauffällige Prüfung (S6, offener Punkt nach S5b). |
| Mehr als fünf Beobachtungen ohne Regel | Warnung | Ein Hinweis auf fehlende Prüfungen, kein Fehler im Bericht. |
| Auftraggeber fehlt | Fehler unter `strict`, sonst Warnung | Bis S6 immer nur Warnung: der WebCheck-Bericht `75338c97` trug deshalb 39-mal „Auftraggeber“ und ging mit 0 Fehlern durch (spec/08 Punkt 8). Rückweg ist das Kundenkontext-Feld im Admin. |
| Einschränkungszeile ohne betroffene Prüfung (`einschraenkung_ohne_pruefung`) | Fehler | S6b-1 (spec/09 Q9): eine Zeile in 2.2 nennt, welche Prüfungen ausfielen. |
| Werkzeugname im Kundentext (`werkzeugname_im_kundentext`) | Fehler | S6b-1 (spec/09 Q10): Einschränkungen und Posture in Kundensprache, ohne „zap_active“ oder „testssl“. |
| Rolle ohne Fakt (`rolle_ohne_fakt`) | Fehler | S6b-1 (spec/09 Q2): Zusammenfassung, Kontext und Systemsätze nennen nur belegte Rollen. |
| Aussage ohne erfüllte Fakten-Bedingung (`aussage_ohne_fakt`) | Fehler | S6b-2 (spec/09 Q4): jede Aussage eines Befunds stammt aus einer fehlgeschlagenen Prüfung, deren Bedingung für die genannten Mitglieder gilt; seit S6b-4 auch Titelvarianten. |
| Zahl mit Zähleinheit widerspricht 2.1 (`zaehlung_widerspruch`) | Fehler | S6b-2 (Nachtrag S6b-1): „4 Hosts“ bei 3 Systemen. |
| Header im Befundtext, der laut Messung nicht fehlt (`header_nicht_fehlend`) | Fehler | S6b-3 (spec/10 R2): castenow VS-007/009 und huendgen VS-009 nannten X-Frame-Options, obwohl die Endseite ihn setzte. |
| Einschränkung neben Befund oder „unauffällig“ derselben Messung (`einschraenkung_widerspricht_befund`) | Fehler | S6b-3 (spec/10 R4): „nicht prüfbar“ und Befund zum selben Subjekt (DMARC, Zertifikat, Header). Familien in `catalog/families.py`. S6b-4 (spec/11 T4): an Fehlerseite und Sicherheitsabfrage sind HSTS und die übrigen Header dieselbe Messung (heuel online: HSTS-Befund an der 429 neben „nur an einer Sicherheitsabfrage gemessen“); HSTS aus testssl oder von der Endseite ist eine eigene Messung. S6b-4n (spec/11 N2, E24): ein gesetzter HSTS-Header an einer Fehlerseite (400, nie 429) ist ebenfalls eine eigene Messung. |
| Positivbefund und Befund am selben Host:Port (`positiv_widerspricht_befund`) | Fehler | S6b-3 (spec/10 R7): POP3 110 bei lumbeck-wolter, junkerwerk und heuel stand im Positivbefund und als „ließ sich nicht feststellen“. |
| Posture widerspricht den Befunden (`posture_widerspricht_befund`) | Fehler | S6b-3 (spec/10 R8): „unauffällig“ neben einem Befund derselben Regel oder „Handlungsbedarf“ ohne Befund (DANE bei MX beim Dienstleister). S6b-4 (spec/11 T16): alle vier Karten, jeder neutrale Zustand („softfail“, „teilweise geprüft“, „nicht prüfbar“, „entfällt“) neben einem gelben oder roten Befund, Zertifikatsregeln an der Transportzeile je Host (`pulls`). |
| Nachweis ohne Regelfakt (`nachweis_ohne_regelfakt`) | Fehler | S6b-4 (spec/11 T3): der Nachweis nennt den Fakt der Regel (Header mit Wert, XML-RPC-Adresse, „VRFY in der EHLO-Liste“); dortmund-beach VS-014 nannte nur „Antwort: 200“. Muster in `REGELFAKT`. S6b-4n (spec/11 N3): „bewertet an der Endseite“ nur, wenn die Header aus der Endantwort stammen (`header_eval.final_response`); heuel ose zitierte die erste Antwort (gleiche ETag wie header_check). |
| IPv6-Adresse laut DNS nicht im Inventar (`ipv6_ohne_inventar`) | Warnung | S6b-4 (spec/11 T7): bis S6c übernimmt der Scanner AAAA-Adressen nicht; Kapitel 2 nennt sie als nicht geprüft. S6b-4n (spec/11 N13): nur IPv6 (weitere A-Einträge stehen seit Fakten 1.3.0 ebenfalls in `additional_ips`), Wortlaut „nicht im Scan-Inventar, im Bericht als ungeprüft ausgewiesen“. |
| Messung an einer Adresse außerhalb des Inventars (`messadresse_ausserhalb_inventar`) | Warnung | S6b-4 (spec/11 T7): DNS-Rotation (huendgen testssl an 52.59.120.70, heuel an 216.150.1.129); Kapitel 2 nennt die Messadresse. |
| Firmenname nicht bestätigt (`firmenname_nicht_bestaetigt`) | Warnung | S6b-4 (Entscheidung E23): Firmenname oder Kurzname mit Quelle `recherche`; der Admin bestätigt ihn vor der Freigabe. |
| Positivbefund ohne Rohfakt (`positiv_ohne_rohfakt`) | Fehler | S6b-4n (spec/11 N6): jedes im Positivbefund genannte Subjekt braucht ein bejahtes Ergebnis seiner Regel; für den Zonentransfer zusätzlich den eigenen AXFR-Lauf je Domain im Nachweis (`ROHFAKT_POSITIV`). junkerwerk P06 nannte .hu ohne eigenen Fakt, bergersysteme P06 die CDN-Kante. |
| Anmeldename im Kundentext (`anmeldename_im_kundentext`) | Fehler | S6b-4n (Entscheidung E25, Vorschlag umgesetzt): WordPress-Anmeldenamen stehen nur als Anzahl und Fundweg im Bericht, die Namen bleiben in den Rohdaten (castenow VS-018). Geprüft werden Befunde, Empfehlungen, Positivbefunde und Anhang C. |
| Passivport 25 ohne Einschränkungszeile (`e5_fehlt`) | Fehler | S6b-3 (spec/10 R10): E5 je Adresse, nicht nur für Hosts ohne andere Ursache. |
| Zusage im Kundentext (`zusage_im_kundentext`) | Fehler | S6b-3 (spec/10 R12): „wir prüfen sie und nehmen … auf“, „auf Anfrage bereitgestellt“. |
| CVE im Befund ohne Zeile in A.3 (`cve_ohne_a3`) | Fehler | S6b-3 (spec/10 R14): dortmund-beach zitierte 17 CVE aus wpscan bei leerem A.3. |
| Gefundene Namen nicht geprüft (`namen_nicht_geprueft`) | Warnung | S6b-3 (spec/10 R5): bis S6c die Hostsuche repariert; Kapitel 2 nennt die Namen. |
| Frist zwischen Scan- und Berichtstag abgelaufen (`frist_vor_berichtsdatum`) | Warnung | S6b-3 (spec/10 R18): Hinweis an den Admin im Review, den Stand beim Kunden zu prüfen (castenow mailstore 24.09. bei Bericht vom 26.09.). |

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

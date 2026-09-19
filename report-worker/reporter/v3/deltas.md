# Abweichungen der Reportdaten v3 vom Prototyp

Stand 19.09.2026, Session S3. Der Prototyp
(`report-prototype/out/report-data.json`, 15 Befunde und 8 Positivbefunde fuer den
Junkerwerk-Auftrag) ist handkuratiert. Die Reportdaten v3 entstehen deklarativ aus
Fakten und Pruefkatalog. Wo beides auseinanderlaeuft, steht hier der Grund.

Entscheidung DC vom 19.09.2026: Abnahme ist Abdeckung, nicht Gleichheit. Jeder
Sachverhalt des Prototyps muss als Befund erscheinen; jede Abweichung braucht eine
Begruendung an dieser Stelle. Der Test dazu ist
`tests/v3/test_golden_junkerwerk.py`.

## Ergebnis fuer Junkerwerk, Lauf 1

| Groesse | Prototyp | v3 |
|---|---|---|
| Befunde | 15 | 16 |
| Positivbefunde | 8 | 9 |
| Zeilen im Massnahmenplan | 10 | 10 |
| Werkzeugbefunde im Anhang | 0 | 9 |

Alle 15 Soll-Befunde und alle 8 Soll-Positivbefunde sind abgedeckt.

## Abweichungen

1. **Zuschnitt der Befunde.** Die Buendelung ist deklarativ (`merge_by` je Buendel), die
   des Prototyps redaktionell. Konkret: VS-2026-013 (Header-Luecken auf zwei Hosts) wird
   zu zwei Befunden, weil `web_header_hygiene` nach Host trennt und die Massnahme je
   Host eine andere ist. Die Aufteilung ist in `tests/v3/test_golden_junkerwerk.py`
   unter `GETEILT` festgehalten; eine weitere Aufteilung faellt dort auf.

2. **Anmeldeportale sind ein eigener Befund.** Der Prototyp verarbeitet
   `login_portal_exposed` nur im Geschaeftskontext und in Hebel 2. Der Katalog laesst
   die Pruefung fehlschlagen, also entsteht daraus das Buendel
   `access_portals_exposed`. Das ist der zusaetzliche sechzehnte Befund.

3. **Standardseite ist niedrig statt mittel.** `default_page_exposed` steht im Katalog
   auf `niedrig` (Entscheidung S2: die reine Auslieferungsseite ist kein
   Handlungsdruck), der Prototyp hatte VS-2026-003 wegen des Gateway-Kontexts auf
   `mittel`. Damit ist der Befund blau statt gelb.

4. **Exim ist ein Passivbefund, kein EOL-Befund.** VS-2026-004 erscheint als
   `passive_service_version_unverified`. Ohne Termin aus dem Herstellerfeed ist eine
   EOL-Behauptung nicht belegbar (Entscheidung S2, Negativfixture NEG-EOL).

5. **Zertifikatsbefund nur im hu-Lauf.** `cert_hostname_mismatch` faellt nur im Lauf
   gegen junkerwerk.hu; im Multi-Lauf ist die Pruefung positiv. VS-2026-010 des
   Prototyps stammt aus diesem Lauf.

6. **Anhang A.3 bleibt leer.** `facts.threats` traegt fuer Junkerwerk zwei CVE aus
   testssl, beide ohne Fremdwert (kein NVD-Score, kein KEV-Eintrag). Ohne Fremdwert wird
   nicht zitiert; der SWEET32-Verweis des Prototyps ist nicht belegt. Sobald die
   Anreicherung aus Phase 3 in den Fakten ankommt, fuellt sich der Anhang von selbst.

7. **Zusaetzliche Positivbefunde.** v3 meldet zusaetzlich "Webdienst mit
   Transportverschluesselung" (`http_no_tls` bestanden). Der Prototyp laesst ihn weg.
   Ein belegter Positivbefund mehr ist kein Schaden.

8. **Erzaehltexte sind Vorlagen.** `plan[].action` und `[].effect`, `glance.levers`,
   `business.observed[].system`, `architecture.notes`, `scope.limitations[].detail`,
   `appendix.filtering` und `appendix.repeat` sind im Prototyp handgeschrieben. v3
   erzeugt sie aus `narrative.py` und den Fakten; der Wortlaut weicht ab, die Aussage
   nicht.

9. **Zahlen sind neu definiert.** `meta.tool_runs` ist die Zahl der Abdeckungszeilen,
   `meta.raw_findings` die Zahl der Einzelbeobachtungen aus Katalog, Ignorierliste und
   Auffangregeln, `meta.after_fp` die Zahl der fehlgeschlagenen Pruefgruppen. Der
   Prototyp hat diese Zahlen von Hand ueber drei Laeufe gezaehlt.

10. **Werkzeugbefunde im Anhang.** ZAP-Informationsalerts und veraltete
    JavaScript-Bibliotheken stehen ueber das Buendel `tool_findings_unrated` im Anhang
    statt als Befund (spec/06 Abschnitt 4, Stufe 2). Der Prototyp hatte diesen Abschnitt
    noch nicht; `appendix.tool_findings` ist deshalb neu im Datenmodell.

11. **Kein `temperature` beim Prosa-Aufruf.** `claude-opus-4-7` nimmt den Parameter
    nicht mehr an. Determinismus kommt aus Cache, Gate und Katalog-Fallback.

12. **Screenshots ohne Bilddatei.** `architecture.screens` entsteht aus
    `facts.fqdns[].screenshot_key`. Die Golden-Tars enthalten keine Bilder (S0c hat sie
    entfernt); die Aufloesung des Schluessels gegen MinIO macht der Renderer in S4.

13. **Zeitzone.** Das Scanfenster steht in Ortszeit (Europe/Berlin). Fehlt die
    Zeitzonendatenbank im Image, bleibt es bei UTC, und der Bericht schreibt das an die
    Uhrzeit. `tzdata` steht deshalb in `requirements.txt`.

## Bewusst nicht uebernommen

- **Top-N-Auswahl je Paket.** Die alte Selection kappt auf 15 Befunde je Perimeter-
  Bericht. In v3 ist jeder Befund ein konsolidierter Sachverhalt mit Massnahme; ein
  Kappen wuerde belegte Befunde aus dem Bericht nehmen, ohne es zu sagen. Der
  castenow.de-Auftrag zeigt mit 29 Befunden, dass die Frage gestellt werden muss; sie
  ist eine Produktentscheidung und steht als offener Punkt im Abschlussbericht zu S3.

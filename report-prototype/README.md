# Report-Prototyp (Junkerwerk, Perimeter)

Arbeitsordner für einen auslieferungsfähigen Report auf Basis der drei Scans vom 31.08.2026,
gebaut außerhalb der Report-Pipeline. Der Prototyp ist die Vorlage für den finalen Report in der
Applikation (Übernahme mit Claude Code, siehe `spec/03-prototyp-struktur.md`).

## Ordner
- `input/<label>/` Rohdaten aus der API je Order (gitignored): order, findings, correlation, results,
  events, report-versions, aktuelles Pipeline-PDF, Screenshots. Laden: `scripts/fetch-order.sh <orderId> <label>`
  mit `vectiscan.creds` (Zeile 1 E-Mail, Zeile 2 Passwort, gitignored).
- `spec/00-erstsichtung.md` erste Sichtung des Pipeline-Outputs.
- `spec/01-rohdaten-analyse.md` verifizierte Fakten je Host, Falschbefunde, methodische Einschränkungen.
- `spec/02-scan-drift.md` Vergleich der drei Läufe (multi, de, hu) mit Ursachen und Code-Anknüpfpunkten.
- `spec/03-prototyp-struktur.md` Seitenaufbau, Datenmodell, Regeln, offene Entscheidungen.
- `spec/04-umsetzungsplan-report-v3.md` Reputationsfallen-Register, Zielarchitektur, Arbeitspakete, Definition of Done für den Livegang.
- `scripts/take-screenshots.py` Playwright-Nachaufnahmen für Web-Oberflächen (Container).
- `build/report_data.py` kuratierte Datenbasis, `build/template.html.j2` Layout, `build/build_report.py` Gate + Render.
- `out/` erzeugte PDFs, HTML und `report-data.json` (gitignored).

## Build
```
cd report-prototype/build
python3 build_report.py --raster      # braucht weasyprint 69, jinja2, cvss, Inter + DejaVu Sans Mono
```

## Orders (31.08.2026, Paket perimeter, Status pending_review)
| Label | Order-ID | Ziel |
|---|---|---|
| multi | 0bf16342-ed96-4b0e-a596-05aee3a62cb5 | junkerwerk.de + junkerwerk.hu |
| de    | 2572eebc-6135-40e6-b1d2-e9dfccc20ae6 | junkerwerk.de |
| hu    | a6df9d9d-eccd-49d1-8dd3-b00a5e005108 | junkerwerk.hu |

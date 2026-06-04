# Demo-Seed & Guided-Demo-Pfad (VEC-86 / PA-6)

Ziel: Vertrieb (anfangs Board/Mensch) kann **jederzeit** eine verlässliche
VectiScan-Demo fahren — ohne 60–90 Min auf einen echten Scan zu warten.

Dieser Seed legt einen **synthetischen Demo-Mandanten** mit je einem fertigen
Report pro umsatzrelevantem Paket (WebCheck, Perimeter, Compliance) an. Alle
Zieldaten sind synthetisch (RFC-6761-`.test`-TLD, garantiert nicht auflösbar),
es werden **keine echten Kundendaten / PII** verwendet.

## Was der Seed anlegt

| Element | Wert |
|---|---|
| Mandant | `VectiScan Demo GmbH` |
| Demo-Login | `demo@vectiscan.tech` |
| Passwort | `VectiScanDemo2026!` (überschreibbar via `DEMO_PASSWORD`) |
| Rolle | `customer` (sieht nur die eigenen Demo-Scans) |

Drei fertige Reports (`status = report_complete`, bezahlt):

| Paket | Synthetisches Ziel | Gesamtrisiko | Befunde |
|---|---|---|---|
| WebCheck | `demo-shop.vectiscan-demo.test` | MEDIUM | 6 (0C / 0H / 4M / 2L) |
| Perimeter | `demo-corp.vectiscan-demo.test` | HIGH | 10 (1C / 3H / 4M / 2L) |
| Compliance | `demo-stadtwerke.vectiscan-demo.test` | CRITICAL | 11 (1C / 4H / 4M / 2L) + NIS2/§30-BSIG-Summary |

Jeder Report enthält:
- `reports.findings_data` → speist Dashboard, Risk-Gauge, Top-Findings, Severity-Counts.
- Ein echtes, herunterladbares **PDF** in MinIO (`scan-reports/demo/<paket>/…`).

## Ausführen

Voraussetzung: laufende Postgres- + MinIO-Container (z. B. via
`docker-compose.dev.yml`) mit den üblichen `DATABASE_URL` / `MINIO_*`-ENV-Vars.

```bash
cd api
npm run seed:demo
```

Der Seed ist **idempotent**: er räumt vorhandene Demo-Daten (feste UUIDs,
Präfix `d0000000-…`) auf und legt sie frisch an. Mehrfaches Ausführen ist
gefahrlos und erzeugt deterministisch denselben Zustand.

Im laufenden Stack (Server) entweder im `api`-Container:
```bash
docker compose exec api npm run seed:demo
```

### Quellen / Architektur (für Entwickler)
- `api/src/scripts/seed-demo.ts` — Orchestrierung (DB + MinIO, idempotent).
- `api/src/scripts/demoReportPdf.ts` — abhängigkeitsfreier PDF-Generator (Node,
  kein Python/reportlab, kein Claude-API, kein echter Scan nötig).
- `api/src/scripts/demo-data/{webcheck,perimeter,compliance}.json` — die
  synthetischen `findings_data`-Fixtures (Single Source of Truth für PDF + Dashboard).

Befunde/Texte ändern → die jeweilige JSON-Fixture anpassen und `npm run seed:demo`
erneut laufen lassen. PDF und Dashboard-Daten bleiben automatisch konsistent.

## Guided-Demo-Pfad (Bildschirme)

Reproduzierbarer Klickpfad für die Demo (Talktrack/Detailtext liefert PM, VEC-86):

1. **Login** — `scan.vectigal.tech` (bzw. lokal Frontend) → `demo@vectiscan.tech` /
   `VectiScanDemo2026!` → landet auf dem **Dashboard**.
2. **Dashboard** — KPI-Karten (Domains, Scans gesamt, Gesamtrisiko) + drei
   Paket-/Einzelscan-Karten mit Risk-Badge und Severity-Verteilung.
3. **Paket öffnen** — eine Karte anklicken → Scan-Detailseite (`/scan/<orderId>`)
   mit **Risk-Gauge**, **Top-Findings** und Befundliste.
4. **PDF herunterladen** — „Report herunterladen" → das gebrandete PDF öffnet sich.
   - Für Perimeter (HIGH) und Compliance (CRITICAL) lässt sich der „Aha-Effekt"
     gut zeigen; WebCheck (MEDIUM) eignet sich als „so sieht ein sauberes
     Schnell-Audit aus".

## Acceptance-Criteria-Mapping (VEC-86)

- **AC1** (synthetischer Mandant + je 1 Report pro Paket, synthetische Daten) →
  erfüllt durch diesen Seed. ✅ (CTO/Coder)
- **AC2** (Login reproduzierbar → Dashboard mit Risk-Gauge + Top-3-Findings +
  herunterladbarem PDF) → erfüllt; reproduzierbar über `npm run seed:demo`. ✅ (CTO/Coder)
- **AC3** (dokumentiertes Demo-Skript + QA-Gegenlauf) → Demo-Skript/Talktrack
  liefert PM (Paul), QA läuft den Pfad einmal ohne Vorwissen gegen. ⏳

## Hinweise

- Die PDFs sind **Demo-Reports mit synthetischen Daten** — bewusst kein
  Ersatz für den vollen Python-Report-Worker-Output. Sie enthalten Cover,
  Executive Summary (Risk-Box + Severity-Verteilung + Empfehlungen),
  detaillierte Befunde, positive Feststellungen und Haftungsausschluss.
- Branding-Farben sind an `report-worker/reporter/pdf/branding.py` angelehnt.
- Kein Seed in Produktion mit echten Mandanten vermischen — die festen
  Demo-UUIDs (`d0000000-…`) sind klar abgegrenzt und nur über diesen Seed im System.

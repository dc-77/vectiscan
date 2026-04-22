# VectiScan — Review-TODO (Stand: 2026-04-21)

Offene Punkte aus alten Plänen, die noch nicht umgesetzt sind. Konsolidiert
beim Doc-Cleanup am 2026-04-21 aus `PIPELINE-PLAN-v2.md` (gelöscht),
`SCAN-PIPELINE-v2.md` (gelöscht), `KNOWN-ISSUES.md` (Root) und
`VectiScan_Master_Plan.md` (April-UX-Audit).

Status-Notation: `[ ]` offen, `[~]` teilweise umgesetzt, `[!]` blockierend
für ein anderes Feature.

---

## A. Master Plan (UX) — offene Tickets

Sprints 1–5 sind laut Commit-Historie überwiegend umgesetzt
(`f10ed4d`–`5d48987`). Die folgenden Punkte aus dem Master Plan sind nach
Code-Review noch offen:

### Konversions- und Pricing-Strategie
- [ ] **TICKET-051 (Pricing-Überarbeitung)** — Entscheidung steht aus, ob
      kostenloser WebCheck wirtschaftlich tragbar ist. Pricing-Seite ist da,
      aber gestuftes Modell („gratis → einmalig → Abo") ist noch
      „auf Anfrage".
- [ ] **L4 (Preisindikation auf Landing)** — keine konkreten Preise auf
      `/`. Mindestens „ab X €/Monat" oder Rechner ergänzen.
- [ ] **L7 (Lead-Magnet WebCheck)** — Strategisch verknüpft mit TICKET-051.
- [ ] **L6 (Social Proof)** — Kundenlogos / Testimonials fehlen auf der
      Landing Page.

### Onboarding & Conversion
- [~] **TICKET-050 (Onboarding-Flow)** — `/welcome` existiert; Dashboard-
      Checkliste mit „Ersten Scan / Report angesehen / Domain verifiziert /
      Abo abgeschlossen" fehlt noch.
- [ ] **TICKET-054 (Scan + Abo zusammenführen)** — `/scan` und `/subscribe`
      sind weiter getrennt; einheitlicher Flow „Domain → Ergebnis →
      regelmäßig überwachen?" fehlt.

### Domain-Verifizierung
- [ ] **TICKET-052 / P6 (Multi-Methode)** — Aktuell DNS-TXT, File, Meta-Tag.
      Methode „E-Mail an Domain-Admin" (`admin@`/`webmaster@`) und
      „IT-Admin einladen" sind nicht implementiert.

### Notifications
- [ ] **TICKET-053 (Notification-Center)** — Glocke ist als Placeholder im
      `AppHeader` (`{/* Notification bell placeholder */}`), kein Backend.
      Geplante Events: Scan abgeschlossen, neuer kritischer Befund,
      Abo läuft ab, Maßnahmen erledigt.
- [ ] **P4 (E-Mail bei Scan-Abschluss)** — kein E-Mail-Versand für fertige
      Reports; Resend ist eingerichtet (Password-Reset funktioniert),
      Report-E-Mail nicht angebunden. Subscription-Tabelle hat bereits
      `report_emails TEXT[]`.

### Reporting & Maßnahmen
- [ ] **TICKET-043 (Empfehlungen mit Tracking)** — Checkboxen pro
      Empfehlung, Fortschrittsbalken, Auto-Abgleich bei Re-Scan,
      CSV-Export für Ticket-Systeme.
- [ ] **SD6 (Inline-PDF-Preview)** — Optional; PDF.js-Renderer auf der
      Detail-Seite wäre ein Plus.

### Admin-Komfort
- [ ] **AD1 (AI-Kosten in EUR statt USD)** — `GET /api/admin/ai-costs`
      liefert USD; entweder umrechnen oder als „USD (Anthropic API)"
      kennzeichnen.
- [ ] **AD6 (Domain-Verifizierungs-Queue im Admin)** — Pending-Domains-
      API existiert (`/api/admin/pending-domains`), aber dedizierte UI im
      `/admin` für Approve/Reject von Subscription-Domains fehlt teilweise.

### Frontend-Polish
- [ ] **F1/F2/F3 (Forgot-Password Container/Button/Label)** — Card-Style
      und Brand-Farbe ggf. nachziehen.
- [ ] **W1 (Umlaut-Sweep im Abo-Wizard)** — Master Plan listet 8+ Stellen.
      Bei Sprint 1 wurden Umlaute pauschal gefixt — Wizard-Strings nochmal
      prüfen.
- [ ] **D7/D9 (Dauer- und Timestamp-Formatierung)** — `formatDuration`
      ist in `lib/utils` vorhanden; Stichprobe machen, ob alle Stellen
      `STATUS_LABELS` und Duration-Helper benutzen.

---

## B. Pipeline v2 — abgehakt + Restpunkte

Aus dem ehemaligen `PIPELINE-PLAN-v2.md` (Phasen I–VI). Stand:
nahezu vollständig in Code, einige Komfortfeatures offen.

### Phasen I–V (Foundation, Passive Intel, Deep Scan, Correlation, Reports)
**Status: Implementiert.** Code in `scan-worker/scanner/passive/`,
`correlation/`, `phase0a.py`, `phase3.py`; Report-Worker mit 5 Mappern
und Compliance-Modulen. Migration 009 ist eingespielt.

### Phase VI — Frontend-Integration (Restpunkte)
- [~] **PackageSelector mit Feature-Vergleichstabelle** — Selector ist da,
      Vergleichstabelle nur im Admin/Subscribe vorhanden, nicht direkt im
      Order-Wizard.
- [ ] **Phase-0a-Anzeige im Scan-Detail** — `passiveIntelSummary` wird
      vom Backend geliefert (`GET /api/orders/:id`), aber kein dediziertes
      UI-Modul rendert Shodan/AbuseIPDB/SecurityTrails-Befunde auf
      `/scan/[orderId]`.
- [ ] **Phase-3-Korrelations-Tab** — `correlationData` und
      `businessImpactScore` sind im API-Response, ein Korrelations-/
      Cluster-Tab im Debug-Modus fehlt.
- [ ] **Findings-Viewer: Confidence/EPSS/CISA-KEV Badges** — Daten kommen
      vom Report-Worker durch (Phase 3 enrichment), Badges im
      `FindingsViewer.tsx` ergänzen.
- [ ] **Dashboard: Business-Impact-Score** — Wert ist im Cockpit-Endpoint
      noch nicht sichtbar (`dashboard-summary` liefert Risk + Counts,
      aber keinen Score).

### Sonstiges (offen)
- [ ] **TLSCompliance im Frontend** — Paket ist als sechstes Paket
      implementiert (Backend, Mapper, packages.py), erscheint aber nicht
      im PackageSelector und im Schedule-Dropdown ist es Master-Plan-
      Befund **Z5** (LOW, noch offen).

---

## C. Bekannte Probleme aus `KNOWN-ISSUES.md` (Root)

Übernahme der noch offenen Items:

### P2 — Lieferketten-Seite Layout bei vielen Findings
- [ ] **Niedrig.** Bei mehr als 8 Findings bricht die SupplyChain-1-Seiter-
      Sektion auf eine zweite Seite um. Workaround: Claude-Prompt sollte
      max 8 Findings für die Sektion ausgeben — falls das nicht
      verlässlich klappt, im PDF-Generator clampen.

### P3 — WebCheck-Scope-Anzeige
- [ ] **Info.** Scope-Block im Report listet Phase-0-Tools (crt.sh,
      subfinder) nicht explizit. Optisch im Report nachziehen.

### A1 — amass-Timeout bei großen Domains
- [ ] **By design.** amass kann den Phase-0-Timeout (15 Min im Perimeter+)
      reißen; partial output wird gelesen. Keine Action geplant, hier nur
      dokumentiert.

---

## D. Aus Memory-Notizen

### MITRE-CWE-API-Anbindung (`project_cwe_api.md`)
- [~] **In Vorbereitung.** `report-worker/reporter/cwe_api_client.py`
      existiert; Anbindung im QA-Check (Severity-Validierung pro CWE)
      noch nicht voll integriert. CWE-Reference (`cwe_reference.py`) wird
      lokal genutzt.

### Hacker-Terminal-Upgrade (`project_terminal_upgrade.md`)
- [ ] **Ausstehend.** Tool-Start-Events, Spinner, CRT-Effekt, Glitch-
      Animation für `/scan/[orderId]`-Terminal. 7 Dateien geplant; laut
      Memory liegen 3 unpushed Commits — beim nächsten Sprint sichten und
      ins Repo bringen.

### Scan-Pipeline: Katana nach Phase 1 verschieben (`project_open_items.md`)
- [ ] **Offen.** Aktuell läuft Katana (laut Master-Spec) noch in Phase 2
      Stage 1. Zur Diskussion: Endpoints aus Phase 1 als Spider-Seed nach
      ZAP, statt Katana separat. Noch nicht umgesetzt; Memory-Notiz aus
      März.

---

## E. Aus Dashboard-Gruppierungs-Refactor (2026-04-21)

- [ ] **Backfill alter Orders zu Abos**: Bestehende Orders mit
      `subscription_id = NULL` werden nicht nachträglich verknüpft,
      auch wenn der Customer inzwischen ein passendes Abo hat. Ein
      einmaliges Backfill-Script könnte nach Domain matchen und das
      älteste passende Abo zuordnen — bewusst nicht im Scope der
      Dashboard-Gruppierung.
- [ ] **STRUCTURE.md**: neue Datei `frontend/src/lib/grouping.ts` und
      Route `frontend/src/app/scans/[groupKey]/page.tsx` ergänzen.
- [ ] **DB-CHECK-Constraint für Order-Status**: Aktuell kein CHECK auf
      `orders.status` — neue Statuswerte (`pending_review`, `approved`,
      `rejected`) sind nur dokumentiert. Optional Migration mit CHECK.

## F. Hygiene / Doku-Konsistenz

- [ ] **`KNOWN-ISSUES.md` und `PACKAGE-COMPARISON.md` (Root)** sind aus
      der v1-Welt (3 Pakete). Entweder löschen oder auf 6 Pakete
      hochziehen — Inhalt überschneidet sich mit
      `docs/PROTOTYPE-SCOPE.md` und `docs/SCAN-TOOLS.md`.
- [ ] **`plan.md` (Root)** ist der historische Auth-Migrationsplan. Kann
      gelöscht oder nach `docs/historical/` verschoben werden.
- [ ] **CHECK-Constraint `chk_orders_package` in DB** enthält
      `tlscompliance` nicht — Validation passiert im API-Layer
      (`VALID_PACKAGES`). Entweder Migration nachziehen oder dokumentieren
      (in `DB-SCHEMA.sql` ist es als Hinweis vermerkt).
- [ ] **Stripe-Integration**: Subscription-Code ist auf
      `paid_at`/`amount_cents`/`stripe_*`-Felder vorbereitet, geht aber
      direkt auf `active`. Sobald Stripe live geht, Checkout-Session +
      Webhook + Payment-Status-Handling nachziehen.

## G. Multi-Target Follow-ups (Stand: 2026-04-22)

Umgesetzt: Migration 014, Precheck-Worker, validate-targets-Endpoint,
POST /api/orders + /api/subscriptions auf `targets[]`, Admin-Review-API +
Scan-Authorizations, Scope-Enforcement im Scan-Worker. Siehe
`docs/MULTI-TARGET-PLAN.md` und Commits `194c921`..`7b620ab`.

Offene Follow-ups:

- [ ] **KI #1 Tier-Prompt**: `plan_host_strategy` gibt aktuell weiterhin
      `action: scan|skip` zurueck. Der geplante Umbau auf
      `tier: 1|2|3|null` inkl. harter Regeln ("fqdn_specific/ipv4 → min
      Tier 2") und Tier-Overflow-Override steht noch aus. Ohne Tier-Split
      laufen alle Scan-Hosts im bestehenden max_parallel-Modus — das ist
      funktional, aber bei 50 Hosts ineffizient.
- [ ] **`packages.py` Tier-Konfiguration**: `tier1_tools`, `tier2_tools`,
      `tier3_tools` + Max-Host-Budgets pro Tier noch nicht eingefuehrt.
- [ ] **Report-Worker Unreachable-vs-Fixed-Diff** (MULTI-TARGET-PLAN §10.3):
      Kompletter Neubau der Diff-Logik im Report-Worker. Datenbasis
      (`scan_target_hosts`, `scan_run_targets`) ist durch Migration 014 /
      Scope-Enforcement bereits befuellt.
- [ ] **Cloud-Provider-Range-Refresh**: `precheck/saas_heuristic.py`
      nutzt statische Haupt-Ranges. Wochentlicher Cron-Refresh aus Azure
      ServiceTags / AWS ip-ranges.json / Cloudflare ips-v4 / Hetzner ASN
      fehlt (Plan §14).
- [ ] **Phase 0b voll policy-aware im Scan-Worker**: `run_phase0()` laeuft
      aktuell mit `primary_domain` (erster enumerate-FQDN). Scoped /
      ip_only-Targets werden in `scope.build_partial_inventory_for_non_enumerate`
      separat erzeugt und gemerged — funktional korrekt, aber der geplante
      Umbau auf `run(targets: list[TargetWithPolicy])` als native Signatur
      steht aus.
- [ ] **`frontend/src/lib/api.ts` Tests und Subscription-UI**: neue Order-
      Seite und Admin-Review existieren; Subscription-Target-Editor fuer
      bestehende Abos (Hinzufuegen/Entfernen von Targets ausserhalb des
      Initial-Wizards) fehlt.
- [ ] **Legacy-Test-Sammlung**: `api/src/__tests__/routes.test.ts`,
      `subscription_rescan_admin.test.ts` und `verification.test.ts` gehen
      noch von der Single-Domain-API aus und muessen aktualisiert werden.
- [ ] **Frontend tsc / integrationstests**: Frontend wurde im gleichen
      Durchlauf von Agents umgebaut — `cd frontend && npx tsc --noEmit`
      und die Playwright-Flows einmal komplett durchlaufen lassen.

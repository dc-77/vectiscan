# Scan-Optimierung — Test-Session-Prompt

**Zweck:** Copy-paste-bereiter Prompt für eine neue Claude-Code-Session, sobald die Test-Scans durch sind. Enthält den vollen Kontext, sodass die neue Session ohne Rückfragen mit der Analyse starten kann.

---

## Wie verwenden

1. Test-Scans durchlaufen lassen (siehe `Scan-Optimierung-Test-Coverage.md` für empfohlene Konfigurationen).
2. PDF-Reports + Order-IDs sammeln.
3. `ops-baseline-snapshot`-Job vorher und nachher triggern, beide `baseline-snapshot.txt`-Artifacts speichern.
4. Neue Claude-Code-Session in diesem Repo starten.
5. Untenstehenden Prompt copy-pasten + die Order-IDs / Pfade ausfüllen.

---

## Der Prompt

```
Wir testen jetzt die Scan-Optimierung-Implementierung (P0-P4a, 41/42 Findings deployed).
F-PH2-002 (nuclei + katana) ist als P4b deferred.

WICHTIGE DOKUMENTE:
- docs/scan-flow/Scan-Optimierung.md — das Audit (42 Findings mit Optionen)
- docs/scan-flow/Scan-Optimierung-Roadmap.md — Paket-Strategie + Status
- docs/scan-flow/Scan-Optimierung-Changelog.md — was geändert wurde, erwartetes Verhalten,
  Test-Anker pro Finding, Rollback-Anweisungen
- docs/scan-flow/Scan-Optimierung-Test-Coverage.md — welcher Scan testet welche Findings

WAS DEPLOYED IST:
- POLICY_VERSION: 2026-05-10.1 (von 2026-04-30.1 hochgezogen — 2× POLICY_VERSION-Bump in P2 + P3)
- Migration 026 (Shodan Pre-Warm: orders.pre_warm_requested + subscriptions.shodan_scan_request)
- 5 GitLab-Pipelines erfolgreich: 2411 (P0), 2412 (P1), 2414 (P2), 2415 (P3), 2416 (P4a)
- Rollback-Tags: pre-p0-foundation, pre-p1-quickwins, pre-p2-sync,
  pre-p3-mail-discovery, pre-p4a-phase1-ki

GETESTETE SCANS (bitte Daten ergänzen):
- Order-ID Scan 1 (TLSCompliance): __________________________
- Order-ID Scan 2 (Perimeter FQDN-Basis): ___________________
- Order-ID Scan 3 (Re-Scan derselben Order): _________________
- Order-ID Scan 4 (Insurance + EOL-Software): ________________
- Order-ID Scan 5 (Multi-VHost-Host): _______________________
- Order-ID Scan 6 (Hosted-CMS-Domain): ______________________
- Order-ID Scan 7 (Compliance >10 Hosts): ___________________

ARTEFAKTE:
- Baseline-Snapshot vor Tests: __________________ (Pfad oder Inhalt)
- Baseline-Snapshot nach Tests: __________________
- PDF-Reports: __________________________________
- Auffälligkeiten beim Visual-Check der PDFs: ______________________________

DEINE AUFGABE:

1. Ordne pro Scan zu, welche Findings aus dem Audit (`Scan-Optimierung.md`)
   tatsächlich getriggert wurden. Nutze dafür:
   - GitLab-API zum Auswerten der Job-Logs (Helper: gitlab-api.sh)
   - PostgreSQL-Queries via ops-Jobs ODER über die in den Snapshot-Files
     enthaltenen Daten
   - PDF-Inspektion (visuell oder Text-Extract)

2. Vergleiche Vor-/Nachher-Snapshot:
   - Cache-Hit-Quote: sollte für ki2_tech_analysis + ki3_phase2_config
     deutlich gestiegen sein (vorher 0% Order-übergreifend → erwartet 30-60%)
   - Severity-Verteilung: kann sich ändern bei F-RPT-001 (mehr CRITICAL bei
     Banner-Match), F-RPT-002 (weniger falsche Konsolidierung → mehr getrennte
     Findings)
   - Determinismus-Score: einmalig dippen direkt nach POLICY_VERSION-Bump,
     dann zurück hoch
   - Neue policy_ids: SP-DNS-011..014, SP-URLHAUS-001 sollten auftauchen
     wenn Test-Targets das triggert

3. Identifiziere Findings die NICHT erwartet funktionieren:
   - Liste pro Finding: erwartetes Verhalten (aus Changelog) vs. beobachtet
   - Klassifiziere als: ✓ wirkt | ⚠ Edge-Case-Tuning | ✗ Bug | ? unklar

4. Bei Bugs (✗):
   - Code-Stelle + Symptom + reproduzierbare Repro-Schritte
   - Vorschlag für Fix oder Rollback (welcher Tag?)
   - Risiko-Einschätzung

5. Bei Edge-Case-Tuning (⚠):
   - Welche Daten/Patterns/ENV-Variablen fehlen
   - Aufwand zur Behebung (XS/S/M)
   - Ob das ein Blocker ist

ARBEITSWEISE:
- Nutze gitlab-api.sh für Pipeline + Job-Logs
- Nutze ops-Jobs (ops-findings-audit, ops-baseline-snapshot) für DB-Queries
  via GitLab-Pipeline-Trigger
- Für PDF-Inhalt: bitte mir die relevante Section direkt geben
  (Reporter-Worker-Logs zeigen welche Findings extrahiert wurden)
- Code-Read bei Bedarf zur Verifikation
- Ergebnis als strukturierter Report:
  * Pro Paket P0-P4a: ✓/⚠/✗-Bilanz
  * Bug-Liste (falls vorhanden) mit Priorität
  * Edge-Case-Liste mit Fix-Aufwand
  * Empfehlung: weiter mit P4b? Oder erst Bugfix-Cycle?

STOP-BEDINGUNGEN:
- Wenn ein Bug einen kompletten Scan zerstört: STOP, melden, Rollback-Vorschlag
- Wenn Pipeline-Build neu rot wird: STOP, Diagnose
- Wenn DB-Daten unkonsistent (z.B. consolidated_findings ohne policy_id): STOP, kläre
  ob Migration 026 + POLICY_VERSION-Bump korrekt durchliefen

NICHT TUN:
- Keine Code-Änderungen ohne Bug-Bestätigung + User-OK
- Kein Push, kein Pipeline-Trigger ohne explizite Anfrage
- Kein POLICY_VERSION-Bump
- Keine destruktiven Operationen (cleanup-prod, force-push, etc.)

START:
Bitte starte mit einem Statusbericht:
- Welche Scans sind ausgeführt? (Order-IDs aus dem Prompt-Block)
- Welche Artefakte hast du Zugriff drauf? (PDF, Logs, Snapshot)
- Welcher Test-Path läuft als erstes? (Empfehlung: Baseline-Diff zuerst,
  dann pro Scan die Findings durchgehen)
```

---

## Anpassungen vor Verwendung

**Pflichtfelder ausfüllen:**
- Order-IDs der Test-Scans (mindestens 1, idealerweise 3-5)
- Pfad oder Inhalt der Baseline-Snapshots
- Auffälligkeiten beim PDF-Visual-Check (falls vorhanden — sonst leer lassen)

**Optionale Anpassungen:**
- Falls nicht alle Scan-Typen ausgeführt: streiche entsprechende Order-ID-Zeilen
- Falls weitere Test-Targets relevant: ergänze unter "GETESTETE SCANS"
- Falls POLICY_VERSION zwischenzeitlich geändert: Nummer im Prompt anpassen

---

## Fallback wenn der Hauptprompt zu lang wird

Kürzere Variante für eine fokussierte Analyse:

```
Test-Session für Scan-Optimierung-Implementierung. Lese:
- docs/scan-flow/Scan-Optimierung-Changelog.md (was wurde gemacht + Test-Anker)
- docs/scan-flow/Scan-Optimierung-Test-Coverage.md (welche Scans testen was)

Test-Scans durch:
- Order <ID>: Perimeter auf <Domain> — Schwerpunkt P0-P3 Findings
- Baseline-Snapshot vor + nach in <Pfad>

Aufgabe: prüfe pro Paket, ob die erwarteten Verhaltens-Änderungen aus dem Changelog
eingetroffen sind. Nutze GitLab-Logs + ops-Jobs für DB-Queries. Klassifiziere
✓/⚠/✗ pro Finding. Output: strukturierter Bilanzbericht mit Bug-Liste.

Stop bei Code-Änderungs-Bedarf — bitte um User-OK.
Start mit Baseline-Diff.
```

---

## Während der Test-Session evtl. nützlich

Diese Files können bei der Analyse zusätzlich helfen:
- `scripts/ops-baseline-snapshot.sql` — die SQL-Queries selbst (zum Anpassen)
- `scripts/diff-orders.py` — Forensik-Diff zwischen zwei Orders
- `bash /c/Users/danie/.claude/projects/.../gitlab-api.sh trace <JOB-ID>` — Job-Logs holen
- `report-worker/reporter/severity_policy.py` — alle policy_ids im Code

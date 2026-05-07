# Test-Evidence — Scan-Optimierung-Audit-Verifikation

**Stand:** 2026-05-07 21:22 UTC
**Zweck:** Test-Run nach P0-P4a-Deployment, sammelt Evidence für die nachfolgende Test-Session.

## Inhalt

| Datei | Beschreibung | Im Repo? |
|---|---|---|
| `evidence.json` | Test-Set mit Order-IDs, Pipeline-IDs, Sync-Job-Status, bekannten Bugs | nein |
| `order-summary.json` | Per-Order severity_counts + business_impact_score | nein |
| `baseline-pre-tests.txt` | KPI-Snapshot via `ops-baseline-snapshot` Pipeline 2421 | nein |
| `baseline-post-tests.txt` | KPI-Snapshot via Pipeline 2422 | nein |
| `report-<8>.pdf` | PDF-Reports 5/6 Test-Orders (1 Reporter-Hang offen) | nein |
| `setup-test-scans.py` | Reproduzier-Skript für Test-Order-Anlage (API-Calls) | nein |
| `poll-orders.py` | Polling-Helper für Order-Status | nein |
| `test-session-prompt-filled.md` | Copy-paste-Prompt für nachfolgende Claude-Session | nein |
| `README.md` (diese Datei) | Inhalt-Erklärung | **ja** |
| `.gitignore` | Schutz: alles ausgenommen README + .gitignore | **ja** |

## Test-Set

7 Orders angelegt + released (alle ohne dummy-Authorization wegen Test-System):

| Order-ID (8) | Package | Target | Final-Status |
|---|---|---|---|
| 4861875f | tlscompliance | scanme.nmap.org | `pending_review`, 4 HIGH + 1 MEDIUM, risk=HIGH |
| 8a3ee0c8 | perimeter | heuel.com | `pending_review`, 2 MEDIUM + 4 LOW + 1 INFO, risk=MEDIUM |
| 6ba0cade | perimeter | testphp.vulnweb.com | `pending_review`, 2 MEDIUM + 1 INFO |
| b583d83b | perimeter | ginandjuice.shop | `pending_review`, 4 MEDIUM + 1 INFO |
| 83c35c03 | webcheck | dvwa.co.uk | `pending_review`, 1 MEDIUM + 2 LOW + 1 INFO |
| 0674d120 | perimeter | securess.de | `scan_complete`, Reporter hängt (offen) |
| 49019e7b | webcheck | scanme.nmap.org | (Probe-Order — 0 Findings ggf.) |

## Pipelines (alle erfolgreich, außer 1 Sync-Job-Bug)

- 2411 P0-Foundation-Deployment ✓
- 2412 P1-Quick-Wins ✓
- 2414 P2-Sync-Pipelines ✓
- 2415 P3-Mail-Discovery ✓
- 2416 P4a-Phase1-KI-Coverage ✓
- 2421 (api): ops-baseline-snapshot + 3/4 sync-jobs ✓ (known-vuln-builds-sync ✗)
- 2422 (push): ops-baseline-snapshot ✓ (post-test-snapshot)

## Bekannte Bugs (sollten in Folge-PR adressiert werden)

1. **`scripts/sync-known-vuln-builds.py` OSV-API HTTP 400** — Request-Format vermutlich falsch. Alle Vendor-Queries scheitern. `KNOWN_VULN_BUILDS_GENERATED` bleibt leer; F-RPT-001 wirkt nur über die 20 Manual-Entries.
2. **securess.de Reporter-Hang** — `status=scan_complete` + `hasReport=false` nach >30 min. Worker-Logs prüfen, evtl. KI #5 Token-Truncation oder API-Stall.
3. **Vuln-Test-Sites zu wenig Findings** — testphp.vulnweb.com/ginandjuice.shop/dvwa.co.uk liefern 3-5 Findings (erwartet ≥10). Bestätigt: F-PH2-002 (nuclei + katana, P4b deferred) ist nötig für CVE/Schwachstellen-Abdeckung.

## Wichtige Erkenntnisse aus den Snapshots

- POLICY_VERSION 2026-05-10.1: 10 Reports (Test-Scans + 4 frühere). Cache-Invalidation greift.
- KI-Cache-Hit `reporter_v1`: 41.7% (20 von 48 Calls) — gute Cache-Wirksamkeit.
- KI #1/#2/#3 Cache-Hit 0% — Test-Scans waren alle frisch (kein Re-Scan auf gleichem Tech-Stack innerhalb 7d), F-XS-002 content_hash-Symmetrie wirkt erst bei Re-Scans.
- `subscription_posture.determinism_score`: 100.00 für 1 Subscription — perfekt deterministisch.
- KI-Kosten 7d: Opus $45.36 (45 Calls), Haiku $1.73 (112 Calls), Sonnet $0.20 (3 Calls — Skip-Gate griff bei KI #4 oft).

## Wie weiter

Neue Claude-Code-Session starten und Inhalt von `test-session-prompt-filled.md` als Initial-Prompt verwenden. Die Test-Session-Claude analysiert dann:
- Vor-/Nachher-Snapshot-Diff
- Pro Order welche Audit-Findings tatsächlich getriggert wurden
- Bug-Liste mit Reproduktions-Schritten
- Empfehlung: weiter mit P4b (nuclei) oder erst Bugfix-Cycle?

Files in diesem Verzeichnis (außer README + .gitignore) sind **nicht committet** — sie enthalten Order-IDs, Customer-Domain-Scan-Daten und Auth-Tokens-relevante Trails.

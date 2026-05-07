# Scan-Optimierung — Implementierungs-Roadmap

**Quelle:** `docs/scan-flow/Scan-Optimierung.md` (42 Findings, Audit 2026-05-06/07).
**Branch-Strategie:** `feat/p<N>-<name>` pro Paket, Push am Paket-Ende, Pipeline-Watch via `gitlab-api.sh`.

---

## Status-Übersicht

| Paket | Beschreibung | Status | Branch | Commit-Range |
|---|---|---|---|---|
| P0 | Foundation (Determinismus-Hygiene, ohne POLICY_VERSION-Bump) | **deployed** (Pipeline 2411 success) | `feat/p0-foundation` | `pre-p0-foundation..28d36d3` (10 Commits) |
| P1 | Quick-Wins (XS-Aufwand, gebündelt nach Phase) | **deployed** (Pipeline 2412 success) | `feat/p1-quickwins` | `pre-p1-quickwins..6c448d2` (6 Commits, 17 Findings) |
| P2 | Maintained-Listen-Sync (auf F-XS-003 aufbauend) | completed (lokal), push pending | `feat/p2-sync-pipelines` | `pre-p2-sync..6df74bd` (4 Commits, 4 Findings) |
| P3 | Mail-Security & Discovery-Tiefe | pending | `feat/p3-mail-discovery` | — |
| P4 | Phase 1/2 Tool-Erweiterungen (nuclei/katana) | pending | `feat/p4-tool-coverage` | — |

---

## P0 — Foundation

**Ziel:** Saubere Determinismus-Basis. Bug-Charakter, kein POLICY_VERSION-Bump.

| # | Finding | Status | Commit |
|---|---|---|---|
| 1 | F-XS-003 — Sync-Helper-Lib + Pilot-Refactor `sync-eol-data.py` | done | 85d31b3 |
| 2 | F-XS-001 — Output-Normalizer (testssl, ffuf, katana, feroxbuster) | done | 33770ee |
| 3 | F-XS-002 — Cache-Symmetrie KI #2/#3 (`content_hash`-Mode) | done | 31f3d07 |
| 4 | F-RPT-002 — `selection.consolidate` Hash + `STABLE_TITLE_VARS` | done | 22edf02 |
| 5 | F-RPT-007 — `eol_detector.merge` Host-Resolution + Version-Recovery | done | 95882db |
| 6 | F-RPT-003 — `business_impact._classify_finding` policy_id-Mapping | done | 0e061d3 |
| 7 | F-RPT-005 — QA-Check-Reihenfolge nach severity_policy | done | 82c820a |
| 8 | F-RPT-006 — `claude_client` Truncation-Fix (Cap 150K + per_host_cap) | done | 75c764d |
| 9 | F-RPT-004 — `finding_type_mapper` AI-Fallback ThreadPool | done | 50e6a67 |

**Lokale Test-Suite:** 947 grün (562 report-worker + 378 scan-worker, 1 skip + 7 scripts) — keine Regression.

**Reihenfolge-Begründung:**
- F-XS-003 zuerst (Pilot-Refactor, kein Verhaltens-Drift, Helper-Lib für spätere Pakete).
- F-XS-001 + F-XS-002 unabhängig.
- F-RPT-002 vor F-RPT-007 (Konsolidierungs-Logik bevor Merge sie nutzt).
- Rest unabhängig.

---

## P1 — Quick-Wins

**Ziel:** XS-Aufwand-Findings nach Phase gebündelt (5 Bundles → 5 Commits).

| # | Bundle | Findings | Status | Commit |
|---|---|---|---|---|
| A | Pre-Check + Phase 0a | F-PRE-002, F-PRE-004, F-PRE-005, F-P0A-001, F-P0A-005 (5) | done | 8b554d1 |
| B | Phase 0b | F-P0B-002, F-P0B-005, F-P0B-007, F-P0B-008 (4) | done | 9818850 |
| C | Phase 1 + Phase 2 + Upload | F-PH1-002, F-PH2-001, F-PH9-001 (3) | done | 874c665 |
| D | KI #4 + Phase 3 | F-KI4-001, F-PH3-001 (2) | done | 71faa97 |
| E | KI #1 + KI #3 | F-KI1-001, F-KI1-002, F-KI3-001 (3) | done | 92eec98 |

**Lokale Test-Suite:** scan-worker 405 grün (1 skip), report-worker 562 grün, scripts 7 grün — keine Regression.

---

## P2 — Maintained-Listen-Sync

**Ziel:** Sync-Pipelines auf Basis F-XS-003-Helper-Lib (P0). POLICY_VERSION-Bump (2026-04-30.1 → 2026-05-08.1).

| # | Finding | Status | Commit |
|---|---|---|---|
| 1 | F-PRE-001 — Parking-Pattern DACH + Provider + Redirect-Allowlist | done | 968a249 |
| 2 | F-PRE-003 — cloud-ranges-sync (9 Provider, RIPEstat-ASNs) | done | 80b69c5 |
| 3 | F-P0B-006 — takeover-list-sync (EdOverflow fingerprints.json) | done | 8a83dfc |
| 4 | F-RPT-001 — KNOWN_VULN_BUILDS +15 Manual + OSV-Sync + Range-Matcher + POLICY_VERSION-Bump | done | 6df74bd |

**Lokale Test-Suite:** 1011 grün (567 report-worker + 415 scan-worker, 1 skip + 29 scripts) — keine Regression.

**POLICY_VERSION:** 2026-04-30.1 → 2026-05-08.1 (Cache-Invalidierung erwartet bei naechstem Re-Scan).

---

## P3 / P4

_(Detaillierte Tabellen werden befüllt sobald P2 deployed.)_

---

## Pipeline-Konventionen für diese Implementierungs-Phase

- Push pro Paket-Ende (nicht pro Commit).
- POLICY_VERSION-Bump in P2/P3/P4 dokumentiert + zwischen-User-abgesegnet.
- Cleanup-Skript-Auslösung weiterhin manuell (CONFIRM=vectiscan-prod-Gate).
- Test-System — Rollback via `git revert <commit-range>` oder `git reset --hard <pre-paket-tag>`.

## Rollback-Tags

Pro Paket vor dem Push setzen wir einen Tag `pre-p<N>-<datum>`, sodass bei Bedarf `git reset --hard pre-p0-2026-05-08` reicht.

| Tag | Commit | Datum |
|---|---|---|
| `pre-p0-foundation` | 948f6ba | 2026-05-08 |
| `pre-p1-quickwins` | 28d36d3 | 2026-05-08 |
| `pre-p2-sync` | 3632e8a | 2026-05-08 |


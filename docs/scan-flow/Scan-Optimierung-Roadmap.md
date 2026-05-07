# Scan-Optimierung — Implementierungs-Roadmap

**Quelle:** `docs/scan-flow/Scan-Optimierung.md` (42 Findings, Audit 2026-05-06/07).
**Branch-Strategie:** `feat/p<N>-<name>` pro Paket, Push am Paket-Ende, Pipeline-Watch via `gitlab-api.sh`.

---

## Status-Übersicht

| Paket | Beschreibung | Status | Branch | Commit-Range |
|---|---|---|---|---|
| P0 | Foundation (Determinismus-Hygiene, ohne POLICY_VERSION-Bump) | in progress | `feat/p0-foundation` | TBD |
| P1 | Quick-Wins (XS-Aufwand, parallelisierbar) | pending | `feat/p1-quickwins` | — |
| P2 | Maintained-Listen-Sync (auf F-XS-003 aufbauend) | pending | `feat/p2-sync-pipelines` | — |
| P3 | Mail-Security & Discovery-Tiefe | pending | `feat/p3-mail-discovery` | — |
| P4 | Phase 1/2 Tool-Erweiterungen (nuclei/katana) | pending | `feat/p4-tool-coverage` | — |

---

## P0 — Foundation

**Ziel:** Saubere Determinismus-Basis. Bug-Charakter, kein POLICY_VERSION-Bump.

| # | Finding | Status | Commit |
|---|---|---|---|
| 1 | F-XS-003 — Sync-Helper-Lib + Pilot-Refactor `sync-eol-data.py` | pending | — |
| 2 | F-XS-001 — Output-Normalizer (testssl, ffuf, katana, feroxbuster) | pending | — |
| 3 | F-XS-002 — Cache-Symmetrie KI #2/#3 (`content_hash`-Mode) | pending | — |
| 4 | F-RPT-002 — `selection.consolidate` Hash + `STABLE_TITLE_VARS` | pending | — |
| 5 | F-RPT-007 — `eol_detector.merge` Host-Resolution + Version-Recovery (hängt von #4) | pending | — |
| 6 | F-RPT-003 — `business_impact._classify_finding` policy_id-Mapping | pending | — |
| 7 | F-RPT-005 — QA-Check-Reihenfolge nach severity_policy | pending | — |
| 8 | F-RPT-006 — `claude_client` Truncation-Fix (Cap 150K + per_host_cap) | pending | — |
| 9 | F-RPT-004 — `finding_type_mapper` AI-Fallback ThreadPool | pending | — |

**Reihenfolge-Begründung:**
- F-XS-003 zuerst (Pilot-Refactor, kein Verhaltens-Drift, Helper-Lib für spätere Pakete).
- F-XS-001 + F-XS-002 unabhängig.
- F-RPT-002 vor F-RPT-007 (Konsolidierungs-Logik bevor Merge sie nutzt).
- Rest unabhängig.

---

## P1 — Quick-Wins

_(Findings: F-PRE-002, F-PRE-004, F-PRE-005, F-P0A-001, F-P0A-005, F-PH1-002, F-KI3-001, F-KI4-001, F-PH3-001, F-PH9-001, F-KI1-001, F-KI1-002, F-P0B-002, F-P0B-005, F-P0B-007, F-P0B-008, F-PH2-001 — 17 Findings)_

Status-Tabelle wird befüllt sobald P0 deployed.

---

## P2 / P3 / P4

_(Detaillierte Tabellen werden befüllt sobald P1 deployed.)_

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
| `pre-p0-foundation` | TBD | TBD |


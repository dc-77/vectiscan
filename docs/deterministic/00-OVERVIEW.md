# Determinism & Severity Calibration — Q2/2026

**Stand:** 2026-04-24
**Trigger:** Wettbewerbsanalyse Rapid7 vs. VectiScan + interne Beobachtung,
dass Severity-Vergaben „willkürlich" wirken und Re-Scans derselben Domain
abweichende Findings produzieren.
**Ziel:** Deterministische, kalibrierte und auditierbare Scan-Ergebnisse.

---

## Problem in zwei Sätzen

1. **Severity-Willkür**: VectiScan stuft ~370 Findings als Medium ein, die
   kommerzielle DAST-Produkte (Rapid7, Acunetix, Burp, Qualys) als
   Informational klassifizieren. Hauptursache: ZAP-Default-Severities werden
   ungeprüft übernommen.
2. **Run-zu-Run-Varianz**: Vier KI-Entscheidungspunkte (3× Haiku, 1× Sonnet)
   plus die Sonnet-Report-Generierung treffen wertende Auswahl- und
   Severity-Entscheidungen. Gleicher Input → leicht unterschiedlicher Output.

## Lösung in drei Bausteinen (P1-Block)

| # | Maßnahme | Hauptdatei | Aufwand |
|---|---|---|---|
| 02 | **Severity-Policy als Code** (~40 Regeln, kalibriert gegen Rapid7/Acunetix-Baseline) | `report-worker/reporter/severity_policy.py` | 2–3 Tage |
| 03 | **AI-Cache + temperature=0** in allen 5 AI-Calls | `scan-worker/scanner/ai_cache.py` | 1 Tag |
| 04 | **Deterministische Finding-Selektion** (Sortierung statt Sonnet-Auswahl) | `report-worker/reporter/selection.py` | 2 Tage |

Plus:

- **01** Cleanup der Test-Datenbestände (Big-Bang, keine Migration nötig)
- **05** Schema-Migrations 014 (severity-Provenance) + 015 (Threat-Intel-Snapshots)
- **99** Cutover-Plan mit Smoke-Test

## Strategie-Entscheidungen

- **Big-Bang** statt Feature-Flag. Begründung: nur Testkunden im Bestand,
  Aufräum-Schmerz < Migrations-Schmerz.
- **User-Accounts und Subscriptions bleiben** erhalten, alle Scan-Daten
  (Orders, Reports, MinIO-Objekte, Caches) werden gewipt.
- **KI #4 (Phase-3-Priorisierung) bleibt erhalten**, aber reduziert auf
  Confidence-Boost ohne FP-Marker und ohne Selektion. Cross-Tool-Reasoning
  ist echter Sonnet-Mehrwert; die wertenden Entscheidungen wandern in die
  Severity-Policy.
- **Top-N pro Paket**: WebCheck 8, Perimeter 15, Compliance 20,
  SupplyChain 15, Insurance 15. TLSCompliance läuft eigenen Pfad.

## Reihenfolge der Umsetzung (Strict)

```
1. Branch anlegen: feature/q2-determinism
2. Specs durchgehen (diese Files)
3. Migrations 014 + 015 schreiben + lokal testen
4. severity_policy.py + Tests
5. ai_cache.py + Tests + AI-Calls instrumentieren
6. selection.py + Tests + Reporter umstellen
7. Lokaler End-to-End-Scan auf Test-Domain
8. Code-Review
9. Staging-Deploy → Smoke-Test (s. 99-CUTOVER.md)
10. Cleanup-Run (cleanup.sh) gegen Prod-DB
11. Prod-Deploy
12. Post-Deploy Re-Scan einer Test-Domain → Reproducibility validieren
```

**Nicht überspringen**: Cleanup *nach* Code-Deploy, *vor* Prod-Aktivierung.
Falls etwas schiefgeht und ein Rollback nötig wird, willst du keinen
gemischten Datenbestand mit alten + neuen Schemas haben.

## File-Map

```
docs/specs/2026-Q2-determinism/
├── 00-OVERVIEW.md                      ← diese Datei
├── 01-cleanup.md                       ← Spec für DB/MinIO/Redis-Wipe
├── 01-cleanup.sh                       ← ausführbares Cleanup-Script
├── 02-severity-policy.md               ← Spec für Severity-Policy
├── 02-severity-policy-skeleton.py      ← Python-Skeleton
├── 02-severity-policy-tests.py         ← pytest-Stubs
├── 03-ai-determinism.md                ← Spec für AI-Cache + temp=0
├── 03-ai-cache-skeleton.py             ← Python-Skeleton
├── 03-ai-cache-tests.py                ← pytest-Stubs
├── 04-deterministic-selection.md       ← Spec für Finding-Selektion
├── 04-selection-skeleton.py            ← Python-Skeleton
├── 04-selection-tests.py               ← pytest-Stubs
├── 05-schema-migrations.md             ← Migrations-Spec
├── 05-014-severity-policy.sql          ← Migration 014
├── 05-015-threat-intel-snapshots.sql   ← Migration 015
└── 99-CUTOVER.md                       ← Deployment-Plan + Smoke-Tests
```

## Akzeptanzkriterien (Definition of Done)

- [ ] `severity_policy.py` exportiert `SEVERITY_POLICIES` Dict mit ≥35 Regeln
- [ ] Jede Policy-Regel hat eine `policy_id` (Format `SP-<DOMAIN>-NNN`)
- [ ] Jede Policy-Regel hat einen Unit-Test (1 positiv, 1 negativ wenn anwendbar)
- [ ] Alle 5 AI-Calls nutzen `temperature=0.0` und gehen durch `AICache`
- [ ] `selection.py` exportiert `select_findings(findings, package) -> list`
- [ ] Selektion ist deterministisch: zweimaliger Aufruf mit gleichem Input → identisches Output
- [ ] Reporter generiert nur noch Narrative-Texte (Severity, CVSS, Top-N kommen aus Daten)
- [ ] Migration 014 + 015 sind idempotent (re-run sicher)
- [ ] Cleanup-Script hat `--dry-run` Modus und Confirmation-Prompt
- [ ] Smoke-Test-Scan nach Cleanup läuft erfolgreich
- [ ] Reproducibility-Test: 2× Scan derselben Domain → identische `severity_counts`,
      identische `policy_id`-Liste, identischer `business_impact_score`

## Was sich für Customer-facing Verträge ändert

Severity-Verschiebung (alt → neu, geschätzt für typischen Perimeter-Scan):

| Severity | Vorher | Nachher (Schätzung) |
|---|---|---|
| Critical | 0–1 | 0–1 |
| High | 0–2 | 0–3 *(Exchange-EOL etc.)* |
| Medium | 7–12 | 3–5 |
| Low | 4–8 | 8–15 |
| Info | 1–3 | 5–10 |

**Total Findings im Report bleibt etwa gleich (12–20).** Die Verschiebung ist
weg von Medium hin zu Low/Info — das macht den Report glaubwürdiger gegen
Vergleiche mit Rapid7/Acunetix und reduziert Pushback aus Kunden-Reviews.

## Was nicht in diesem Block ist (P2/P3 für später)

- Threat-Intel-Snapshot-System (Tabelle wird in Migration 015 angelegt,
  aber noch nicht aktiv genutzt — bewusst aufgeschoben)
- Reproducibility-Test im CI (Make-Target nachreichen)
- Tool-Versionen pinnen (wpscan-DB, testssl-Version) im Report-Footer
- Evidence-Appendix (Request/Response-Samples pro Finding)
- JS-Sink-Erkennung als neuer Scanner-Modul

## Risiken & Gegenmaßnahmen

| Risiko | Mitigation |
|---|---|
| Severity-Policy übersieht einen häufigen Finding-Typ → ZAP-Default greift unbemerkt | Fallback in `severity_policy_lookup` loggt Warning + zählt Misses; Telemetrie auswerten |
| AI-Cache cached fehlerhaften Output → propagiert in Re-Scans | `policy_version` in Cache-Key, bei Prompt-Änderung Auto-Invalidierung |
| Top-N-Selektion verwirft wichtigen Finding | `business_impact_score` ist Hauptsortierung; CVE-in-KEV-Boost (1.5×) garantiert dass kritische Findings oben landen |
| Cleanup löscht versehentlich produktive Daten | `--dry-run` zeigt was gelöscht würde; Confirmation-Prompt; pre-Backup-Step |
| Reporter-Sonnet halluziniert Severities trotz Trennung | System-Prompt explizit: "Du erhältst Severity, CVSS, Hosts als Fakten — übernimm sie wörtlich; generiere NUR Narrative" |

---

**Verantwortlich:** Daniel Czischke
**Review:** TBD
**Geplanter Cutover:** TBD (nach Staging-Smoketest)

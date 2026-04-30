# 04 — Deterministische Finding-Selektion

**Ziel:** Top-N-Auswahl pro Paket ist eine reine Sortier-Operation auf
business-impact-Score, **nicht mehr** Sonnet-Auswahl. Reporter (Sonnet)
generiert nur noch Narrative-Texte zu den bereits ausgewählten Findings.

**Lokation:** `report-worker/reporter/selection.py`

**Aufruf-Punkt:** Im Report-Worker **nach** `severity_policy.apply_policy()`
und `business_impact.recompute()`, **vor** `claude_client.generate_narrative()`.

---

## 1. Problemraum heute

Heute ist die Auswahl, **welche** Findings im Report landen, an mindestens
zwei Stellen wertend:

1. **KI #4 (Phase-3-Priorisierung)** markiert Findings als FP, wodurch sie
   aus dem Selection-Pool fallen
2. **Sonnet-Reporter** entscheidet implizit durch das Generieren der
   Findings-Sektion, welche von ggf. 30+ Kandidaten in den Top-N landen

Beide Wege sind nicht deterministisch und nicht auditierbar — Customer
fragt „warum ist Finding X drin und Y nicht?" und wir können nicht klar
antworten.

## 2. Lösung

```
                  Findings (nach severity_policy + business_impact)
                              │
                              ▼
                  ┌──────────────────────┐
                  │  selection.py        │
                  │  select_findings()   │
                  └──────────────────────┘
                              │
                              ▼
        ┌─────────────────────┼─────────────────────┐
        │  Top-N pro Paket    │  Stable Sort        │
        │  WebCheck    →  8   │  business_impact ↓  │
        │  Perimeter   → 15   │  cvss_score      ↓  │
        │  Compliance  → 20   │  epss_score      ↓  │
        │  SupplyChain → 15   │  confidence      ↓  │
        │  Insurance   → 15   │  finding_id      ↑  │ ← Tiebreaker
        └─────────────────────┴─────────────────────┘
                              │
                              ▼
                  Reporter (Sonnet, Narrative-only)
```

## 3. Sortier-Schlüssel

Primär nach business_impact_score (höher = wichtiger), bei Gleichstand
weitere Kriterien. **Tiebreaker `finding_id ASC`** ist der Schlüssel zum
Determinismus — bei sonst identischen Findings entscheidet die
alphabetisch kleinere ID.

```python
def sort_key(f: dict) -> tuple:
    return (
        -float(f.get("business_impact_score", 0.0)),    # higher first
        -float(f.get("cvss_score", 0.0)),               # higher first
        -float(f.get("epss_score", 0.0)),               # higher first
        -float(f.get("confidence", 0.0)),               # higher first
        str(f.get("finding_id", "")),                   # ASC for stable tiebreak
    )
```

## 4. Top-N pro Paket (Konfiguration)

```python
TOP_N_PER_PACKAGE: dict[str, int] = {
    "webcheck":      8,
    "perimeter":    15,
    "compliance":   20,
    "supplychain":  15,
    "insurance":    15,
    # tlscompliance hat eigenen Pfad ohne Top-N
}
```

**Kuratierung statt Limit:** Bei Top-N werden Findings unterhalb der Top-N
nicht weggeworfen, sondern in eine separate Liste `additional_findings`
verschoben. Diese taucht im Report als Anhang „weitere Befunde" auf
(Severity + Titel, ohne Narrative).

## 5. Konsolidierung gleicher Findings über Hosts

Vorher: Wenn 33 Hosts dasselbe TLS-Problem haben, sind das 33 Findings.
Nachher: Konsolidieren zu 1 Finding mit `affected_hosts: [...]`.

Konsolidierungs-Schlüssel:
```
(finding_type, policy_id, normalized_evidence_hash)
```

Wobei `normalized_evidence_hash` die Tool-spezifischen, host-spezifischen
Felder ausnimmt (z.B. nicht die IP, aber den TLS-Cipher-Suite-Namen).

**Wichtig:** Konsolidierung passiert **vor** Top-N-Selektion, sonst kann
ein einzelnes Problem 33× im Report landen.

## 6. Reporter-Anpassung: Narrative-only

`report-worker/reporter/claude_client.py::generate()` muss umgebaut werden:

**Alt** (Reporter wählt aus, schreibt Severities, schreibt Narrativ):
```python
report = sonnet_call(
    system=REPORTER_SYSTEM_PROMPT,
    messages=[{"role": "user", "content": all_findings_json}],
)
# report enthält selected_findings, severity_assessment, narrative
```

**Neu** (Reporter bekommt Selektion, schreibt nur Narrativ):
```python
selected = select_findings(findings, package=order.package)
report = sonnet_call(
    system=REPORTER_NARRATIVE_ONLY_PROMPT,
    messages=[{
        "role": "user",
        "content": json.dumps({
            "package": order.package,
            "selected_findings": selected,           # ← schon ausgewählt
            "additional_findings": additional,       # ← unten als Appendix
            "scan_summary": summary,
        })
    }],
)
# report enthält NUR: narrative (Executive Summary, Per-Finding-Beschreibung,
#                                 Per-Finding-Empfehlung)
# NICHT mehr: Severity (kommt aus Daten), CVSS (kommt aus Daten),
#             Auswahl (kommt aus selection.py)
```

System-Prompt für Reporter:

```
Du erhältst eine vorausgewählte Liste von Findings mit final festgelegten
Severities, CVSS-Scores und Empfehlungs-Referenzen.

Deine EINZIGE Aufgabe: Schreibe einen deutschen Pentest-Report mit
- Executive Summary (max 200 Wörter)
- Pro Finding: Kontextuelle Beschreibung (was ist passiert, warum riskant)
- Pro Finding: Empfehlung in Aufzählungspunkten

VERBOTEN:
- Severities zu ändern oder neu zu interpretieren
- CVSS-Scores zu nennen, die nicht im Input stehen
- Findings auszulassen oder hinzuzufügen
- Eine andere Reihenfolge zu nutzen als die Input-Reihenfolge

Antwort als JSON mit Schema:
{
  "executive_summary": "...",
  "findings_narrative": [
    { "finding_id": "...", "description": "...", "recommendation_text": "..." },
    ...
  ]
}
```

## 7. Property-Garantien

Die folgenden Eigenschaften müssen testbar sein:

| Property | Test |
|---|---|
| **Determinismus** | `select_findings(F, p)` zweimal → identisches Resultat |
| **Top-N-Bound** | `len(result.selected) ≤ TOP_N_PER_PACKAGE[p]` |
| **No-Duplicates** | Konsolidierung ist effektiv: keine zwei Findings mit gleichem Hash |
| **Stable-Sort** | Bei Tie-Score gewinnt alphabetisch erste finding_id |
| **Critical-First** | Wenn ≥1 critical existiert, ist das erste Element critical |
| **No-Loss** | `len(result.selected) + len(result.additional) == len(input_after_consolidation)` |

## 8. Was passiert mit dem alten `cap_implausible_scores()`?

Wird **entfernt**. Severity-Policy + CVSS-Validation übernehmen die
Funktion strukturiert. `cap_implausible_scores()` war heuristisch ohne
klare Regel — die Policy macht es jetzt explizit.

## 9. Crosslinks

- Skeleton: [`04-selection-skeleton.py`](./04-selection-skeleton.py)
- Tests: [`04-selection-tests.py`](./04-selection-tests.py)
- Severity-Policy: [`02-severity-policy.md`](./02-severity-policy.md)

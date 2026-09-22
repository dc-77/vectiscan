# 06 — v2-Renderer

`report-worker/reporter/pdf/v2/` — die 3-Schichten-PDF-Architektur, seit `docker-compose.yml:419` der Default in Prod.

## Einstieg: generate_report_v2 (pdf/v2/generate.py:29)

```python
def generate_report_v2(report_data, output_path):
    meta = report_data.get("meta", {}) or {}
    doc = BaseDocTemplate(
        output_path,
        pagesize=(WIDTH, HEIGHT),             # A4 aus reporter.generate_report
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=22 * mm,
        bottomMargin=20 * mm,
        title=meta.get("title", "VectiScan Report"),
        author=meta.get("author", "VectiScan"),
    )
    doc._meta = meta
    doc._classification_label = meta.get(
        "classification_label",
        "KLASSIFIZIERUNG: VERTRAULICH -- NUR FUER AUTORISIERTE EMPFAENGER",
    )
```

### Page-Templates (generate.py:57-70)

Zwei Frames + PageTemplates:

```python
cover_frame  = Frame(25*mm, 20*mm, WIDTH-50*mm, HEIGHT-40*mm, id="cover")
normal_frame = Frame(20*mm, 20*mm, WIDTH-40*mm, HEIGHT-40*mm, id="normal")
doc.addPageTemplates([
    PageTemplate(id="cover",  frames=[cover_frame],  onPage=draw_cover),
    PageTemplate(id="normal", frames=[normal_frame], onPage=draw_normal),
])
```

`draw_cover` und `draw_normal` kommen aus dem v1-Renderer (`reporter/generate_report.py`). Cover-Hintergrund ist dunkel (`#1a1a2e`), Normal-Hintergrund hell. Beide Funktionen zeichnen die Klassifizierungs-Bar als Page-Decoration.

### Story-Aufbau (generate.py:72-82)

```python
styles = create_styles()
story = []
build_cover_v2(story, styles, report_data.get("cover", {}))   # pdf/v2/cover.py:10
build_layer1_frontpage(story, styles, report_data)            # layers/frontpage.py:34
build_layer2_strategy(story, styles, report_data)             # layers/strategy.py:465
build_layer3_findings(story, styles, report_data)             # layers/findings.py:420
build_appendix(story, styles, report_data)                    # layers/appendix.py:619
doc.build(story)
```

Reihenfolge ist linear; jeder Builder appended Flowables an `story`.

## Cover (pdf/v2/cover.py)

`build_cover_v2(story, styles, cover_data)` (Z. 10):

- Liest `cover_data` mit Keys `cover_title`, `cover_subtitle`, `cover_meta`.
- Konstanten: `LIGHT="#FFFFFF"`, `SUBTLE="#94A3B8"` (Z. 22-23).
- Title-Split (Z. 30-37): wenn Title mit `"Sicherheitsbewertung"`, `"Security Assessment"` oder `"Sicherheits-Assessment"` beginnt, wird der Rest auf eine eigene Zeile in 18pt umgebrochen — verhindert, dass lange Domains aus dem Frame laufen.
- `cover_meta`-Filter (Z. 64): Rows mit Label-Prefix `"ergebnis"`, `"risiko"`, `"befunde"` werden NICHT auf dem Cover gerendert (Datenschutz, ausdrücklich kein Risiko auf dem Cover).
- Template-Switch (Z. 72-73): `NextPageTemplate("normal")` VOR `PageBreak()` — der Wechsel passiert auf der nächsten Seite.

## Sechs Custom Flowables (pdf/v2/flowables.py)

Alle erben von `reportlab.platypus.Flowable`:

| Klasse | Zeile | Zweck | Konsument |
|---|---|---|---|
| `AmpelBar` | 16 | Risk-Bar pro Kategorie, 5 Level-Mapping (HOCH/MITTEL-HOCH/MITTEL/NIEDRIG-MITTEL/NIEDRIG/INFO) | frontpage |
| `HebelBox` | 74 | Top-3-Hebel-Box: Rank + Titel + Effekt + Finding-IDs | frontpage |
| `KategorieBlock` | 108 | Befund-Landschaft-Block: Kategorie-Header + max 8 Findings | strategy |
| `PostureIndicator` | 143 | Mini-Dashboard für Mail/Web/DNS/TLS mit Status-Pillen (grün/rot/gelb) | strategy |
| `ServiceCard` | 198 | Host-Karte mit Port-Chips (max 6 pro Reihe) | strategy |
| `FindingHeaderV2` | 239 | Befund-Header (ID, Titel, Priorität, Risiko, Policy-ID) | findings |

`AmpelBar._bar_width` (Z. 51) und `_bar_color` (Z. 62) machen Level → (Breite, Hex-Farbe) Mapping.

## Schicht 1 — frontpage (pdf/v2/layers/frontpage.py)

`build_layer1_frontpage(story, styles, data)` (Z. 34) — Seite 2 "Auf einen Blick".

Liest aus `data`:
- `data["layer1"]` — vollständiges Aggregat aus `layer1_aggregator.build_layer1` (siehe `07_layer1_aggregators.md`).
- `data["compliance_indicators"]` — bis zu 3 Status-Pillen aus `v2_data.build_compliance_indicators`.

`_STATUS_COLOR_HEX` Mapping (frontpage.py top, M5):
```
"Konform"         -> "#16A34A"
"Teilerfuellt"    -> "#CA8A04"
"Handlungsbedarf" -> "#DC2626"
```

Rendering-Reihenfolge: H1 → Risiko-Ampel (`AmpelBar` pro Kategorie) → Gesamtbewertung-Text → Top-3-Hebel (`HebelBox` × 3) → Kontext-Block → Compliance-Pillen.

## Schicht 2 — strategy (pdf/v2/layers/strategy.py)

`build_layer2_strategy(story, styles, data)` (Z. 465) orchestriert 7 Builder:

```python
_build_business_context(story, styles, data)        # Z. 55  -- Seite 3
_build_scope_methodology(story, styles, data)       # Z. 109 -- Seite 4-5
_build_tech_stack(story, styles, data)              # Z. 225 -- Seite 6
_build_service_cards(story, styles, data)           # Z. 308 -- Seite 7
_build_posture_indicators(story, styles, data)      # Z. 330 -- Seite 7
_build_screenshots_v2(story, styles, data)          # Z. 348 -- Seite 7-8
_build_befund_landschaft(story, styles, data)       # Z. 424 -- Seite 8-9
```

Details in `08_layer2_data.md`.

## Schicht 3 — findings (pdf/v2/layers/findings.py)

`build_layer3_findings(story, styles, data)` (Z. 420):

Iteriert über `data["findings"]`, ruft `_build_single_finding` (Z. 300) für jedes nicht-positive Finding auf. Wraps jeden Finding in `KeepTogether`, damit der 7-Sektionen-Body nicht über Seiten-Breaks zerrissen wird (best-effort — bei sehr langen Findings darf trotzdem gebrochen werden).

Details in `09_layer3_findings.md`.

## Anhänge — appendix (pdf/v2/layers/appendix.py)

`build_appendix(story, styles, data)` (Z. 619):

```python
_build_appendix_a(story, styles, data)   # CVSS + Hygiene
_build_appendix_b(story, styles, data)   # Service-Inventar
_build_appendix_c(story, styles, data)   # Tools + Konfidenz
_build_appendix_d(story, styles, data)   # Compliance-Mapping
_build_appendix_e(story, styles, data)   # Filterungen
_build_appendix_f(story, styles, data)   # Wiederholung + Haftung
```

Details in `10_appendices.md`.

## Welche report_data-Keys jede Schicht braucht

| Schicht | Builder | report_data-Keys |
|---|---|---|
| Cover | `build_cover_v2` | `cover.cover_title, cover.cover_subtitle, cover.cover_meta` |
| Layer1 | `build_layer1_frontpage` | `layer1.risk_categories[], layer1.massnahmen_top3[], layer1.kontext, layer1.gesamtbewertung, compliance_indicators[]` |
| Layer2 (BC) | `_build_business_context` | `business_context.industry_label, .narrative, .data_kinds, .compliance_focus` |
| Layer2 (Scope) | `_build_scope_methodology` | `scope_meta.{domain, hosts_count, subdomains_count, scan_date, started_at, finished_at, package, out_of_scope}`, `methodology_stats.{filtered_count, selected_count, filter_rate_pct, policy_version, ai_models, tool_versions, phase_descriptions}` |
| Layer2 (Tech) | `_build_tech_stack` | `tech_table_v2[].{host, rows[]}` mit `rows[].{name, version, category, patch_status, top_cve, source}` |
| Layer2 (Services) | `_build_service_cards` | `service_cards[].{host, ports[]}` |
| Layer2 (Posture) | `_build_posture_indicators` | `posture_indicators[].{label, sub_indicators[].{name, status, detail}}` |
| Layer2 (Screenshots) | `_build_screenshots_v2` | `screenshots_v2[].{path, caption, urls[]}` |
| Layer2 (Landschaft) | `_build_befund_landschaft` | `befund_landschaft.categories[].{key, label, findings[]}`, `befund_landschaft.positive_findings[]` |
| Layer3 | `build_layer3_findings` | `findings[]` (komplette Finding-Dicts), `compliance_mappings[finding_id]` |
| Appendix A | `_build_appendix_a` | `findings[]` (für Hygiene-Subgroup), `methodology_stats` |
| Appendix B | `_build_appendix_b` | `service_cards[]`, `findings[]` (für Port-Cross-Reference) |
| Appendix C | `_build_appendix_c` | `report_mapper.SCAN_TOOLS` (Const im Code), `scope_meta.tool_versions` |
| Appendix D | `_build_appendix_d` | `findings[]`, `compliance_mappings[finding_id]` |
| Appendix E | `_build_appendix_e` | `additional_findings[]`, `methodology_stats` |
| Appendix F | `_build_appendix_f` | `scope_meta` (Datum für Wiederholungs-Empfehlung) |

## Defensive Pfade

Alle Builder verwenden `data.get("…") or {…}` bzw. `or []`-Pattern. Fehlende v2-Augment-Felder (z.B. wenn `_augment_for_v2` für ein Sub-Feld ge-`except`-t hat) führen zu leeren Sektionen, nicht zu Crash. Der Renderer ist forward-kompatibel mit teilweise befüllten `report_data`-Dicts.

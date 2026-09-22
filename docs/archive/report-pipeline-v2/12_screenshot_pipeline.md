# 12 — Screenshot-Pipeline

Zwei Stufen: `report_mapper._build_screenshot_data` (Vorverarbeitung) → `screenshot_pipeline.dedup_and_cap` (Body-Hash-Dedup + Cap) → `pdf/v2/layers/strategy.py:_build_screenshots_v2` (Render).

## Stufe 1: report_mapper._build_screenshot_data (Z. 788)

Aufgerufen in den paket-spezifischen Mappern (`report_mapper.py:1038` und 1125). Erzeugt die initiale Screenshot-Liste:

### Input

- `host_inventory.hosts[]` mit `ip, fqdns, vhosts`.
- `host_screenshots` aus `parser.parse_scan_data` — entweder Legacy-Schema `{ip: [path, ...]}` oder neues per-VHost-Schema `{ip: [{vhost: fqdn, path: ...}]}` (F-PH1-003, `parser.py:1283-1290`).

### Verarbeitung (Z. 836-905)

1. Normalisierung beider Schemata zu `(vhost, path)`-Tupeln.
2. Pfad-Dedup pro IP (Z. 859-865, gleicher Pfad wird nicht doppelt aufgenommen).
3. Cap pro Host: `_MAX_SCREENSHOTS_PER_HOST_IN_PDF` (Konstante im selben Modul, siehe Code für aktuellen Wert).
4. Skip von Non-Content (PR-F, Mai 2026): wenn `vhost.site_summary.is_real_content == False`, wird der Eintrag übersprungen — Parking-Pages, Error-Seiten, Non-Web werden nicht in den Customer-Report aufgenommen.
5. Pro VHost ein eigener Eintrag (`label = "<vhost> (Screenshot)"`), mit optional:
   - `caption` aus `vhost.site_summary.description`.
   - `tech_chips` aus `tech_profile.tech` für diesen VHost.
   - `classification` aus `site_summary` (steuert das `skip_non_content`-Flag).

### Output-Schema

```python
[
  {
    "label":          "<vhost> (Screenshot)",
    "paths":          ["/abs/path/to/screenshot_<vhost>.png"],
    "caption":        "Optional: Site-Summary-Text",
    "tech_chips":     ["WordPress 6.4", "PHP 8.2"],
    "classification": "real_content" | "parking" | "error" | ...,
  },
  ...
]
```

Eintrag in `report_data["screenshots"]`.

## Stufe 2: screenshot_pipeline.dedup_and_cap (Z. 58)

Wird im `_augment_for_v2`-Block aufgerufen (`report_mapper.py:1939-1941`):

```python
from reporter.screenshot_pipeline import dedup_and_cap
original_screenshots = report_data.get("screenshots") or []
report_data["screenshots_v2"] = dedup_and_cap(original_screenshots)
```

Wichtig: das v1-Feld `screenshots` bleibt unverändert (für Legacy-Renderer ohne Cap); v2 liest `screenshots_v2`.

### DEFAULT_MAX_SCREENSHOTS

```python
# screenshot_pipeline.py:31
DEFAULT_MAX_SCREENSHOTS = 2
```

Begründung aus dem Code-Header (Z. 8-9): "max. 2 Screenshots im Default-Layout — groesste Sichtbarkeit fuer die produktivsten Hosts."

### Verarbeitung (Z. 78-152)

1. **Hash-Berechnung** (`_hash_file`, Z. 34): SHA256 über die Bild-Bytes des ersten Pfads pro Eintrag, 64KB-Chunks. Bei IO-Fehler: `None`.
2. **Dateien-Check** (Z. 88-93): Einträge ohne lesbare Datei werden übersprungen.
3. **Gruppierung** (Z. 100-107): Einträge mit gleichem Hash landen in einem Bucket; Einträge ohne Hash (None) in `nonhashable[]`.
4. **Dedup pro Bucket** (Z. 109-121): erstes Vorkommen behalten (shallow-copy, Originale werden nicht mutiert). Bei mehr als 1 Element im Bucket:
   - `caption_dedup = "Identisch auf <label1>, <label2>, <label3>"` (Z. 117-119).
   - `dedup_count = <Gruppen-Größe>`.
5. **Sortierung** (Z. 123-133): Schlüssel `(- dedup_count, insertion_index)`. Größte Gruppen zuerst (signalisieren breite Verteilung), dann Original-Reihenfolge für Stabilität.
6. **Nicht-hashbare Einträge** (Z. 137): werden hinten angehängt (Datei-Lese-Probleme sollen den anderen Renderer-Pfad nicht blockieren).
7. **Cap** (Z. 140-150): wenn die deduplizierte Liste länger ist als `max_screenshots`, harter Schnitt. `screenshot_pipeline_capped`-Log.

### Output-Schema (zusätzliche Felder vs Stufe 1)

```python
[
  {
    ...,                              # alles aus Stufe 1
    "caption_dedup": "Identisch auf foo.example.de, bar.example.de",  # NEU
    "dedup_count":   3,                                                # NEU
  },
  ...
]
```

### _entry_label_short (Z. 50)

Verkürzt `"foo.example.de (Screenshot)"` zu `"foo.example.de"` für die `caption_dedup`-Zeile — ohne den `(Screenshot)`-Suffix lesbarer.

## Stufe 3: Render in pdf/v2/layers/strategy.py:_build_screenshots_v2 (Z. 348)

```python
entries = data.get("screenshots_v2") or []
if not entries:
    return

_subsection(story, styles, "Web-Oberflaechen")
_body(story, styles, "Die folgenden Screenshots sind eine kuratierte Auswahl: ...")
```

Pro Entry:

1. **Label** als Paragraph mit `ScreenshotLabel`-Style (Z. 367, Fallback `SubsectionTitle` → `BodyText`).
2. **Image** mit Scaling auf `_MAX_IMAGE_WIDTH_V2 = 160 mm` (Z. 386-388), Cap auf `120 mm` Höhe (Z. 390-393). Bei IO-Fehler: Block wird komplett verworfen (kein halber Eintrag).
3. **caption** als kursiver Paragraph (Z. 399-402).
4. **caption_dedup** als kursiver Paragraph in grau (`#64748B`) — visuell sekundär zur primären Caption (Z. 404-410).
5. **tech_chips** als Bullet-Liste mit Mittelpunkt-Separator (Z. 412-415).

Jeder Block ist in `KeepTogether` gewrapped (Z. 418), damit das Bild nicht vom Label oder Caption getrennt wird.

## Render-Reihenfolge im PDF

Im Layer 2 ("Strategy"), nach den Posture-Indikatoren, vor der Befund-Landschaft:

```
build_layer2_strategy
  ├─ _build_business_context
  ├─ _build_scope_methodology
  ├─ _build_tech_stack
  ├─ _build_service_cards
  ├─ _build_posture_indicators
  ├─ _build_screenshots_v2     ← HIER
  └─ _build_befund_landschaft
```

## Annotation-Layer (geplant, nicht aktiv)

Im Modul-Header (`screenshot_pipeline.py:13-15`):

> "Optionaler Annotation-Layer (Pillow-based, Finding-Kontext-getriggert) ist strukturell vorbereitet, aber konservativ deaktiviert — ein falsches Highlight schadet mehr als gar keins (siehe Master-Plan M6, Risiken)."

Aktueller Stand: nur Body-Hash-Dedup + Cap, keine Annotation auf den Bildern.

## Beispiel-Output

Eingabe (heuel.com mit zwei VHosts, beide zeigen Plesk-Default):

```
[
  {"label": "www.heuel.com (Screenshot)", "paths": ["/tmp/.../screenshot_www.heuel.com.png"], ...},
  {"label": "heuel.com (Screenshot)",     "paths": ["/tmp/.../screenshot_heuel.com.png"],     ...},
]
```

Wenn beide Dateien byte-identisch (Plesk-Default-Page):

```
screenshots_v2 = [
  {
    "label": "www.heuel.com (Screenshot)",
    "paths": ["..."],
    "caption_dedup": "Identisch auf heuel.com",
    "dedup_count": 2,
  }
]
```

Im PDF erscheint nur ein Screenshot mit der grauen Caption "Identisch auf heuel.com" — der zweite Host bleibt in der Service-Card-Tabelle und im Anhang B sichtbar, aber kein weiteres Plesk-Screenshot wird gerendert.

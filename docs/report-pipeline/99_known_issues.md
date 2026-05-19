# 99 — Known Issues

Diskrepanzen Code ↔ Code, oder Code ↔ Doku, die während dieser Code-Truth-Inventur aufgefallen sind. Stand 2026-05-19.

## 1. Doppelter POLICY_VERSION-Default in zwei Modulen

**Datei 1:** `report-worker/reporter/severity_policy.py:36`
```python
POLICY_VERSION = os.environ.get("VECTISCAN_POLICY_VERSION", "2026-06-01.1")
```

**Datei 2:** `report-worker/reporter/ai_cache.py:22`
```python
POLICY_VERSION = os.environ.get("VECTISCAN_POLICY_VERSION", "2026-05-10.1")
```

**Problem:** Die ENV-Variable `VECTISCAN_POLICY_VERSION` ist im Prod-`docker-compose.yml` nicht gesetzt (Z. 404-405 erwähnen sie nur als Override-Möglichkeit). Damit gilt der Code-Default — und der ist in den zwei Modulen unterschiedlich.

**Auswirkung:**

- `severity_policy.apply_policy` schreibt `severity_provenance.policy_version = "2026-06-01.1"` (über `SeverityProvenance.policy_version: str = POLICY_VERSION`).
- Der AI-Cache (`ai_cache.py`) baut den Cache-Key mit `POLICY_VERSION = "2026-05-10.1"`.

Das automatische Cache-Invalidate beim POLICY_VERSION-Bump funktioniert dadurch zwischen den beiden Versionen nicht synchron: Findings werden mit der neuen Policy bewertet, aber AI-Calls referenzieren den alten Cache-Schlüssel.

**Fix-Vorschlag:** Beide Module sollten denselben Default haben oder beide aus einer zentralen Konstante lesen (z.B. `severity_policy.POLICY_VERSION` importieren).

## 2. v2_data.build_methodology_stats hat eigene POLICY_VERSION-Quelle

**Datei:** `report-worker/reporter/v2_data.py:122-126`

```python
policy_version = os.environ.get(
    "VECTISCAN_POLICY_VERSION",
    # gleicher Default wie severity_policy.POLICY_VERSION
    "2026-06-01.1",
)
```

Code-Kommentar sagt "gleicher Default wie severity_policy.POLICY_VERSION" — was stimmt, aber der Wert ist hartcodiert dupliziert. Wenn `severity_policy.POLICY_VERSION` hochgezogen wird, vergisst man hier leicht die Aktualisierung.

**Fix-Vorschlag:** `from reporter.severity_policy import POLICY_VERSION` statt eigenes `os.environ.get`.

## 3. CLAUDE.md sagt "5 KI-Punkte", Code zeigt 3 in der PDF

**CLAUDE.md (Header `## Scan-Worker (6 Phasen, 4 KI-Punkte)`)** erwähnt:

> "0a Passive Intel … → 0b DNS+httpx+Scope → KI #1 Host-Strategy (Haiku) → 1 Tech-Detection … → KI #2 CMS-Korrektur (Haiku) + KI #3 Phase-2-Config (Haiku) → 2 Deep-Scan … → KI #4 Cross-Tool-Confidence (Sonnet, nur Confidence-Boost) → 3 Correlation + Threat-Intel …"

Plus separater Hinweis "5 Prompt-Varianten" beim Report-Worker.

**Code-Wahrheit:** `v2_data.build_methodology_stats:128-154` listet in der `ai_models`-Sektion (die im PDF auf Seite 4 angezeigt wird) nur **3 Einträge**:

1. Sonnet 4.6 (Cross-Tool-Confidence-Boost, Phase 3 + neue Finding-Pattern).
2. Haiku 4.5 (Host-Strategie, Phase-2-Tool-Konfiguration, Title-Type-Fallback).
3. VECTISCAN-Severity-Policy `<version>` (deterministisch, keine KI).

Die Granularität "KI #1 bis #4" aus CLAUDE.md taucht nirgendwo in den `ai_models`-Daten auf. Render-Text auf Seite 4 ist daher knapper.

**Fix-Vorschlag:** Entweder CLAUDE.md korrigieren oder `ai_models` um die feinere Phase-Zuordnung erweitern.

## 4. report_mapper liest mit Legacy-Paket-Defaults

**Datei:** `report-worker/reporter/report_mapper.py:1698`

```python
def map_to_report_data(
    ...,
    package: str = "professional",
    ...
):
```

Default ist `"professional"` (Legacy-Alias). Wird vom Mapper über `mappers.get(package, map_professional_report)` resolved (`report_mapper.py:1731`) — Aliase greifen also. In der Praxis kommt `package` immer aus `job_data["package"]` (`worker.py:416` mit Default `"perimeter"`).

**Auswirkung:** Wenn jemand `map_to_report_data` direkt aufruft ohne `package`-Argument, bekommt er den Legacy-Pfad. In Prod nicht relevant, in Tests evtl. überraschend.

## 5. Default VECTISCAN_REPORT_LAYOUT divergiert zwischen Code und Compose

**Code-Default** (`worker.py:711`, `report_mapper.py:1776`): `"v1"`.

**Compose-Default** (`docker-compose.yml:419`): `${VECTISCAN_REPORT_LAYOUT:-v2}` → `"v2"`.

In Prod gilt der Compose-Wert. In lokalen Tests ohne ENV-Override (z.B. `pytest`) gilt der Code-Default `v1` — das ist absichtlich für die Test-Suite (siehe `tests/test_pdf_v2_skeleton.py:108-115` `monkeypatch.setenv`).

**Auswirkung:** Lokale Ad-hoc-Skripte, die `generate_report_v2` testen wollen, müssen `VECTISCAN_REPORT_LAYOUT=v2` explizit setzen — sonst läuft der v1-Pfad und das `_augment_for_v2` wird übersprungen. Kein Bug, aber Stolperstein.

## 6. CHECK_REGISTRY-Fehler werden als Skip behandelt

**Datei:** `validation/gate.py:149-154`

```python
def _load_check(self, name: str, module_path: str) -> Callable | None:
    try:
        mod = __import__(module_path, fromlist=["check"])
        return getattr(mod, "check", None)
    except ImportError:
        return None
```

Nur `ImportError` wird abgefangen. Wenn das Check-Modul einen anderen Import-Fehler beim Modul-Init wirft (z.B. `ValueError` in einer Konstanten-Berechnung), crasht `_load_check` mit Stack-Trace im Worker.

Innerhalb der Check-Funktion selbst gibt es danach noch einen `try/except Exception` (Z. 114-129), aber der Modul-Load-Pfad ist unbalanciert.

**Fix-Vorschlag:** `except Exception` in `_load_check` mit Warning-Log, statt nur `ImportError`.

## 7. Bug-Marker aus Memory `project_report_redesign.md` (M6.18)

**Status:** offen laut Memory `project_report_redesign.md`.

> M6.18 (FTP→URLhaus-Klassifikationsbug): Reporter klassifiziert FTP-Findings unter Umständen als URLhaus-Treffer. Sehe Mapper-Logik im `befund_landschaft.py` und im URLhaus-Pattern.

In dieser Inventur nicht direkt verifiziert; siehe Memory für Reproducer.

## 8. screenshot_pipeline: Insertion-Index-Lookup ist O(n²)

**Datei:** `screenshot_pipeline.py:155-167`

`_first_hash_of_entry(entry, hashed)` iteriert linear über alle `hashed`-Einträge pro Sort-Key-Aufruf. In der Sort-Comparator-Funktion (Z. 130-133) wird das pro Element aufgerufen → O(n²).

In Prod mit `DEFAULT_MAX_SCREENSHOTS = 2` und typisch < 20 Screenshots pro Scan irrelevant. Bei massiv erhöhtem Cap könnte das auffallen.

**Fix-Vorschlag:** Pre-compute `entry id → hash`-Map vor dem Sort.

## 9. Selection-Floor "deficit"-Berechnung

**Datei:** `selection.py:289-302`

```python
min_n = MIN_N_PER_PACKAGE.get(package_norm, 0) if top_n_override is None else 0
if min_n > 0 and len(selected) < min_n:
    deficit = min_n - len(selected)
    if additional:
        extra = additional[:deficit]
        selected = selected + extra
        additional = additional[deficit:]
        floor_applied = len(extra)
    if len(selected) < min_n:
        retry_hint = (
            f"package={package_norm} hat nur {len(selected)} Findings "
            f"(Min {min_n}); KI lieferte zu wenig — Retry mit Hinweis sinnvoll."
        )
```

Der Floor wird NUR bei `top_n_override is None` aktiviert. Wenn ein Caller explizit ein `top_n_override` setzt und der Floor unterschritten wird, gibt es keine Warning. In Prod nicht erreicht — `apply_deterministic_pipeline` ruft `select_findings` ohne Override.

## 10. Nicht-trivialer Pfad: domain-fallback in business_context

**Datei:** `business_context.py:253-271`

`_detect_industry_from_domain` ist sehr konservativ und erkennt nur 9 Token-Muster — eine Domain wie `daniel-czischke-anwalt.de` matched `legal_services`, aber `czischke.de` nicht. Das ist beabsichtigt (Kommentar Z. 254-256), kann aber für Customer überraschend sein, wenn die Branchenheuristik nicht greift und der Generic-Cluster verwendet wird.

**Mitigation:** Order-Wizard kann `industry_vertical` explizit setzen (höchste Priorität in der Heuristik).

---

## Bestätigt: keine Bug-Marker

Während der PDF-Inspektion der zwei Sample-Reports wurde stichprobenartig geprüft, ob die in Code dokumentierten Felder (Cover-Title-Split, Service-Cards-Prod-Format, Header-Doppelung, Security-Header-Filter aus Commit `6fa6a36`, Posture-Pillen aus Commit `263fbdd`) wirklich so im Render erscheinen — sie tun es. Keine Code ≠ Rendering Mismatches gefunden.

Wenn neue Mismatches bei der Doku-Pflege entdeckt werden, hier ergänzen.

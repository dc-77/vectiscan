# 05 — Validation-Gate

`reporter/validation/` — die letzte Determinismus-Schicht vor dem PDF-Build.

## Aufruf-Punkt

`worker.py:650-705`. Wird zwischen `_build_findings_data` und PDF-Generierung aufgerufen. STRICT-Failure setzt Order auf `failed` ohne PDF-Build.

## ValidationGate (validation/gate.py)

### ValidationLevel-Enum (Z. 19)

```python
class ValidationLevel(str, Enum):
    OFF    = "off"     # nur fuer lokale Tests, Gate-Body wird ge-shortcut
    WARN   = "warn"    # Defekte -> logs + reports.validation_warnings, Build laeuft
    STRICT = "strict"  # Defekte -> Order failed, kein PDF/Upload
```

In Prod: `VECTISCAN_VALIDATION_LEVEL=strict` (`docker-compose.yml:411`). Fallback auf `warn` bei ungültigem ENV-Wert (`gate.py:91`).

### ValidationIssue Dataclass (Z. 26)

```python
@dataclass
class ValidationIssue:
    check: str               # "titles" | "ids" | "cvss" | "consistency" | "tech_table" | "eol" | "plan"
    severity: str            # "error" | "warning"
    finding_id: str | None
    message: str
    detail: dict[str, Any] = field(default_factory=dict)
```

### ValidationResult Dataclass (Z. 35)

```python
@dataclass
class ValidationResult:
    passed: bool
    level: ValidationLevel
    errors:    list[ValidationIssue]
    warnings:  list[ValidationIssue]
    checks_run:     list[str]
    checks_skipped: list[str]

    def to_json(self) -> dict[str, Any]
```

`to_json` (Z. 44) ist das genaue Schema, das in `reports.validation_warnings` (Migration 028) landet:

```json
{
  "passed": true,
  "level": "strict",
  "errors": [],
  "warnings": [
    {
      "check": "consistency",
      "severity": "warning",
      "finding_id": "VS-2026-007",
      "message": "...",
      "detail": {...}
    }
  ],
  "checks_run": ["titles", "ids", "cvss", "consistency", "tech_table", "eol", "plan"],
  "checks_skipped": [],
  "error_count": 0,
  "warning_count": 1
}
```

### Check-Registry (Z. 61)

```python
CHECK_REGISTRY: list[tuple[str, str]] = [
    ("titles",      "reporter.validation.checks.titles"),
    ("ids",         "reporter.validation.checks.ids"),
    ("cvss",        "reporter.validation.checks.cvss"),
    ("consistency", "reporter.validation.checks.consistency"),
    ("tech_table",  "reporter.validation.checks.tech_table"),
    ("eol",         "reporter.validation.checks.eol"),
    ("plan",        "reporter.validation.checks.plan"),
]
```

### ValidationGate.run (Z. 95)

```
1. self.level == OFF? -> return ValidationResult(passed=True)
2. fuer jede (name, module_path) in CHECK_REGISTRY:
     a. _load_check(name, module_path):
          __import__(module_path, fromlist=["check"])
          getattr(mod, "check", None)
          ImportError -> None
     b. None -> result.checks_skipped.append(name); continue
     c. issues = check_fn(findings_data, report_data, context) or []
          try/except: Crash -> Warning(check=name, message=f"Check crashed: {e}"); continue
     d. result.checks_run.append(name)
     e. fuer jede issue: error -> errors, warning -> warnings
3. result.passed = (len(errors) == 0)
4. log.info("validation_gate_complete", ...)
```

`_load_check` (Z. 149) gibt bei `ImportError` `None` zurück — wenn ein Check-Modul fehlt, wird der Check als `skipped` markiert, das Gate crasht nicht.

### ValidationFailedError (Z. 157)

```python
class ValidationFailedError(RuntimeError):
    def __init__(self, result: ValidationResult):
        self.result = result
        super().__init__(f"Validation failed with {len(result.errors)} errors")
```

Wird im Worker (`worker.py:705`) im STRICT-Fall geraised. Der Outer-Except in `worker.py:826` erkennt diesen Typ und überschreibt die kuratierte `error_message` nicht.

## Check-Module

Alle haben Signatur:

```python
def check(findings_data: dict, report_data: dict, context: dict) -> list[ValidationIssue]
```

Imported lazy aus `CHECK_REGISTRY`. Eingaben:
- `findings_data` — aus `_build_findings_data(claude_output, package, report_data)` (`worker.py:659`).
- `report_data` — vor PDF-Render, inkl. v2-Augments.
- `context` — `{"package", "order_id", "domain", "tech_profiles"}` (`worker.py:666-675`).

### titles (validation/checks/titles.py)

| Defekt | ID | Severity | Regex |
|---|---|---|---|
| Leerer Title | — | error | `title.strip() == ""` |
| Unaufgelöste Platzhalter (P0-01) | `{xxx}` | error | `_PLACEHOLDER_RE = r"\{[a-z_][a-z0-9_]*\}"` (Z. 25) |
| Bareword-Number (P0-05) | nackte Zahl | warning | `_BARE_NUMBER_RE` minus `_KNOWN_PORTS` (Z. 28-34, 16 Standard-Ports) minus `_VERSION_RE` minus `_NUMBER_WITH_UNIT_RE` |
| Duplikat-Title (P0-04) | — | error | gruppiert nach normalisiertem Title |

Whitelist-Ports (`titles.py:28-34`): 20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 636, 993, 995, 1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 9300, 27017, 11211, 5060, 5061.

### ids (validation/checks/ids.py)

| Defekt | Severity |
|---|---|
| Format != `VS-YYYY-NNN` | error |
| Lücke in Nummerierung ab 001 (Counter-Diff > 1) | warning |
| Duplikat-ID | error |

### cvss (validation/checks/cvss.py)

Nutzt die `cvss`-Library (P1-02):

| Defekt | Severity |
|---|---|
| Score 0.0 mit Impact-Tokens in Title/Evidence (P1-01) | error |
| Score ↔ Vektor Mismatch (rekalkuliert vs angegebener Score, Toleranz 0.1) | error |
| Vektor ohne `CVSS:3.1/`-Prefix (P2-05) | error |

### consistency (validation/checks/consistency.py)

| Defekt | Severity | Trigger |
|---|---|---|
| Version-Konflikt Title ↔ Tech-Tabelle (P0-02) | error | Title nennt `Apache 2.4.49`, Tech-Tabelle hat `Apache 2.4.62` |
| Service-Verwechslung (P0-03, CONFLICTING_PAIRS) | error | Title sagt "SSH" aber Evidence belegt HTTP; "SPF" aber DKIM-Daten; "MariaDB" aber MySQL-Banner |
| Keyword-Overlap (generischer Title) | warning | Title enthält nur generische Wörter ohne Spezifika |

`_get_tech_versions(tech_profiles)` (Helper) liest `tech_profiles[*].tech_rows`, ggf. `cms`, `server_banner`.

### tech_table (validation/checks/tech_table.py)

Liest `report_data["tech_table_v2"]` oder `context["tech_profiles"][*].tech_rows`.

| Defekt | Severity |
|---|---|
| Kernel-Detection-Blacklist-Treffer (P1-05) | error |
| Minor-Version unter MIN_PUBLIC_VERSIONS (P2-04) | warning |

Quelle für beide Listen: `tech_table_builder.KERNEL_DETECTION_BLACKLIST` und `MIN_PUBLIC_VERSIONS`.

### eol (validation/checks/eol.py)

| Defekt | Severity |
|---|---|
| EOL-Datum im Title ↔ Tech-Tabelle stimmt nicht überein (P1-03) | warning |
| MariaDB ↔ MySQL Verwechslung in EOL-Findings | warning |

`_find_dates(text)` erkennt ISO-Datum + deutsche/englische Monatsnamen.

### plan (validation/checks/plan.py)

Prüft `report_data["recommendations"]` gegen `findings`.

| Defekt | Severity |
|---|---|
| Recommendation ohne `finding_refs` (Orphan, P2-03) | warning |
| `finding_refs` zeigt auf nicht-existente ID | error |
| Recommendation nennt Port, der in keinem referenzierten Finding vorkommt | warning |

`_collect_finding_ports(findings)` baut Port-Index pro `finding_id`.

## Persistenz (Migration 028)

`worker.py:679-680`:

```python
validation_warnings_payload = gate_result.to_json()
report_data["_validation_warnings"] = validation_warnings_payload
```

und in `_create_report_record` (Aufruf `worker.py:748-755`):

```python
... , validation_warnings=validation_warnings_payload, ...
```

`_create_report_record` (`worker.py` ~Z. 115-200) führt einen Runtime-Check, ob die Spalte `validation_warnings` in `reports` existiert. Falls nicht: Warning-Log, INSERT ohne das Feld (Fallback bis Migration 028 überall durchgelaufen ist).

## Replay-Tool (scripts/replay_gate.py)

```
python -m scripts.replay_gate --order-id <uuid-prefix>
python -m scripts.replay_gate --findings-json path/to/findings.json --package perimeter
python -m scripts.replay_gate --replay-m1-set
```

Drei Modi:
1. DB-Mode: zieht `findings_data` aus `reports`-Tabelle.
2. JSON-Mode: liest eine lokale JSON-Datei.
3. M1-Set-Replay: läuft gegen die zwei Real-Reports (secumetrix + heuel), die das M1-Validation-Akzeptanzkriterium definierten.

Akzeptanzkriterium: `--expect-min-errors N`. Exit 0 wenn `len(errors) >= N`.

## Fehlerklassifikation (Doc 01 P0/P1/P2 — vermerkt im Code-Header)

| Stufe | Beschreibung | Beispiel-Checks |
|---|---|---|
| P0 | Blockierer | titles (Platzhalter, Duplikate), ids (Format/Lücke), consistency (Version, Service-Mix-up) |
| P1 | Hygiene | cvss (Score↔Vektor), tech_table (Kernel-Blacklist), eol (Date-Conflict) |
| P2 | Plan | plan (tote Refs, Port-Mismatch), consistency (Keyword-Overlap), titles (Bareword) |

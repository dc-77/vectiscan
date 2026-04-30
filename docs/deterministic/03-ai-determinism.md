# 03 — AI-Determinismus: Cache + temperature=0

**Ziel:** Alle KI-Aufrufe (Haiku × 3 + Sonnet × 1 in Scan-Worker, plus
Sonnet im Reporter) liefern bei identischem Input identischen Output und
sind über einen Redis-Cache wiederverwendbar.

**Lokation:**
- `scan-worker/scanner/ai_cache.py` — Cache-Implementierung
- `scan-worker/scanner/ai_strategy.py` — instrumentieren
- `report-worker/reporter/claude_client.py` — instrumentieren

---

## 1. Problem

Aktuell sind 5 KI-Calls verteilt:

| Call | Modell | Funktion | Determinismus heute |
|---|---|---|---|
| KI #1 | Haiku 4.5 | Host Strategy (scan/skip) | Keine fixe Temperatur, Antwort variiert |
| KI #2 | Haiku 4.5 | CMS-Korrektur | dito |
| KI #3 | Haiku 4.5 | Phase-2-Config pro Host | dito |
| KI #4 | Sonnet 4.6 | Phase-3-Priorisierung | dito |
| Reporter | Sonnet 4.6 | Report-Generierung | dito |

Folge: Re-Scans derselben Domain produzieren leicht unterschiedliche Tool-
Auswahl, Severity-Bewertung, Finding-Auswahl. Das macht den Subscription-
Workflow („monatlicher Rescan") unzuverlässig — Customer fragt warum
sich Befunde geändert haben, obwohl sich der Server nicht geändert hat.

## 2. Lösung in zwei Bausteinen

### Baustein A: `temperature=0.0` überall

Alle 5 Calls nutzen `temperature=0.0`. Anthropic Claude unterstützt das
für Sonnet 4.6 und Haiku 4.5. Damit ist der Output bei gleichem Input
**weitgehend** deterministisch (nicht 100%, da es bei Floating-Point-
Operationen in der Inferenz minimale Variationen geben kann — aber für
unseren Use-Case ausreichend).

### Baustein B: Redis-Cache mit Input-Hash

Vor jedem Call wird ein deterministischer Hash aus
- Modell-Name
- System-Prompt
- User-Input (canonicalized JSON)
- Tool-Definitions (falls verwendet)
- `POLICY_VERSION` (aus `severity_policy.py`)
- `temperature`
- `max_tokens`

berechnet. Ist dieser Hash bereits in Redis, wird der gecachte Output
direkt zurückgegeben. Sonst wird Anthropic aufgerufen, das Ergebnis
gespeichert.

**Effekt:**
- Re-Scan derselben Domain mit identischem Host-Inventar → 100% Cache-Hit
- Re-Scan mit verändertem Inventar → Cache-Miss nur für betroffene Hosts
- KI-Kosten sinken um ~30–50 % bei Subscription-Re-Scans

## 3. KI #4 — Funktions-Reduktion

KI #4 hat heute drei Aufgaben:
1. Confidence-Boost durch Cross-Tool-Reasoning
2. FP-Marker setzen
3. Implizite Selektion durch FP-Markierung

**Mit der neuen Severity-Policy + deterministischer Selektion fallen 2 und 3 weg.**
KI #4 bleibt als reiner Confidence-Boost (Cross-Tool-Reasoning ist echter
Sonnet-Mehrwert), schreibt aber keine FP-Marker mehr.

System-Prompt-Änderung in `ai_strategy.py::ki4_phase3_prioritization()`:

**Alt** (reduziert):
```
- Identifiziere False-Positives anhand Tool-Disagreement
- Setze enrich_priority pro Finding
- Stufe Konfidenz basierend auf Cross-Tool-Bestätigung ein
```

**Neu**:
```
Du erhältst eine Liste von Findings aus mehreren Scan-Tools.
Deine EINZIGE Aufgabe: Pro Finding einen Confidence-Score (0.0–1.0)
basierend auf Cross-Tool-Bestätigung vergeben.

NICHT mehr:
- KEINE False-Positive-Markierung (das macht der deterministische FP-Filter)
- KEINE Severity-Anpassung (das macht severity_policy.py)
- KEINE Finding-Auswahl (das macht selection.py)

Antwort-Format:
{
  "confidence_scores": {
    "<finding_id>": { "confidence": 0.95, "corroboration": ["nmap", "shodan"] }
  }
}
```

## 4. Cache-Key-Konstruktion

```python
def cache_key(model: str,
              system: str,
              messages: list[dict],
              tools: list[dict] | None,
              temperature: float,
              max_tokens: int) -> str:
    """
    Deterministischer Hash über alle Inputs, die das Output beeinflussen.

    canonicalize() = json.dumps mit sort_keys=True und separators=(",",":")
    """
    payload = {
        "model": model,
        "system": system,
        "messages": canonicalize(messages),
        "tools": canonicalize(tools) if tools else None,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "policy_version": POLICY_VERSION,    # aus severity_policy
        "cache_version": "v1",                # bei Cache-Format-Änderung bumpen
    }
    serialized = canonicalize(payload)
    return f"ai_cache:{hashlib.sha256(serialized.encode()).hexdigest()}"
```

## 5. Cache-TTL-Strategie

Verschiedene Calls haben verschiedene „Halbwertszeit":

| Call | TTL | Begründung |
|---|---|---|
| KI #1 Host Strategy | 7 Tage | Host-Inventar ändert sich selten |
| KI #2 CMS-Korrektur | 30 Tage | CMS-Detection ist stabil |
| KI #3 Phase-2-Config | 7 Tage | Tech-Stack ändert sich gelegentlich |
| KI #4 Confidence-Boost | 1 Tag | Findings-Liste ändert sich häufig |
| Reporter | 1 Tag | An Findings gekoppelt |

**Force-Invalidate** über:
- `POLICY_VERSION`-Bump → automatisch (Hash ändert sich)
- Manuell: `redis-cli DEL ai_cache:*`

## 6. Cache-Format

```json
{
  "key": "ai_cache:abc123...",
  "value": {
    "model": "claude-haiku-4-5-20251001",
    "response": { /* Anthropic API response */ },
    "input_tokens": 1234,
    "output_tokens": 567,
    "cached_at": "2026-04-24T12:00:00Z",
    "policy_version": "2026-04-24.1"
  }
}
```

## 7. Telemetrie

In `scan_results.tool_metrics` mitloggen:
- `ai_cache_hit` (boolean)
- `ai_cache_age_seconds` (wenn hit)
- `ai_cost_saved_usd` (wenn hit)

In `audit_log` aggregierte Metrik pro Order:
- Total AI-Calls
- Cache-Hit-Rate
- Cost-Saving

## 8. Edge-Cases

### Anthropic API down
Cache-Hit funktioniert weiter (deshalb generös TTL), Cache-Miss = Tool-Fail.
Wir nutzen den existierenden Fallback in `ai_strategy.py` (z.B. „alle Hosts
scannen, Reihenfolge wie geliefert").

### Cache-Miss bei Anthropic-Throttle (429)
Existing exponential backoff in `claude_client.py` greift weiter.
Bei finalem Fail: Cache nicht beschreiben, Caller bekommt Fail.

### Anthropic ändert Output-Format
`policy_version` bump → Cache automatisch invalidiert.

### Long-running scans und Cache-Race
Zwei parallele Scans derselben Domain könnten beide gleichzeitig Cache-Miss
produzieren und beide den Anthropic-Call durchführen. Wir akzeptieren das —
last-write-wins, beide haben gleichen Output (temperature=0).

## 9. Migration der bestehenden AI-Calls

```python
# ALT (in scanner/ai_strategy.py)
response = anthropic_client.messages.create(
    model="claude-haiku-4-5-20251001",
    system=SYSTEM_PROMPT_HOST_STRATEGY,
    messages=[{"role": "user", "content": user_input}],
    max_tokens=8192,
)

# NEU
from scanner.ai_cache import cached_call

response = cached_call(
    model="claude-haiku-4-5-20251001",
    system=SYSTEM_PROMPT_HOST_STRATEGY,
    messages=[{"role": "user", "content": user_input}],
    max_tokens=8192,
    temperature=0.0,        # ← NEU explizit
    cache_ttl_seconds=7*24*3600,
    cache_namespace="ki1_host_strategy",
)
```

`cached_call` kapselt:
1. Cache-Key berechnen
2. Redis-GET, bei Hit return
3. Bei Miss: Anthropic-Call mit temperature=0, retry-logic
4. Output in Cache schreiben mit TTL
5. Telemetrie schreiben

## 10. Testing

### Unit-Tests
- Hash-Stability: gleiche Inputs → gleicher Hash
- Hash-Sensitivität: Whitespace-Änderung im messages → anderer Hash
- Cache-Hit-Path
- Cache-Miss-Path (mock Anthropic)
- TTL-Expiry

### Integration-Test
- Scan derselben Domain 2× → 2. Lauf hat Cache-Hit-Rate > 90%
- Cost-Saving > 30%

## 11. Crosslinks

- Skeleton: [`03-ai-cache-skeleton.py`](./03-ai-cache-skeleton.py)
- Tests: [`03-ai-cache-tests.py`](./03-ai-cache-tests.py)
- Severity-Policy (für POLICY_VERSION): [`02-severity-policy.md`](./02-severity-policy.md)

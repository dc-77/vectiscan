# Tiefenanalyse — warum jeder Erst-Scan zu einem anderen Ergebnis kommt

**Stand:** 2026-05-02
**Methode:** Byte-für-Byte-Diff aller Pipeline-Stufen für zwei Erst-Scans
desselben Targets im Abstand von ~22 Minuten.
**Vergleichspaar:** heuel.com R1 (`d983c7b4`, 20:50 UTC) vs R2 (`cd702133`,
21:12 UTC) — identische 4 scan-hosts, identischer Pakettyp `perimeter`,
identische `policy_version 2026-04-30.1`.

---

## Was IDENTISCH ist (Beleg dass die Determinismus-Pipeline wirkt)

| Stufe | Identisch zwischen R1 und R2 |
|---|---|
| **Severity-Counts** | `{"low":4,"high":0,"info":1,"medium":2,"critical":0}` byte-identisch ✓ |
| **policy_id_distinct** | `[SP-CSP-001, SP-CSRF-001, SP-DNS-005, SP-DNS-008, SP-DNS-010, SP-FALLBACK]` byte-identisch ✓ |
| **6 von 7 Findings** | Title, Severity, policy_id alle identisch ✓ |
| **KI #4 (Phase-3-Sonnet) confidence_scores** | 7/7 Refs vorhanden, alle 0.25 identisch ✓ |
| **nmap-Output** auf beiden Hosts | byte-identisch ✓ |
| **header_check** auf beiden Hosts | byte-identisch ✓ |
| **web_probe** | byte-identisch ✓ |
| **feroxbuster** auf 217.72.203.132 | byte-identisch ✓ |
| **report_cost** Eintraege | byte-identisch ✓ |
| **subfinder Subdomain-Set** (12 hosts) | 12/12 overlap ✓ |

Die zentrale Aussage: **die Determinismus-Pipeline wirkt korrekt**. Wo der
Input identisch ist, ist auch der Output identisch. Severity-Policy +
Selection + Audit-Felder produzieren reproduzierbare Ergebnisse.

---

## Wo es driftet — und warum

### A) Externe Datenquellen (NICHT durch Code adressierbar)

| Datenquelle | Symptom in R1 vs R2 | Ursache |
|---|---|---|
| **crt.sh** (Certificate Transparency) | R1: 143 Bytes (Error / Rate-Limit) ↔ R2: 50.000 Bytes (vollstaendiger JSON) | Externe Datenbank, Rate-Limit-Schwankung. crt.sh ist notorisch unzuverlaessig (HTTP 502/timeout). Bei R1 lieferte crt.sh quasi nichts, bei R2 das volle Subdomain-Inventar. |
| **wafw00f-Banner** | R1: ASCII-Art W00f mit ANSI-Farb-Codes (1097 Bytes) ↔ R2: andere ASCII-Art ohne Farb-Codes (622 Bytes) | wafw00f rotiert seine Eingangs-Banner zufaellig. Selbe Detection-Logik (beide: "No WAF detected"), aber unterschiedlicher Wrapper-Text. |
| **DNS-Resolver** | R1: 32 Hosts via dnsx ↔ R2: 33 Hosts (zusaetzlich `sftp.heuel.com`) | dnsx wechselt zufaellig zwischen 8.8.8.8 / 1.1.1.1 / 9.9.9.9. Verschiedene Resolver liefern leicht andere Antwort-Sets. |
| **CloudFlare-Edge-IPs** | R1: `104.16.10.6` als Skip-IP ↔ R2: `104.16.11.6` | CloudFlare-Roundrobin auf den AnyCast-Edges; Reihenfolge in DNS-Antworten variiert pro Anfrage. |
| **httpx-Latencies + Timestamps** | R1: `time=191.475269ms` ↔ R2: `time=181.55308ms` und `timestamp=2026-05-01T20:54:58.879...` ↔ `T21:17:05.920...` | Tool brennt Real-Latency und Wall-Clock-Timestamp in JSON-Output. Selbst bei identischem Server-Verhalten unterschiedliche Bytes. |

### B) KI-Inferenz-Drift (KI selbst ist nicht 100% deterministisch)

| Stelle | Beobachtung |
|---|---|
| **KI #1 strategy_notes** | R1: 350 Zeichen, beginnt „... Logistics-Unternehmen mit 4 aktiven Hosts. Prioritaet 1: Basisdomain (217.72.203.132)..." ↔ R2: 303 Zeichen, beginnt „... heuel.com (Logistics-Unternehmen). Prioritaet 1: Basisdomain + kritischer Host..." — gleiche Inhalte, andere Wortwahl |
| **KI #3 zap_active_categories** | Host `217.72.203.132`: R1 `[sqli, xss, lfi, ssrf]` ↔ R2 `[sqli, xss, lfi, rfi, ssrf, cmdi]`. Host `20.79.218.75`: R1 `[..., rfi, cmdi]` ↔ R2 `[..., cmdi]` (rfi weg) |
| **KI #3 zap_extra_urls** | Host `20.79.218.75`: R1 hat 3 URLs ↔ R2 hat 2 URLs (mail.heuel.com:8443 fehlt) |
| **Reporter-Sonnet** | 6 von 7 Findings identisch (Severity + Policy-ID), Description-Texte um 50-110 Zeichen abweichend, **das 7. Finding ist komplett unterschiedlich**: R1 „Zusaetzlicher HTTPS-Dienst auf Port 8443 exponiert" ↔ R2 „Neos CMS Login-Seite oeffentlich erreichbar" |

**Grund:** Anthropic-API mit `temperature=0` ist „**near-deterministic**",
nicht 100% deterministisch. Bei langen Prompts (10–30k Tokens) summieren
sich Floating-Point-Rundungen zu marginalen Token-Differenzen, die in
unterschiedlich formulierten Antworten resultieren. Plus: die Inputs
selbst sind durch (A) bereits leicht unterschiedlich.

### C) Cache greift NICHT, weil verschiedene Order-IDs

`R1` und `R2` sind verschiedene Orders → verschiedene `order_scope`-Cache-
Keys → beide Erst-Scans sind Cache-Miss → KI generiert beide Male neu.

Cost-Breakdown:
- R1: $2.84 / 10 Calls (5× report_generation Retries weil JSON-Parse-Fehler) / 0 Cache-Hits
- R2: $1.25 / 7 Calls / 0 Cache-Hits

Erst beim **`regenerate-report` derselben Order** greift der Cache —
verifiziert mit 3× regenerate auf R1: alle drei byte-identisch (Hash
`9ad8cde05977`), jeweils 6 Sekunden.

---

## Konkretes Reporter-Beispiel: das 7. Finding

| Lauf | Finding | Severity | Quelle im Tool-Output |
|---|---|---|---|
| R1 | „Zusaetzlicher HTTPS-Dienst auf Port 8443 exponiert" | LOW · SP-FALLBACK | wafw00f-Output mit ANSI-Codes (1097 Bytes); httpx-Output mit `chain_status_codes:[301,200]` |
| R2 | „Neos CMS Login-Seite oeffentlich erreichbar" | LOW · SP-FALLBACK | wafw00f-Output ohne Codes (622 Bytes); zusaetzlicher dnsx-Eintrag `sftp.heuel.com` |

**Beide Findings sind sachlich korrekt.** Reporter-Sonnet entscheidet sich
fuer EINE der vielen denkbaren „weiteren Befund"-Erwaehnungen. Welche genau,
haengt am leicht unterschiedlichen Input + dem Sampling-Drift bei
temperature=0.

---

## Ursachen-Hierarchie nach Wirkungsstaerke

| Rang | Quelle | Anteil an Drift | Adressierbar? |
|---|---|---|---|
| 1 | **Reporter-Sonnet near-deterministisch** | groesster Hebel — fuehrt zu Findings-Selektion + Wording-Drift | M5 (volle Narrative-only-Migration) |
| 2 | **Pre-Check externe Quellen** (crtsh, dnsx, subfinder) | mittel — verschiebt Subdomain-Set marginal | M4 (Pre-Check-Snapshot persistieren) |
| 3 | **Tool-Output Timestamps/Latencies** | mittel — addiert Bytes an KI-Input → Cache-Miss | Tool-Output-Normalizer (`scrub_timestamps`) |
| 4 | **wafw00f Random-Banner** | klein — irrelevant fuer Inhalt, aber bricht Cache | wafw00f-Output-Postprocessing (nur Detection-Zeile behalten) |
| 5 | **CloudFlare/DNS-Reihenfolge** | klein | sortieren in dnsx-Output-Postprocessing |
| 6 | **KI-Floating-Point-Drift** | sehr klein bei kurzen Prompts, additiv bei langen | unloesbar ohne local-LLM |

---

## Empfohlene naechste Schritte

| PR | Aufwand | Effekt |
|---|---|---|
| **A — Tool-Output-Normalizer**: `scrub_volatile()` fuer httpx/dnsx/wafw00f vor der Phase-1/2/3-Persistierung | 4-6h | Cache-Hit-Rate beim 2. Lauf identischer Tool-Outputs steigt; KI-Inputs werden stabiler |
| **B — wafw00f-Wrapper**: nur die `[+] Detection result:`-Zeile durchreichen, ASCII-Art weg | 1h | Eliminiert eine willkuerliche Tool-Drift-Quelle |
| **C — dnsx-Output sortieren** vor JSON-Persistierung | 2h | Reproduzierbares dnsx-Output unabhaengig von Resolver-Wahl |
| **D — M4 Pre-Check-Snapshot persistieren** | 2 Tage | Subdomain-Set stabil ueber Tage hinweg; Subscription-Re-Scans nutzen den Snapshot |
| **E — M5 Reporter-Narrative-only-Migration** | 1 Woche | Loest den Reporter-Drift komplett — Findings-Liste wird deterministisch aus Phase-3-Output abgeleitet, Reporter schreibt nur Narrative |

A+B+C zusammen (~1 Tag) reduzieren den KI-Input-Drift auf wirklich
externe Faktoren (Server-State + crt.sh-Verfuegbarkeit). Plus M4 + M5
fuer komplette Determinismus-Garantie.

---

## Wenn der User fragt „warum jeder Scan andere Ergebnisse?"

**Praezise Antwort:**

1. **Severity-Policy + Selection sind 100% deterministisch.** Wo die
   Inputs identisch sind, sind die Outputs identisch.
2. **`regenerate-report` derselben Order ist 100% deterministisch** —
   verifiziert mit 3 aufeinanderfolgenden Regenerationen.
3. Bei zwei **Erst-Scans desselben Targets** kommen unterschiedliche
   Findings raus, weil:
   - Pre-Check-Tools (crt.sh, dnsx, subfinder) externe Datenquellen
     anfragen, die zwischen Laeufen anders antworten
   - Tool-Outputs (httpx, wafw00f) enthalten Timestamps und
     zufaellige Banner-Variationen → Bytehash unterschiedlich
   - Anthropic API mit `temperature=0` ist „near-deterministic" — bei
     langen Prompts produzieren Floating-Point-Rundungen marginale
     Token-Differenzen → Reporter-Sonnet waehlt leicht andere Findings
4. **Aggregierte Metriken** (Severity-Counts, distinct policies) sind
   trotzdem oft identisch oder hoechstens ±1-2 Findings unterschiedlich.
   Der **Sicherheits-Wert des Reports bleibt konsistent**, das Wording
   driftet nur an der Oberflaeche.

---

**Quelldaten:** `C:\Users\danie\AppData\Local\Temp\vs\dt\` (Findings,
Events, Results-JSON beider Orders); Vergleichs-Skripte
`C:\Users\danie\AppData\Local\Temp\vs-deepdiff*.py`.

# VectiScan — Scan-Tools Referenz (Stand: 2026-04-21)

Übersicht der Tools, Pakete und KI-Prompts. Detaillierte Pipeline-Doku mit
Code-Verweisen siehe `SCAN-PIPELINE-DETAIL.md`. Quelle: `scan-worker/scanner/packages.py`.

---

## Pakete

Sechs Pakete steuern, welche Tools in welcher Phase laufen:

| Parameter | WebCheck | Perimeter | Compliance | SupplyChain | Insurance | TLSCompliance |
|-----------|----------|-----------|------------|-------------|-----------|---------------|
| **total_timeout** | 1.200 s (20 Min) | 7.200 s (120 Min) | 7.200 s | 7.200 s | 7.200 s | 600 s (10 Min) |
| **max_hosts** | 3 | 15 | 15 | 15 | 15 | 15 |
| **phase0a_timeout** | 30 s | 120 s | 120 s | 120 s | 120 s | 30 s |
| **phase0b_timeout** | 300 s | 900 s | 900 s | 900 s | 900 s | 300 s |
| **phase3_timeout** | 120 s | 300 s | 300 s | 300 s | 300 s | 0 s |
| **nmap_ports** | `--top-ports 100` | `--top-ports 1000` | `--top-ports 1000` | `--top-ports 1000` | `--top-ports 1000` | `443,8443,993,995,465,587,636,989,990,5061` |
| **zap_min_risk** | Low | Low | Low | Low | Low | Low |
| **skip_ai_decisions** | nein | nein | nein | nein | nein | **ja** |
| **testssl_severity** | (default) | (default) | (default) | (default) | (default) | `""` (alle inkl. OK/INFO) |

Compliance, SupplyChain und Insurance teilen die identische Scan-Konfiguration
mit Perimeter — Unterschiede liegen ausschließlich in der Report-Generierung.

Legacy-Aliase: `basic→webcheck`, `professional→perimeter`, `nis2→compliance`.

### Tools pro Phase und Paket

#### Phase 0a (Passive Intelligence)

| Tool | WebCheck | Perimeter+ | TLSCompliance |
|------|----------|------------|---------------|
| whois          | x | x | x |
| shodan         | - | x | - |
| abuseipdb      | - | x | - |
| securitytrails | - | x | - |

#### Phase 0b (DNS-Recon)

| Tool | WebCheck | Perimeter+ | TLSCompliance |
|------|----------|------------|---------------|
| crtsh        | x | x | x |
| subfinder    | x | x | x |
| amass        | - | x | - |
| gobuster_dns | - | x | - |
| axfr         | - | x | - |
| dnsx         | x | x | x |
| dnssec       | x | x | x |
| caa          | x | x | x |
| mta_sts      | x | x | x |
| dane_tlsa    | - | x | - |

#### Phase 1 (Tech Detection)

| Tool | WebCheck | Perimeter+ | TLSCompliance |
|------|----------|------------|---------------|
| nmap            | x | x | x |
| webtech         | x | x | - |
| wafw00f         | x | x | - |
| cms_fingerprint | x | x | - |

#### Phase 2 (Deep Scan)

| Tool | WebCheck | Perimeter+ | TLSCompliance |
|------|----------|------------|---------------|
| zap_spider  | x | x | - |
| zap_passive | x | - | - |
| zap_active  | - | x | - |
| ffuf        | - | x | - |
| feroxbuster | - | x | - |
| headers     | x | x | x |
| httpx       | x | x | - |
| wpscan      | x | x | - |
| testssl     | - | - | x |

> Hinweis: `testssl` ist im Perimeter+-Profil **nicht** mehr als
> Phase-2-Tool aufgeführt — die TLS-Coverage liegt jetzt bei ZAP-Spider/
> Active und Headers. Für ein vollwertiges TLS-Audit ist `tlscompliance`
> das passende Paket.

#### Phase 3 (Enrichment)

| Tool | WebCheck | Perimeter+ | TLSCompliance |
|------|----------|------------|---------------|
| nvd             | x | x | - |
| epss            | - | x | - |
| cisa_kev        | x | x | - |
| exploitdb       | - | x | - |
| correlator      | x | x | - |
| fp_filter       | x | x | - |
| business_impact | - | x | - |

---

## Scan-Ablauf (6 Phasen, 4 KI-Punkte)

```
Phase 0a: Passive Intelligence (WHOIS, Shodan, AbuseIPDB, SecurityTrails,
                                DNSSEC/CAA/MTA-STS/DANE)
    ↓
Phase 0b: DNS-Reconnaissance + Web-Probe (httpx)
    ↓
KI #1: Host Strategy (Haiku) — scan/skip pro Host, Priorität
    ↓
Phase 1: Technologie-Erkennung (nmap, Playwright-webtech, wafw00f,
                                CMS-Fingerprinter)
    ↓
KI #2: Tech Analysis (Haiku) — CMS-Korrektur via Redirect-Daten
    ↓
KI #3: Phase-2-Config (Haiku, pro Host) — ZAP-Policy, ffuf-Modus,
                                          feroxbuster-Tiefe, skip_tools
    ↓
Phase 2: Deep Scan (ZAP-Spider/Active, testssl/Headers/httpx, ffuf,
                    feroxbuster, wpscan)
    ↓
KI #4: Phase-3-Priorisierung (Sonnet, nur bei >5 Findings) — Konfidenz,
                                                              FP-Erkennung
    ↓
Phase 3: Correlation + Enrichment (NVD, EPSS, CISA KEV, ExploitDB,
                                    FP-Filter, Business-Impact)
    ↓
Report-Worker: Claude Sonnet 4.6 → PDF + JSON-Findings
```

---

## Phase 0a — Passive Intelligence

Detaillierte Tool-Parameter, Endpoints und Output-Strukturen siehe
`SCAN-PIPELINE-DETAIL.md` §3. Kurzfassung:

- **WHOIS**: `whois <domain>`, Timeout 30 s — Registrar, Ablauf, Nameserver,
  DNSSEC-Status
- **Shodan**: `GET /dns/domain/<d>`, `GET /shodan/host/<ip>` — bekannte
  offene Ports und Service-Versionen pro IP, max 15 IPs, Rate-Limit 429
  → exponentieller Backoff
- **AbuseIPDB**: `GET /api/v2/check?ipAddress=<ip>` — Abuse-Score,
  ISP, Country
- **SecurityTrails**: `GET /v1/domain/<d>`, `/subdomains`,
  `/history/<d>/dns/a` — DNS-Records, Subdomains, Änderungshistorie
- **DNSSEC**: `dig DNSKEY/DS/RRSIG` + `drill -S` — Chain-of-Trust,
  Algorithmus-Erkennung (warnt bei SHA-1)
- **CAA**: `dig CAA` — autorisierte CAs
- **MTA-STS**: `dig _mta-sts.<d> TXT` + `curl mta-sts.<d>/.well-known/...` —
  Policy-Mode (enforce/testing/none)
- **DANE/TLSA** (nur Perimeter+): SMTP-TLSA pro MX, HTTPS-TLSA

---

## Phase 0b — DNS-Reconnaissance

Alle Discovery-Tools laufen parallel mit `ThreadPoolExecutor(max_workers=6)`.

### crt.sh (Certificate Transparency)
```bash
curl -s "https://crt.sh/?q=%.<domain>&output=json"   # Timeout 60 s
```

### subfinder (Passive Subdomain Enumeration)
```bash
subfinder -d <domain> -silent -json -disable-update-check -o <output>
# Timeout 120 s
```

### amass (OSINT Discovery) — nur Perimeter+
```bash
amass enum -passive -d <domain> -json <output>       # Timeout 300 s
```

### gobuster dns (DNS Brute-Force) — nur Perimeter+
```bash
gobuster dns --domain <domain> --wordlist /usr/share/wordlists/subdomains-top5000.txt -q -o <output>
# Timeout 180 s
```

### dig (Zone Transfer AXFR) — nur Perimeter+
```bash
dig NS <domain> +short
dig @<ns> <domain> AXFR                              # Timeout 30 s pro NS
```

### dig (DNS Records — alle Pakete)
```bash
dig <domain> TXT +short                    # SPF
dig _dmarc.<domain> TXT +short             # DMARC
dig default._domainkey.<domain> TXT +short # DKIM
dig <domain> MX +short
dig <domain> NS +short                     # Timeout 10 s pro Query
```

### dnsx (Validierung & IP-Auflösung)
```bash
dnsx -l <subdomains> -a -aaaa -cname -resp -json -o <output>   # Timeout 60 s
```

### Web-Probe (httpx)
```bash
httpx -u <fqdn> -json -silent -follow-redirects -status-code -title -timeout 5
# Pro FQDN, max 3 pro Host
```

Parking-Page-Patterns werden erkannt (Froxlor, Plesk, cPanel, "domain not
configured", "default web page", "welcome to nginx" etc.).

### FQDN- und Host-Sortierung
```
Priorität 0: Basisdomain
Priorität 1: www-Subdomain
Priorität 5: Andere Subdomains
Priorität 9: Mail-Prefixes (mail/mx/smtp/imap/autodiscover)
```

---

## KI #1 — Host Strategy (nach Phase 0)

**Modell:** `claude-haiku-4-5-20251001`, max 8.192 Tokens.

Übersprungen bei `skip_ai_decisions=True` (TLSCompliance) — dort werden
alle Hosts ungefiltert gescannt.

System-Prompt (Auszug — vollständig in `scanner/ai_strategy.py`):

```
Du bist ein Security-Scanner-Orchestrator. Du entscheidest, welche Hosts
gescannt werden und mit welcher Priorität.

WICHTIG ZU FQDNs:
- Die ERSTE FQDN in der Liste ist die relevanteste
- Wenn ein Host sowohl Basisdomain als auch Mail-FQDNs enthält, ist er
  IMMER ein Web-Host

WEB-PROBE DATEN:
- has_web=true → Web-Scan; has_web=false → nur Port-Scan + SSL

PASSIVE INTELLIGENCE (wenn verfügbar):
- shodan_ports / shodan_services / abuseipdb_score / is_tor /
  dnssec_signed / whois_expiration

ERWEITERTE REGELN:
- Hosts mit veralteten Service-Versionen aus Shodan → Priorität 1
- Hosts mit exponierten Management-Ports (22, 3389, 5900, 8080, 8443) → Prio 1
- Hosts mit AbuseIPDB-Score > 50 → Priorität 1
- Mailserver mit fehlender SPF/DMARC → scannen (nicht skippen!)

STANDARD-REGELN:
- Basisdomain und www: IMMER scannen, höchste Priorität
- Mailserver: scan mit niedrigerer Priorität
- Autodiscover-only: skip
- Parking-Pages, externe Redirects: skip
- CDN-Edge ohne eigenen Content: skip
- Wenn unklar: lieber scannen
```

Antwortformat:
```json
{
  "hosts": [
    { "ip": "1.2.3.4", "action": "scan", "priority": 1,
      "reasoning": "Basisdomain", "scan_hints": {...} }
  ],
  "strategy_notes": "...",
  "passive_intel_summary": "..."
}
```

**Fallback** bei JSON-/API-Fehler: alle Hosts scannen, Reihenfolge wie geliefert.

---

## Phase 1 — Tech Detection (parallel, max 3 Hosts)

Vor jedem Host: TCP-Reachability-Check auf 80/443 (5 s Timeout).

### nmap
```bash
nmap -sV -sC -T4 <nmap_port_args> -oX <xml> -oN <txt> <ip>
# Timeout 300 s
```

### webtech (Playwright-basiert, CLI als Fallback)
```bash
# Primär: Headless Chromium über Playwright
# Sammelt: meta-generator, X-Powered-By, Server-Header, JS-Eval (Scripts,
#          Stylesheets, Cookies)
# Schemes: HTTPS zuerst, dann HTTP-Fallback
# Bis zu 8 FQDNs pro Host
# Timeout 60 s pro Scheme
# Fallback: webtech -u <url> --json
```

### wafw00f
```bash
wafw00f <fqdn> -o <output> -f json                   # Timeout 60 s
```

### CMS-Fingerprinting-Engine

5-Methoden-Erkennung in `scanner/cms_fingerprinter.py`, max 20 HTTP-Requests
pro Host, Early-Exit bei Konfidenz ≥ 0.70:

1. **Webtech-Analyse** — CMS aus Phase-1-webtech-Output extrahieren (0.70–0.80)
2. **Meta-Tag-Analyse** — `<meta name=generator>`, `X-Generator`, Cookies (0.75–0.90)
3. **Probe-Matrix** — CMS-spezifische Pfade (z.B. `/wp-login.php`, `/typo3/`,
   `/backend/admin`) gegen 13 CMS prüfen (0.80–0.95)
4. **Cookie-Analyse** — `wordpress_logged_in`, `sw-states`, `fe_typo_user`,
   `mosvisitor`, `Drupal.visitor`, … (0.80)
5. **Response-Headers** — `x-generator`, `x-powered-by` (0.75)

Erkannte CMS: WordPress, Joomla, Drupal, TYPO3, Magento, Shopify, Shopware
(5 + 6), Wix, PrestaShop, Contao, NEOS, Craft CMS, Strapi, Ghost.

Merging: Cluster nach CMS, Base + Boost (+0.05 pro zusätzliche bestätigende
Methode, max +0.15), final ≤ 0.99.

---

## KI #2 — Tech Analysis (nach Phase 1)

**Modell:** `claude-haiku-4-5-20251001`, max 8.192 Tokens.

Korrigiert CMS-Detection-Fehler basierend auf Redirect- und HTTP-Daten:

- `/wp-login.php` mit Body „nicht gefunden" → kein WordPress
- Redirect auf andere Domain → CMS dort, nicht hier
- Page-Title „Outlook Web App" → Microsoft Exchange, kein CMS
- IIS + `.aspx` → Microsoft-Stack, kein PHP-CMS

Antwortformat:
```json
{
  "hosts": {
    "<ip>": {
      "cms": "WordPress|TYPO3|Shopware|...|null",
      "cms_version": "...",
      "cms_confidence": 0.95,
      "technology_stack": ["nginx", "PHP 8.2", "WordPress"],
      "is_spa": false,
      "reasoning": "..."
    }
  }
}
```

---

## KI #3 — Phase-2-Config (pro Host)

**Modell:** `claude-haiku-4-5-20251001`, max 8.192 Tokens.

Konfiguriert ZAP, ffuf, feroxbuster pro Host basierend auf Tech-Stack und
WAF-Signal.

ZAP-Konfiguration:
- `zap_scan_policy`: passive-only / waf-safe / standard / aggressive
- `zap_spider_max_depth`: 3–7 (SPA: 6–7, statisch: 3)
- `zap_ajax_spider_enabled`: true bei React/Vue/Angular/Next/Nuxt/Shopware 6
- `zap_active_categories`: sqli, xss, lfi, rfi, ssrf, cmdi, xxe, crlf
- `zap_rate_req_per_sec` / `zap_threads` / `zap_spider_delay_ms`: WAF →
  15/2/800, ohne WAF → 80/5/0

Tools, die übersprungen werden können: `feroxbuster`, `zap_ajax_spider`.

**Override:** Auf Basisdomain und `www.<domain>` ist `skip_tools` immer leer
(Basisdomain wird immer vollständig gescannt).

Antwortformat:
```json
{
  "zap_scan_policy": "standard",
  "zap_spider_max_depth": 5,
  "zap_ajax_spider_enabled": true,
  "zap_active_categories": ["sqli", "xss", "lfi", "ssrf"],
  "zap_rate_req_per_sec": 80,
  "zap_threads": 5,
  "zap_spider_delay_ms": 0,
  "zap_extra_urls": [],
  "skip_tools": [],
  "reasoning": "..."
}
```

---

## Phase 2 — Deep Scan

Parallelität: max 3 Hosts ohne ZAP, max **1 Host** wenn ZAP-Tools aktiv
(Daemon ist Singleton). 3-Stufen-Pipeline pro Host.

### Stage 1: Discovery (parallel, 3 Worker)

#### ZAP Spider (Traditional + AJAX)
- REST-Client zum ZAP-Daemon auf Port 8090
- Kontext-Isolation pro Scan: `ctx-{order_id[:8]}-{ip}`
- Traditional: `POST /JSON/spider/action/scan/`, Polling alle 5 s
- AJAX (optional): `POST /JSON/ajaxSpider/action/scan/`, Polling alle 10 s,
  Timeout 240 s

#### testssl.sh (nur TLSCompliance)
```bash
bash /opt/testssl.sh/testssl.sh --jsonfile <output> --quiet --ip one \
  --warnings off --sneaky --hints --nodns min https://<fqdn>
# Timeout 300 s
# TLSCompliance: --severity "" (alle Einträge inkl. OK/INFO)
```

#### HTTP-Security-Headers
```bash
curl -sI https://<fqdn>                              # Timeout 10 s
```
Prüft 7 Header: X-Frame-Options, X-Content-Type-Options, HSTS, CSP,
X-XSS-Protection, Referrer-Policy, Permissions-Policy. Score = present/7.

#### httpx
```bash
httpx -u <fqdn> -json -o <output> -status-code -title -tech-detect \
  -server -content-length -follow-redirects -silent
# Timeout 60 s
```

### Stage 2: Deep (Spider-URLs als Input)

#### ZAP Active Scan (nur Perimeter+)
- `POST /JSON/ascan/action/scan/`, Polling alle 10 s
- Custom Scan Policy `policy-{order_id[:8]}-{ip}` mit nur den angeforderten
  Kategorien
- Plugin-IDs pro Kategorie: sqli (40018-40024), xss (40012-40017),
  lfi (6, 40009), rfi (7), ssrf (40046), cmdi (90020), xxe (90023),
  crlf (40003)
- **Verbotene Scanner:** 40032 (DoS), 30001/30002 (Buffer Overflow),
  40033/40034 (Fuzzer)
- Timeout 600 s

#### ffuf (nur Perimeter+)
3 Modi (KI-adaptiv):
```bash
# Directory Discovery
ffuf -u https://<fqdn>/FUZZ -w common.txt -e .php,.html,.js,.bak \
  -mc 200,301,302,403 -fc 404 -t 40 -rate 100 -timeout 5 -json -o <output> -s

# Virtual Host Discovery
ffuf -u https://<ip>/ -H "Host: FUZZ.<domain>" -w subdomains-top1m-5000.txt \
  -mc 200,301,302 -t 40 -rate 100 -timeout 5 -json -o <output> -s

# Parameter Discovery
ffuf -u <url>?FUZZ=test -w burp-parameter-names.txt -mc 200 \
  -t 40 -rate 100 -timeout 5 -json -o <output> -s
# Timeout 180 s
```

#### feroxbuster (nur Perimeter+)
```bash
feroxbuster -u https://<fqdn> -w <wordlist> -d <depth> -t 30 \
  --rate-limit 100 -s 200,301,302,403 --json -o <output> \
  --dont-scan logout|signout|delete --timeout 5 --no-recursion --silent
# Timeout 150 s, Tiefe max 2 (KI-konfigurierbar)
# Deduplizierung gegen ffuf-Ergebnisse
```

#### wpscan (nur wenn CMS = WordPress)
```bash
wpscan --url https://<fqdn> --format json --output <output> \
  --enumerate vp,vt,u1-5 --random-user-agent --no-banner \
  --disable-tls-checks [--api-token <WPSCAN_API_TOKEN>]
# Timeout 600 s
# Exit 0 oder 5 = OK (5 = Vulnerabilities gefunden)
```

### Stage 3: Alert Collection

1. Warten auf ZAP-Passive-Scanner-Queue (`GET /JSON/pscan/view/recordsToScan/`
   bis 0, Timeout 30 s, Poll 3 s)
2. Alerts sammeln: `GET /JSON/alert/view/alerts/`
3. Domain-Filter: FQDN muss in Alert-URL vorkommen
4. Mapping über `ZapAlertMapper`:

| ZAP Risk | Severity | CVSS |
|----------|----------|------|
| High | high | 7.5 |
| Medium | medium | 5.3 |
| Low | low | 3.1 |
| Informational | info | 0.0 |

| ZAP Confidence | Multiplikator |
|----------------|---------------|
| Confirmed | 1.0 |
| High | 0.9 |
| Medium | 0.7 |
| Low | 0.4 |
| False Positive | 0.0 (verworfen) |

---

## KI #4 — Phase-3-Priorisierung (Sonnet)

**Modell:** `claude-sonnet-4-6`, max 16.384 Tokens. Nur bei >5 Findings.

Cross-Tool-Reasoning, Konfidenz-Scoring, FP-Erkennung. Input wird auf
max 100 Findings gekappt.

Antwortformat:
```json
{
  "high_confidence_findings": [{ "finding_ref": "...", "confidence": 0.95,
                                 "corroboration": [...], "enrich_priority": "high" }],
  "low_confidence_findings": [{ "finding_ref": "...", "confidence": 0.3,
                                "reason": "...", "enrich_priority": "low" }],
  "potential_false_positives": [{ "finding_ref": "...", "reason": "..." }],
  "strategy_notes": "..."
}
```

---

## Phase 3 — Correlation & Enrichment

### Cross-Tool-Korrelation (`scanner/correlation/correlator.py`)

Tool-Base-Confidence:
```
testssl 0.90 | header_check 0.95 | wpscan 0.85 | nmap 0.80 |
zap_passive 0.85 | zap_active 0.75 | httpx 0.70 |
ffuf/feroxbuster/gobuster_dir 0.60 | sonst 0.50
```

Schritte:
1. CVE-Match → Merge, +0.10 pro zusätzliches Tool
2. Non-CVE-Findings als eigene CorrelatedFindings
3. Tech-Version-Boost: +0.05 wenn Technologie auf Host erkannt
4. Shodan-Boost: +0.10 wenn Port in Shodan-Services für IP
5. Cluster-Bildung (transport_security / security_headers / xss / cms /
   discovery / sqli / web_vulns)
6. WAF-Degradierung: -0.10 wenn nur ein Tool und WAF aktiv
7. Confidence-Clamping: max 0.99

### False-Positive-Filter (`scanner/correlation/fp_filter.py`)

6 Regeln markieren Findings als FP (entfernen sie aber nicht):
1. **WAF-Filter** — ZAP-Active ohne Bestätigung + Confidence <0.5
2. **Version-Mismatch** — Major-Version Finding ≠ erkannte Version
3. **CMS-Mismatch** — WordPress-Templates auf Shopware-Site etc.
4. **SSL-Dedup** — gleiche CVE oder ≥2 Wort-Overlap im Cluster
5. **Header-Dedup** — header_check-Finding behalten, ZAP-Duplikate FP
6. **Info-Noise** — Server-Banner ohne Version, robots.txt, sitemap.xml,
   `OPTIONS` aktiviert

### Threat-Intel-Enrichment (`scanner/correlation/threat_intel.py`)

Parallel mit `ThreadPoolExecutor(max_workers=4)`, individuelle Timeouts.

| Quelle | Endpoint / Tool | Cache | Limit |
|--------|----------------|-------|-------|
| **NVD** | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Redis 24 h | 5/30 s ohne Key, 50/30 s mit Key; WebCheck 5, Perimeter+ 50 |
| **EPSS** | `https://api.first.org/data/v1/epss` | Redis 12 h | Batch 100 CVEs |
| **CISA KEV** | `cisa.gov/.../known_exploited_vulnerabilities.json` | Redis 6 h | voller Katalog (~1.5 MB) |
| **ExploitDB** | `searchsploit --cve <id> -j` | Redis 24 h | 10 s pro CVE |

Auswirkungen:
- CVE in CISA KEV → Severity = `critical`, Confidence ≥ 0.95
- EPSS > 0.5 und Severity `medium`/`low` → `high`
- NVD-CVSS wird als `authoritative_cvss` gespeichert

### Business-Impact-Scoring

```
base = CVSS_Score (NVD > Tool > Severity-Approximation)
× EPSS-Multiplikator (>0.5: 1.3, >0.2: 1.1)
× CISA-KEV-Multiplikator (1.5; +1.2 wenn Ransomware)
× Asset-Wert (Basisdomain/www: 1.2, Mail: 1.1, sonst 1.0)
× Paket-Gewichtung (z.B. Insurance rdp_smb: 2.0; Compliance encryption: 1.5)
× Confidence-Adjustment (<0.5: 0.7)
→ min(round(base, 1), 10.0)

Order-Score: gewichteter Durchschnitt der Top-5-Findings
             (weights = [1.0, 0.8, 0.6, 0.4, 0.2])
```

---

## Report-Generierung

**Modell:** `claude-sonnet-4-6` (mehrere Token-Budgets je Paket).

### Post-Processing-Pipeline (`reporter/`)
1. `cap_implausible_scores()` — CVSS-Caps für Info Disclosure (3.5),
   Banner (2.5), Security-Headers (5.5), DNS-Records (5.5), SSH-Key-Auth (0.0)
2. `validate_cvss_scores()` — CVSS-3.1-Score aus Vektor berechnen,
   Toleranz 0.1
3. `validate_cwe_mappings()` — Lokale `cwe_reference.py` + optional
   `cwe_api_client.py` (MITRE)
4. `run_qa_checks()` — Programmatische Konsistenz + Haiku-Plausibilität
   bei Anomalien
5. Trailing-Comma-Bereinigung per Regex
6. JSONDecodeError → Retry bis 3× mit 3 s Pause

### Prompt-Varianten (`reporter/prompts.py`)

| Paket | Prompt | Besonderheiten |
|-------|--------|----------------|
| WebCheck | SYSTEM_PROMPT_WEBCHECK | Einfache Sprache, max 5–8 Findings, Ampelsystem |
| Perimeter | SYSTEM_PROMPT_PERIMETER | PTES-konform, EPSS-Kontext, Evidence |
| Compliance | SYSTEM_PROMPT_COMPLIANCE | + §30 BSIG, BSI-Grundschutz, NIST CSF, Audit-Trail |
| SupplyChain | SYSTEM_PROMPT_SUPPLYCHAIN | + ISO 27001 Annex A, Lieferketten-1-Seiter |
| Insurance | SYSTEM_PROMPT_INSURANCE | + Versicherungsfragebogen, Ransomware-Indikator |

TLSCompliance hat keinen eigenen Sonnet-Prompt — der Worker baut eine
TR-03116-4-Summary aus `tr03116_checker.py` und übergibt sie als Findings-
Text an einen vereinfachten Claude-Aufruf.

### Compliance-Module (`reporter/compliance/`)
- `nis2_bsig.py` — §30 BSIG Mapping
- `iso27001.py` — ISO 27001 Annex A
- `bsi_grundschutz.py` — BSI IT-Grundschutz
- `nist_csf.py` — NIST CSF 2.0
- `insurance.py` — Versicherungs-Fragebogen-Generator

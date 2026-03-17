# VectiScan — Scan-Tools Referenz

## Scan-Ablauf (Phase-First Architektur)

```
Phase 0: DNS-Reconnaissance (alle Hosts entdecken)
    ↓
Web-Probe: Schneller HTTP-Check pro Host (httpx)
    ↓
KI: Host-Strategie (Haiku entscheidet welche Hosts gescannt werden)
    ↓
Phase 1: Technologie-Erkennung (ALLE Hosts, nacheinander)
    ↓
KI: Phase-2-Konfiguration (Haiku konfiguriert Tools pro Host)
    ↓
Phase 2: Deep Scan (ALLE Hosts, nacheinander)
    ↓
Report: Claude Sonnet analysiert Rohdaten → PDF
```

## Paket-Konfiguration

| Parameter | Basic | Professional | NIS2 |
|-----------|-------|-------------|------|
| Phase 0 Tools | crtsh, subfinder, dnsx | + amass, gobuster_dns, axfr | = Pro |
| Phase 0 Timeout | 5 Min | 10 Min | 10 Min |
| Max Hosts | 5 | 10 | 10 |
| nmap Ports | Top 100 | Top 1000 | Top 1000 |
| Phase 2 Tools | testssl, headers, gowitness, httpx, wpscan | + nikto, nuclei, gobuster_dir, katana | = Pro |
| Nuclei Severity | high, critical | low, medium, high, critical | = Pro |
| Nuclei Timeout | 10 Min | 25 Min | 25 Min |
| Gesamt-Timeout | 15 Min | 120 Min | 120 Min |

---

## Phase 0 — DNS-Reconnaissance

### crt.sh (Certificate Transparency)
```bash
curl -s "https://crt.sh/?q=%.<domain>&output=json" -o <output>
# Timeout: 60s
```

### subfinder (Passive Subdomain Enumeration)
```bash
subfinder -d <domain> -silent -json -disable-update-check -o <output>
# Timeout: 120s
```

### amass (OSINT Discovery) — nur Pro/NIS2
```bash
amass enum -passive -d <domain> -json <output>
# Timeout: 300s (5 Min)
```

### gobuster dns (DNS Brute-Force) — nur Pro/NIS2
```bash
gobuster dns --domain <domain> --wordlist /usr/share/wordlists/subdomains-top5000.txt -q -o <output>
# Timeout: 180s (3 Min)
```

### dig (Zone Transfer AXFR) — nur Pro/NIS2
```bash
# Schritt 1: Nameserver ermitteln
dig NS <domain> +short

# Schritt 2: Zone Transfer pro Nameserver
dig @<ns> <domain> AXFR
# Timeout: 30s pro NS
```

### dig (DNS Records)
```bash
dig <domain> TXT +short                    # SPF
dig _dmarc.<domain> TXT +short             # DMARC
dig default._domainkey.<domain> TXT +short  # DKIM
dig <domain> MX +short                      # MX
dig <domain> NS +short                      # NS
# Timeout: 10s pro Query
```

### dnsx (Validierung & IP-Auflösung)
```bash
dnsx -l <subdomain-liste> -a -aaaa -cname -resp -json -o <output>
# Timeout: 60s
```

### Web-Probe (httpx — schneller HTTP-Check)
```bash
httpx -u <fqdn> -json -silent -follow-redirects -status-code -title -timeout 5
# Pro FQDN, max 3 pro Host
# Timeout: 10s
# Ergebnis: has_web, status_code, final_url, title → in host_inventory gespeichert
```

### FQDN-Sortierung (nach Relevanz)
```
Priorität 0: Basisdomain (z.B. finescience.com)
Priorität 1: www-Subdomain (www.finescience.com)
Priorität 5: Andere Subdomains (goldenticket.finescience.com)
Priorität 9: Mail-Prefixes (email.*, mail.*, mx.*, smtp.*, imap.*, autodiscover.*)
```
→ Die FQDN mit der niedrigsten Prioritätszahl wird als `primary_fqdn` für Phase 1/2 verwendet.
→ Wenn web_probe eine antwortende FQDN findet, wird diese bevorzugt.

---

## KI-Entscheidung: Host-Strategie (nach Phase 0)

**Modell:** Claude Haiku 4.5 (`claude-haiku-4-5-20251001`), max 2048 Tokens

**System-Prompt:**
```
Du bist ein Security-Scanner-Orchestrator. Du entscheidest, welche Hosts gescannt werden.

WICHTIG ZU FQDNs:
- Jeder Host hat eine Liste von FQDNs die auf dieselbe IP zeigen
- Die ERSTE FQDN in der Liste ist die relevanteste (Basisdomain vor www vor Subdomains)
- Wenn ein Host sowohl die Basisdomain als auch Mail-FQDNs enthält, ist er IMMER ein Web-Host
- Beurteile den Host nach seiner wichtigsten FQDN, nicht nach Mail-Subdomains

WEB-PROBE DATEN:
- Jeder Host kann ein "web_probe" Feld haben mit has_web, status, final_url, title
- has_web=true: HTTP-Content vorhanden → Web-Scan (alle Tools)
- has_web=false: Kein HTTP-Content → Port-Scan (nmap + testssl reichen)
- final_url zeigt wohin Redirects führen → die relevante Scan-URL

REGELN:
- Basisdomain und www-Subdomain: IMMER scannen (action: "scan"), höchste Priorität
- Webserver mit interaktivem Content (Apps, APIs, CMS, Shops): scan (hohe Priorität)
- Mailserver (MX, SMTP, IMAP): scan mit NIEDRIGERER Priorität — NICHT skippen!
- Autodiscover-Hosts (nur Exchange/Outlook-Konfiguration): skip (einzige Ausnahme)
- Parking-Pages, Redirect auf externe Domain: skip
- CDN-Edge-Nodes (nur CDN-IP, kein eigener Content): skip
- Wenn unklar: lieber scannen als überspringen
```

**Erwartetes Antwort-Format:**
```json
{
  "hosts": [
    { "ip": "1.2.3.4", "action": "scan", "priority": 1, "reasoning": "Basisdomain, muss immer gescannt werden." },
    { "ip": "5.6.7.8", "action": "skip", "priority": null, "reasoning": "Autodiscover-Host, keine Web-Inhalte." }
  ],
  "strategy_notes": "3 Hosts scannen, 1 übersprungen."
}
```

---

## Phase 1 — Technologie-Erkennung (pro Host)

### nmap (Service Version Detection)
```bash
nmap -sV -sC -T4 <nmap_ports> -oX <xml> -oN <txt> <ip>
# Basic: --top-ports 100
# Pro/NIS2: --top-ports 1000
# Timeout: 300s (5 Min)
```

### webtech (Technologie-Stack-Erkennung)
```bash
webtech -u <scheme>://<fqdn> --json
# Probiert HTTPS zuerst, bei Fehler HTTP
# Probt bis zu 3 non-Mail FQDNs pro Host (Multi-FQDN-Probing)
# Timeout: 60s pro Versuch
```

### wafw00f (WAF/IDS-Erkennung)
```bash
wafw00f <fqdn> -o <output> -f json
# Timeout: 60s
```

### CMS-Fallback-Erkennung (wenn webtech kein CMS findet)
```
HEAD-Requests mit User-Agent "VectiScan/1.0", Timeout 5s:
  https://<fqdn>/wp-login.php      → WordPress
  https://<fqdn>/wp-admin/         → WordPress
  http://<fqdn>/wp-login.php       → WordPress
  https://<fqdn>/backend/admin     → Shopware
  https://<fqdn>/admin/login       → Shopware
HTTP 200/301/302/307 = CMS erkannt
```

**Erkannte CMS:**
wordpress, joomla, drupal, typo3, magento, shopify, shopware, wix, prestashop, contao, neos, craft, strapi, ghost

---

## KI-Entscheidung: Phase-2-Konfiguration (nach Phase 1, pro Host)

**Modell:** Claude Haiku 4.5, max 2048 Tokens

**System-Prompt:**
```
Du bist ein Security-Scanner-Orchestrator. Du konfigurierst Phase-2-Scan-Tools
optimal basierend auf dem erkannten Tech-Stack eines Hosts.

VERFÜGBARE NUCLEI-TAGS (wichtigste):
wordpress, apache, nginx, iis, php, java, python, nodejs, rails, laravel, django,
spring, tomcat, jboss, weblogic, coldfusion, drupal, joomla, magento, shopify,
shopware, prestashop, struts, exposure, network, ssl, dns, cve, default-login,
misconfig, tech, token, sqli, xss, lfi, rfi, ssrf, redirect, upload

NIKTO-TUNING-KATEGORIEN:
1=Interesting File, 2=Misconfiguration, 3=Information Disclosure,
4=Injection (XSS/Script), 5=Remote File Retrieval, 6=Denial of Service,
7=Remote File Retrieval (Server Wide), 8=Command Execution, 9=SQL Injection,
0=File Upload

GOBUSTER-WORDLISTS:
- "common" — Generische Pfade (Standard)
- "wordpress" — WordPress-spezifische Pfade
- "api" — API-Endpunkte (swagger, graphql, /api/v1, actuator)
- "cms" — CMS-Admin-Panels und typische CMS-Pfade

WICHTIG FÜR skip_tools:
- Für Basisdomain und www: skip_tools MUSS IMMER leer sein []
- Für Hosts mit Web-Content: skip_tools MUSS leer sein []
- Im Zweifel: leer lassen

WICHTIG FÜR NUCLEI-TAGS (Performance):
- NIEMALS den Tag "cve" allein — 3000+ Templates, Timeout garantiert
- Max 5-7 fokussierte Tags
- "exposure" und "misconfig" sind effizient (wenige Templates, hoher Ertrag)
```

**Erwartetes Antwort-Format:**
```json
{
  "nuclei_tags": ["apache", "exposure", "misconfig", "ssl", "default-login"],
  "nuclei_exclude_tags": ["dos", "fuzz"],
  "nikto_tuning": "1,2,3,4",
  "gobuster_wordlist": "common",
  "skip_tools": [],
  "reasoning": "Apache-Server ohne CMS. Fokus auf Misconfiguration und Exposure."
}
```

**Basisdomain-Schutz:** Für die Basisdomain wird `skip_tools` immer auf `[]` erzwungen, unabhängig von der KI-Entscheidung.

---

## Phase 2 — Deep Scan (pro Host)

### testssl.sh (SSL/TLS-Analyse) — nur wenn has_ssl=true
```bash
bash /opt/testssl.sh/testssl.sh --jsonfile <output> --quiet --ip one --warnings off https://<fqdn>
# Timeout: 300s (5 Min)
# Exit 0 oder 1 = OK (1 = Findings gefunden)
```

### nikto (Web-Server-Scanner) — nur Pro/NIS2
```bash
perl /opt/nikto/program/nikto.pl -h <fqdn> -Format json -output <output> -Tuning <tuning>
# Tuning: AI-adaptiv oder Default "1234567890"
# Timeout: 600s (10 Min)
# Exit 0 oder 1 = OK
```

### nuclei (Vulnerability Scanner) — nur Pro/NIS2
```bash
nuclei -u <fqdn> -severity <severity> -jsonl -o <output> \
  -timeout 5 -retries 1 -no-interactsh -c 25 -rl 150 \
  [-tags <ai_tags>] [-exclude-tags <ai_exclude>]
# Severity: Basic="high,critical" Pro/NIS2="low,medium,high,critical"
# Timeout: Basic=600s Pro/NIS2=1500s
# Exit -1 = Timeout → Teilergebnisse werden trotzdem gelesen (JSONL inkrementell)
```

### gobuster dir (Directory Brute-Force) — nur Pro/NIS2
```bash
gobuster dir -u https://<fqdn> -w <wordlist> -o <output> -q
# Wordlist: AI-adaptiv (common/wordpress/api/cms)
# Timeout: 120s (2 Min)
```

### gowitness (Screenshot)
```bash
gowitness scan single -u https://<fqdn> --screenshot-path <dir>/ \
  --chrome-path /usr/bin/chromium --disable-logging
# Chrome-Flags via CHROMIUM_FLAGS="--no-sandbox --disable-gpu --disable-dev-shm-usage"
# Timeout: 30s
```

### header_check (Security Headers)
```bash
curl -sI https://<fqdn>
# Prüft: x-frame-options, x-content-type-options, strict-transport-security,
#   content-security-policy, x-xss-protection, referrer-policy, permissions-policy
# Score: <gefunden>/<7>
# Timeout: 10s
```

### httpx (HTTP-Probing & Tech Detection)
```bash
httpx -u <fqdn> -json -o <output> -status-code -title -tech-detect \
  -server -content-length -follow-redirects -silent
# Timeout: 60s
```

### katana (Web Crawler) — nur Pro/NIS2
```bash
katana -u https://<fqdn> -o <output> -depth 3 -jsluice -known-files all -silent
# Timeout: 300s (5 Min)
```

### wpscan (WordPress Scanner) — nur wenn CMS = WordPress erkannt
```bash
wpscan --url https://<fqdn> --format json --output <output> \
  --enumerate vp,vt,u1-5 --random-user-agent --no-banner \
  --ignore-main-redirect --disable-tls-checks \
  [--api-token <WPSCAN_API_TOKEN>]
# vp=vulnerable plugins, vt=vulnerable themes, u1-5=users
# Timeout: 600s (10 Min)
# Exit 0 oder 5 = OK (5 = Vulnerabilities gefunden)
```

---

## Report-Generierung

**Modell:** Claude Sonnet 4 (`claude-sonnet-4-20250514`)

### Post-Processing Pipeline
1. **`cap_implausible_scores()`** — Deckelt CVSS bei Info Disclosure (max 3.5), Banner (max 2.5), Security Headers (max 5.5)
2. **`validate_cvss_scores()`** — Berechnet CVSS 3.1 Score aus Vektor, korrigiert Divergenzen > 0.1
3. **`validate_cwe_mappings()`** — Prüft CWE-Format (CWE-\d{1,4}), warnt bei unbekannten CWEs

### Trailing-Comma Fix
Claude-JSON-Responses mit Trailing Commas vor `}` oder `]` werden per Regex bereinigt.

### JSONDecodeError Retry
Bei JSON-Parse-Fehler wird der Claude-Call bis zu 3x wiederholt (mit 3s Pause).

# amass v5 — Race-Condition-Diagnose und Workaround

**Stand:** 2026-05-03
**Issue:** amass v5.0.1 enum exit 0 mit 0 Bytes Output, subs liefert "No names"
**Live-Beleg:** Order `384fa1b1-7672-4d19-ba78-ad9ca7f65d13`
- `amass enum`: exit 0, dur 11.3s, raw_output 0 bytes
- `amass subs`: exit 0, dur 38ms, "No names were discovered"

---

## v5-Architektur (Code-Audit aus owasp-amass/amass v5.0.1)

amass v5 hat sich von v4 grundlegend veraendert:

1. **Engine als HTTP-Server**: `amass enum` checkt ob ein Engine-Prozess
   auf `http://127.0.0.1:4000/graphql` lauscht (`engineIsRunning()` in
   `cmd/amass/process.go`). Wenn nicht, wird via `nohup amass engine`
   ein neuer Prozess gestartet (`startEngine()`).
2. **Asset-DB als Persistierung**: Die Engine schreibt gefundene Assets
   in eine Graph-DB unter `cfg.Dir` (vom CLI mit `-dir <pfad>` uebergeben).
3. **enum sendet Discovery-Job, polled, beendet Session**:
   `cmd/amass/internal/enum/cli.go` ruft `client.CreateSession(cfg)`,
   pollt alle 2s `client.SessionStats(token)` und prueft auf
   `WorkItemsCompleted == WorkItemsTotal`. **5 aufeinanderfolgende
   erfolgreiche Polls** (entspricht 10s) gelten als "fertig" → Session
   wird via `client.TerminateSession(token)` geschlossen → enum exit 0.
4. **subs liest direkt aus DB**: `amass subs -dir <db> -names` greift
   auf die Graph-DB zu, filtert nach `oamdns`-Asset-Typen, druckt FQDNs
   auf stdout.

---

## Root Cause der "0 Bytes"-Beobachtung

**Race-Condition im enum-Polling:**

```
T=0s    enum startet
T=0s    engineIsRunning() = false
T=0s    startEngine() → "nohup amass engine" im Hintergrund
T=0-3s  waitForEngineResponse() polled bis Engine antwortet
T=3s    client.CreateSession(cfg) → token
T=5s    1. SessionStats-Poll: WorkItemsCompleted=0 WorkItemsTotal=0 → finished=1
T=7s    2. Poll: 0==0 → finished=2
T=9s    3. Poll: 0==0 → finished=3
T=11s   4. Poll: 0==0 → finished=4
T=13s   5. Poll: 0==0 → finished=5 → close(done) → enum exit 0
```

**Warum WorkItemsTotal=0?**

Die meisten v5-Datasources brauchen API-Keys (per Default ist `~/.config/amass/datasources.yaml` praktisch leer). Ohne aktive Sources entstehen keine WorkItems. Der "fertig"-Check triggert auf der initialen `0==0`-Bedingung, **bevor** irgendein Source ueberhaupt Zeit hatte zu antworten.

**Beweis:** Die Live-Dauer 11.3s passt exakt: ~3s Engine-Start + 5×2s Polls = 13s, ggf. minus initialer Warmup → 11.3s.

---

## Workaround: `-brute`-Flag

Mit `-brute` aktiviert amass DNS-Brute-Force aus seiner internen
Wordlist (~5000-10000 Eintraege). Das erzeugt **garantiert WorkItems
ueber die initiale Poll-Phase hinaus**:

```bash
amass enum -d <domain> -dir <db> -brute -timeout 4 -nocolor -o <log>
```

Effekt: `WorkItemsTotal` waechst sofort auf 5000+, der "fertig"-Check
kann nicht mehr triggern bevor echte Discovery passiert.

Implementiert in `scan-worker/scanner/phase0.py:run_amass()`.

---

## Alternativen (verworfen)

| Option | Begruendung |
|---|---|
| Datasources-YAML mit aktiven Free-Sources | Wartungsaufwand pro Source; Free-Tier-Limits sind sehr eng (z.B. crt.sh API), nutzen unsere bestehenden subfinder/crtsh/certspotter ohnehin |
| amass v4 Downgrade | EOL, keine Bugfixes, alte Source-Liste |
| Engine als persistenter Container-Service | Zusaetzliche Komplexitaet, Port-4000-Konflikt-Risiko, Lifecycle-Management |
| amass komplett rauswerfen | Funktional zu 95% redundant zu subfinder+crtsh+certspotter+securitytrails — aber User wollte Backup |

---

## Funktional: Was bringt amass UNS noch zusaetzlich?

Unser Discovery-Stack hat schon:

| Source | Tool | Coverage |
|---|---|---|
| Cert Transparency | crtsh, certspotter, subfinder, securitytrails | 4 Quellen, vollstaendig |
| Passive DNS | securitytrails, subfinder | 2 Quellen |
| 30+ Source-APIs | subfinder mit -all -recursive | Inkl. chaos, alienvault, anubis, bevigil, binaryedge, bufferover, c99, censys, certspotter, crtsh, fofa, fullhunt, github, hackertarget, hunter, intelx, leakix, netlas, passivetotal, quake, rapiddns, shodan, urlscan, virustotal, waybackarchive, zoomeye |
| DNS-Brute-Force | gobuster_dns mit subdomains-top5000 | 5000 Eintraege |
| Zone-Transfer | axfr in collect_dns_records | falls erlaubt |

**amass-Mehrwert mit `-brute`-Workaround:**
- Eigene Permutations (Mutationen wie `api-v2.example.com` aus `api.example.com`) → marginaler Mehrwert
- Zweite DNS-Brute-Force-Wordlist parallel zu gobuster_dns → minimal
- Marginal andere Datasource-Reihenfolge als subfinder → fast identisch

**Realistischer Mehrwert: 1-3 zusaetzliche Subdomains pro Scan im Schnitt.**
Das rechtfertigt amass im Stack als Backup, aber nicht als kritische Komponente.

---

## Verification

Nach Pipeline-Deploy mit `-brute`-Workaround:
1. Frischer Scan auf bekannter Test-Domain (heuel.com / securess.de)
2. Snapshot vorher invalidieren via `POST /api/admin/targets/<id>/restart-precheck`
3. Im scan_results pruefen:
   - `amass` exit_code 0, dur > 30s, raw_output > 0 bytes
   - `amass_subs` exit_code 0, raw_output enthaelt FQDN-Liste
4. Vergleich `amass`-Subdomains vs `subfinder`-Subdomains im Tool-Trace
5. Falls amass nach diesem Workaround weiterhin "No names" liefert →
   amass dauerhaft entfernen.

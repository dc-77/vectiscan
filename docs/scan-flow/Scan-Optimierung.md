# Scan-Optimierung — Perimeter-Pipeline (Audit)

**Generiert:** 2026-05-06
**Git-Commit:** `ea8e1a5` (`fix(scan-drift): Snapshot als Seed + Tech-Profile-Anreicherung + finding_type-Persistenz`)
**Quelle der Wahrheit:** Code im o. g. Commit. Baseline `docs/scan-flow/perimeter-single-tld.md` ausschließlich als Reiseroute / Live-Mess-Quelle (§6).

**Explizit ignoriert:**
- `docs/MULTI-TARGET-PLAN.md`
- `docs/PERFORMANCE-PARALLELIZATION-PLAN.md`
- alle weiteren Plan-, Spec-, Design-Dokumente (Soll-Zustände)
- Landingpage

**Live-API:** Test-Umgebung `scan-api.vectigal.tech` darf für Coverage-/Übergabe-Stichproben sparsam konsultiert werden. Secrets, Order-IDs, Customer-Daten, PDF-URLs erscheinen NICHT in dieser Datei — nur strukturelle Beobachtungen.

---

## Fortschritt

- Pre-Check: completed (5 Findings, alle accepted)
- Phase 0a: completed (6 Findings, alle accepted)
- Phase 0b: completed (8 Findings, alle accepted)
- KI #1 — Host-Strategy: completed (2 Findings, alle accepted)
- Phase 1 — Tech-Detection: completed (3 Findings, alle accepted)
- KI #2 / KI #3: completed (3 Findings, alle accepted)
- Phase 2 — Deep-Scan: completed (2 Findings accepted, 2 deferred → Anhang A)
- Phase 3 + KI #4: completed (2 Findings, alle accepted)
- tar.gz / MinIO + Reporter-Parser: completed (1 Finding, accepted)
- KI #5 — Reporter: skipped (gut konfiguriert, kein Optimierungs-Finding)
- Deterministische Reporter-Pipeline: completed (7 Findings, alle accepted)
- Übergreifende Themen: completed (3 Findings, alle accepted)

**Total: 42 Findings accepted, 2 deferred (Anhang A), 0 abgelehnt.**

---

## 2. Executive Summary

Top-10 angenommene Findings nach Priorität (Severity-/Cost-/Determinismus-Hebel kombiniert):

1. **F-PH2-002** (Phase 2, Coverage, hoch) — nuclei + katana implementieren als Stage 3 (nikto + dalfox deferred). Massive CVE-Detection-Coverage-Erweiterung; POLICY_VERSION-Bump erforderlich.
2. **F-RPT-001** (Reporter, Coverage, hoch) — KNOWN_VULN_BUILDS Initial-Liste +20 manuelle 2022-2026-Entries + OSV-Sync-Skript + Range-Matcher. EOL-Confidence-kritisch, Severity-Hebel bei Banner-Match.
3. **F-RPT-002** (Reporter, Übergabe, hoch) — `selection.consolidate` Hash um `title_vars` (port/tech/version/plugin/library/directive/selector) erweitern. Verhindert falsche Konsolidierung von EOL/DB/Plugin/Library-Findings auf Multi-Tech-Hosts.
4. **F-XS-001** (Übergreifend, Übergabe-Cache, hoch) — Output-Normalizer für testssl, ffuf, katana, feroxbuster ergänzen. Cache-Hit-Quote TLSCompliance ~80%+, Perimeter ~50%, Reporter-Cache wirksam.
5. **F-RPT-007** (Reporter, Übergabe, mittel-hoch) — `eol_detector.merge_into_claude_findings` Dedup mit Host-Resolution (FQDN↔IP) + Version-Recovery aus Title-Regex. Verhindert Doppel-EOL-Findings bei FQDN-basierten Scans.
6. **F-PH3-001** (Phase 3, Parallelität, mittel-hoch) — NVD-Lookup parallel + max_lookups 50→100 (webcheck 5→10). Wichtig nach F-PH2-002, Cache dämpft Re-Scans.
7. **F-PH1-003** (Phase 1, Übergabe, mittel-hoch) — Screenshots full_page + alle primary VHosts ins PDF + Label pro FQDN; Tool-Naming-Drift `gowitness`→`playwright_screenshot`. Customer-Confidence "alles gesehen".
8. **F-P0A-002** (Phase 0a, Coverage, mittel-hoch) — Neues `mail_security_parsers.py` zentral + TLS-RPT + BIMI + DMARC-Policy + NSEC3-Iterations. Severity-Hebel DMARC, Compliance/Insurance-Marker.
9. **F-P0B-001** (Phase 0b, Coverage+Parallelität, mittel-hoch) — DKIM-Probe parallelisieren (max_workers=10) + ~19 fehlende Selektoren (DE-Provider + SES/Postmark/Mailgun/Mailjet/Brevo/Zoho). False-positive "DKIM missing"-Klasse bei DE-Customers fix.
10. **F-P0B-006** (Phase 0b, Coverage, mittel-hoch) — Subdomain-Takeover-Liste-Sync via EdOverflow's `can-i-take-over-xyz` (~70 Services); GitLab-Job `takeover-list-sync`. CRITICAL-Severity bei echten Takeovers.

**Quick-Win-Cluster (XS-Aufwand, mittel-Impact):** F-PRE-002 (DNS-Resolution parallel), F-PRE-004 (nmap-Light Performance-Flags), F-PRE-005 (nmap-Light 57-Port-Liste), F-KI4-001 (KI #4 Severity-Pre-Sort), F-PH1-002 (wafw00f parallel), F-KI3-001 (KI #3 ThreadPool), F-XS-002 (KI #2/#3 content_hash), F-RPT-004 (AI-Fallback parallel).

**Strukturelle Voraussetzungen:** F-XS-003 (Sync-Helper-Lib + GitLab-Anchor) als Pilot-Refactor vor Rollout der Sync-Skripte aus F-PRE-003, F-P0B-006, F-RPT-001.

---

## 3. Phasen-weise angenommene Findings

### 3.1 Pre-Check

#### 3.1.1 Tool-Parameter

##### F-PRE-004 — `nmap_light` Pre-Check: fehlende Performance-Flags

| Feld | Inhalt |
|---|---|
| ID | F-PRE-004 |
| Phase / Stage | Pre-Check (IPv4-Pfad, CIDR-Pfad) |
| Komponente | `nmap_utils.run_top_ports` |
| Code-Stelle | `scan-worker/scanner/common/nmap_utils.py:10-30` |
| Dimension | Tool-Parameter |
| Beobachtung | nmap-Aufruf `nmap -T4 -Pn --top-ports 10 --min-rate 200 -oX -` ohne `--max-retries` (Default 10), ohne `--host-timeout`, ohne `-n` (DNS-Reverse läuft doppelt — Pre-Check macht es separat), ohne `--open`. Worst-Case-Eskalation im CIDR-Pfad mit DROP-Firewall: nmap läuft bis Wrapper-Timeout (180s). |
| Live-Messung | Kein `duration_ms` in `scan_results` (Library-Call). Strukturelle Worst-Case-Analyse. |
| Entscheidung | **Option A**: vier Flags ergänzen.<br>`--max-retries 2` (statt Default 10) — Standard-Empfehlung nmap-Doku für Internet-Targets mit `-T4`.<br>`--host-timeout 30s` — kappt einzelne hängende IPs.<br>`-n` — Pre-Check macht reverse-DNS bereits separat via dnspython (deterministischer Resolver-Pool).<br>`--open` — XML-Reduktion (kostenneutral). |
| Quelle | nmap Performance-Doku https://nmap.org/book/performance.html (2026-05-06); nmap man-page (`--max-retries` Default 10, `-n` skip-DNS); Code-Analyse `common/nmap_utils.py:10-30`, `precheck/runner.py:138-170, 173-210`. |
| Risiko | FP-Rate vernachlässigbar (Liveness-Check, nicht Vollständigkeits-Scan); Determinismus verbessert (kein DNS-Drift im XML); kein Cache betroffen. |
| Priorität | mittel — direkter Worst-Case-Cap im CIDR-Pfad, trivialer Code-Change. |

#### 3.1.2 Übergaben
_(noch keine angenommenen Findings)_

#### 3.1.3 Parallelität

##### F-PRE-002 — DNS-Resolution sequenziell (5×5s seriell)

| Feld | Inhalt |
|---|---|
| ID | F-PRE-002 |
| Phase / Stage | Pre-Check (FQDN-Pfad) |
| Komponente | `dns_utils.resolve_all` |
| Code-Stelle | `scan-worker/scanner/common/dns_utils.py:122-130` |
| Dimension | Parallelität |
| Beobachtung | `resolve_all` ruft `resolve_a/aaaa/cname/mx/ns` sequenziell auf, jede mit `timeout=5s` + `lifetime=5s`. Worst-Case bei DNS-Stillstand auf einer Record-Sorte: 5×5s = 25s pro FQDN. Healthy: 150–300 ms (cached recursors). |
| Live-Messung | Pre-Check-Tools haben kein `duration_ms` in `scan_results` (Library-Calls). Worst-Case-Pfad nur theoretisch nachgewiesen. |
| Entscheidung | **Option A**: `resolve_all` via `concurrent.futures.ThreadPoolExecutor(max_workers=5)` parallelisieren — fünf Record-Typen gleichzeitig, Worst-Case fällt von 25s auf 5s. Jeder Sub-Call instanziiert eigenen `dns.resolver.Resolver` (siehe `_resolver()`-Helper Z. 39-44) → kein Thread-Safety-Problem. Output bleibt dict mit deterministischer Schlüssel-Reihenfolge. |
| Quelle | dnspython Doku https://dnspython.readthedocs.io/en/stable/resolver-class.html — Abgerufen 2026-05-06. Code-Analyse `dns_utils.py:39-44, 122-130`. |
| Risiko | keiner. Kein Cache, keine Determinismus-Auswirkung, keine FP-Rate-Veränderung. |
| Priorität | niedrig — Pre-Check ist sub-Minute typical, Optimierung greift nur bei langsamen Authoritative-NS. Aufwand trivial (~10 LOC). |

#### 3.1.4 Coverage / Signal-Vollständigkeit

##### F-PRE-005 — `nmap_light` Top-10 zu eng für Security-Pre-Check

| Feld | Inhalt |
|---|---|
| ID | F-PRE-005 |
| Phase / Stage | Pre-Check (IPv4-Pfad, CIDR-Pfad) |
| Komponente | `nmap_utils.run_top_ports` (`--top-ports 10`) |
| Code-Stelle | `scan-worker/scanner/common/nmap_utils.py:10, 21-22`; `scan-worker/scanner/precheck/nmap_light.py:10` |
| Dimension | Coverage |
| Beobachtung | `--top-ports 10` deckt nur 80, 23, 443, 21, 22, 25, 3389, 110, 445, 139. Datenbanken (3306, 5432, 6379, 27017, 9200), Alt-Web (8080, 8443), Mgmt (5900, 5985), Docker (2375), k8s (6443), AD (88, 636), Backups (873, 2049), Industrial (102, 502, 1883) fallen durchs Raster. `is_live` aus `bool(ports) or http_reachable` (`runner.py:148-150`) → ein Server, der nur auf Custom-Port lauscht, wird `is_live=false` → Admin-Ablehnungs-Risiko, KI #1 sieht leeren Service-Hint. |
| Coverage-Vergleich | Ist 10 Ports. Soll: 57 Ports kuratiert (Standard + S1 RCE/Anonymous + S2 KMU-Mgmt + S3 Industrial). |
| Entscheidung | **Option B++** — kuratierte 57-Port-Liste via `-p` (statt `--top-ports 10`):<br><br>```<br>21,22,23,25,53,80,88,102,110,111,143,389,443,445,465,<br>500,502,587,636,873,993,995,1099,1433,1521,1883,2049,<br>2375,2525,3000,3306,3389,5432,5601,5900,5984,5985,5986,<br>6379,6443,7547,8000,8080,8086,8200,8443,8500,8883,8888,<br>9090,9200,9300,9443,10000,11211,27017,28017<br>```<br><br>Kategorien (S1 RCE/Pre-Auth: Docker 2375, k8s 6443, WinRM 5986, Vault 8200, Consul 8500, Kibana 5601, Java RMI 1099, Elastic Transport 9300, rsync 873, NFS 2049, RPC 111, Oracle 1521 — S2 KMU-Mgmt: Webmin 10000, TR-069 7547, Grafana 3000, Prometheus 9090, InfluxDB 8086, CouchDB 5984, MongoDB-Web 28017, Kerberos 88, Alt-SMTP 2525 — S3 Industrial: Siemens S7 102, IKE 500, Modbus 502, MQTT 1883/8883). |
| Quelle | nmap-services Top-N https://nmap.org/book/nmap-services.html (2026-05-06); SANS ISC Top-Ports https://isc.sans.edu/data/topports.html (2026-05-06); Shodan ICS https://www.shodan.io/explore/category/industrial-control-systems (2026-05-06); Code-Analyse `common/nmap_utils.py:21-22`, `precheck/runner.py:148-150`. |
| Risiko | CIDR-Worst-Case: 256 IPs × 57 Ports × `-T4 --min-rate 200 --max-retries 2 --host-timeout 30s` ≈ 90-120s real, unter Wrapper-Timeout 180s. Mehr `is_live=true`-Hosts im Admin-Review (gewünschtes Verhalten — bessere Sichtbarkeit). Determinismus: Liste hardcoded → reproduzierbar. Cache: kein Pre-Check-Cache. |
| Priorität | mittel — direkter Coverage-Hebel auf Admin-Sichtbarkeit und KI #1-Signal bei IPv4/CIDR-Targets. |

##### F-PRE-003 — Cloud-Provider-Detection: deutsche/europäische Hoster fehlen

| Feld | Inhalt |
|---|---|
| ID | F-PRE-003 |
| Phase / Stage | Pre-Check (alle Pfade — FQDN, IPv4, CIDR) |
| Komponente | `saas_heuristic.detect_cloud_provider` / `_STATIC_RANGES` |
| Code-Stelle | `scan-worker/scanner/precheck/saas_heuristic.py:15-46` |
| Dimension | Coverage |
| Beobachtung | 5 Provider statisch (Cloudflare, AWS, Azure, GCP, Hetzner Cloud), kein Sync-Mechanismus. Fließt in `scan_target_hosts.cloud_provider`, `passive_intel.cloud_provider` (KI #1-Hint), CDN-Edge-Dedup in Phase 0b `merge_and_group()`. Konsequenz: KI #1 sieht null bei IONOS/STRATO/OVH-Hosts, CDN-Dedup greift bei Fastly/Akamai nicht, Admin-Review zeigt unbekannte Hoster für DE-Standard-Setups. |
| Coverage-Vergleich | Ist 5 Provider. Soll: +8 (IONOS, STRATO, OVHcloud, Hetzner Online, DigitalOcean, Fastly, Akamai, Vercel/Netlify) → 13 Provider. Phase-0b-Code referenziert Fastly bereits als CDN-Dedup-Provider, hier aber nicht klassifiziert. |
| Entscheidung | **Option B**: Sync-Skript `scripts/sync-cloud-ranges.py` + GitLab-Job `cloud-ranges-sync` (analog `eol-data-sync`, manueller Trigger oder Wochen-Schedule). Quellen:<br>• AWS `https://ip-ranges.amazonaws.com/ip-ranges.json`<br>• Azure ServiceTags JSON-Download<br>• GCP `https://www.gstatic.com/ipranges/cloud.json`<br>• Cloudflare `https://www.cloudflare.com/ips-v4`<br>• Fastly `https://api.fastly.com/public-ip-list`<br>• DigitalOcean `https://digitalocean.com/geo/google.csv`<br>• OVH / IONOS / STRATO / Hetzner-Online via RIPEstat ASN-Prefixes (AS16276 / AS8560 / AS6724 / AS24940)<br>Output: JSON-Datei im Worker-Image, beim Worker-Start in `_STATIC_RANGES` geladen. Cleanup-Regel: nur Prefixes ≥ /16 für ASN-Quellen, sonst Lookup-Tabelle wird zu groß. Initial-Build mit ~12 Providern + ~150 Ranges; Sync hält sie aktuell. |
| Quelle | AWS ip-ranges https://ip-ranges.amazonaws.com/ip-ranges.json (2026-05-06); Cloudflare https://www.cloudflare.com/ips-v4 (2026-05-06); Fastly https://api.fastly.com/public-ip-list (2026-05-06); RIPEstat https://stat.ripe.net/docs/02.data-api/ris-prefixes.html (2026-05-06); Code-Analyse `saas_heuristic.py:15-46`. |
| Risiko | gering. Sync-Quellen sind offiziell. Statische Datei beim Worker-Start geladen → Determinismus reproduzierbar bis zum nächsten Sync (Image-Tag enthält Sync-Stand). Kein Cache-Invalidierungs-Aufwand. |
| Priorität | mittel — direkter Effekt auf KI #1-Signalqualität und CDN-Dedup-Vollständigkeit, plus Admin-Sichtbarkeit für DE-Hoster. |

##### F-PRE-001 — Parking-/Maintenance-Pattern-Coverage

| Feld | Inhalt |
|---|---|
| ID | F-PRE-001 |
| Phase / Stage | Pre-Check (FQDN-Pfad, beide Schemes) |
| Komponente | `is_parking_page` / `_PARKING_PATTERNS` |
| Code-Stelle | `scan-worker/scanner/common/http_utils.py:18-34, 93-97` |
| Dimension | Coverage |
| Beobachtung | 14 Parking-Patterns, ausschließlich englisch. Keine deutschen Marker (VectiScan-Kundenbasis ist DE/AT). Mehrere große Provider fehlen (Namecheap, Bodis, Epik, Sav.com, Uniregistry, BuyDomains, PerfectDomain). „expired"/„maintenance"/„reserviert" fehlen. Konsequenz: nicht erkannte Parking-Hosts werden in Phase 0b/1 voll gescannt (~2–5 min Scan-Zeit + KI-Calls pro übersehenem Host). |
| Coverage-Vergleich | Ist 14 Patterns / 0 deutsch. Soll: +13 Pattern (siehe Entscheidung) → 27 total. |
| Entscheidung | **Option B (modifiziert)**: Pattern-Liste erweitern UND zusätzlichen Status-Code-Marker einführen. <br><br>**Pattern-Erweiterung (`_PARKING_PATTERNS`):**<br>```regex<br>diese\s+domain\s+steht\s+zum\s+verkauf<br>diese\s+domain\s+ist\s+(reserviert\|geparkt)<br>diese\s+seite\s+befindet\s+sich\s+im\s+aufbau<br>wartungsarbeiten<br>in\s+wartung<br>under\s+maintenance<br>this\s+domain\s+(has\s+)?expired<br>domain\s+expired<br>this\s+domain\s+is\s+(parked\|reserved)<br>namecheap<br>bodis<br>epik<br>sav\.com<br>uniregistry<br>buydomains<br>perfectdomain<br>```<br><br>**Status-Code-Marker:** Zusätzliche Heuristik in `is_parking_page` bzw. `probe_both_schemes`: Wenn `status==200` UND `final_url`-Hostname auf eine bekannte Parking-/Domain-Sale-Domain redirected (Allowlist von ~10 Hosts: `sedoparking.com`, `parkingcrew.net`, `dan.com`, `afternic.com`, `bodis.com`, `parkingpage.namecheap.com`, `epik.com`, `uniregistry.com`, `sav.com`, `buydomains.com`) → `parking=true` auch ohne Body-Match. Catcht Redirect-zu-Landing-Page-Variante.<br><br>**Konsolidierte Pattern-Anzahl:** ~30. **Allowlist-Hosts:** ~10. |
| Quelle | Code-Analyse `http_utils.py:18-34`; Marktanteile Parking-Plattformen `https://www.cnstats.org/dns-zones/parking` (2026-05-06); Namecheap Parking-Default `https://parkingpage.namecheap.com/` (Live-Inspektion 2026-05-06). |
| Risiko | keiner. Pattern-Erweiterung ist additiv (mehr Erkennungen, keine FP). Status-Code-Marker hat theoretisches FP-Risiko bei Self-Hosted-Setup eines Sale-Subdomains, aber Allowlist ist klein und enthält nur dedizierte Parking-Domains. Kein Cache (Pre-Check). |
| Priorität | mittel — direkter Cost-Effekt (eingesparte KI #1-Calls + Phase-1-Tools auf toten Hosts); abhängig von realer Parking-Häufigkeit der Kundenbasis. |

### 3.2 Phase 0a — Passive Intel

#### 3.2.1 Tool-Parameter

##### F-P0A-006 — Shodan on-demand Scans für Subscription-Pre-Warm

| Feld | Inhalt |
|---|---|
| ID | F-P0A-006 |
| Phase / Stage | Pre-Check (Subscription-Pfad) → Phase 0a |
| Komponente | Neuer Trigger-Pfad in `precheck_worker.py` (Subscription-only) + `ShodanClient.request_scan` |
| Code-Stelle | Trigger: `scan-worker/scanner/precheck_worker.py:69-77` (Subscription-Branch nach `precheck_complete`); ergänzend `scan-worker/scanner/passive/shodan_client.py` (neue Methode); Persistenz: neue JSONB-Spalte oder Tabelle `shodan_scan_requests`. |
| Dimension | Tool-Parameter / neuer Tool-Slot |
| Beobachtung | Shodan Freelancer-Plan stellt ~5000 monthly Scan-Credits (separater Pool von Query-Credits) für `POST /shodan/scan` zur Verfügung — aktuell ungenutzt. Shodan-Daten in `lookup_host(ip)` können beliebig alt sein, `data.last_update` wird nicht ausgewertet. |
| Live-Messung | Asynchroner API-Call, latenz-unabhängig (Fire-and-Forget). Resultats-Verfügbarkeit: typisch Stunden bis Tage in Shodan-DB. |
| Entscheidung | **Option D + Opt-In für One-Off-Orders** (Ergänzung 2026-05-06): Pattern 1 (Pre-Warm) **default-on für Subscription-Orders** und **optional opt-in für One-Off-Orders**.<br>**Subscription-Pfad (default-on):**<br>1. Neue Methode `ShodanClient.request_scan(ips: list[str]) -> str` (POST `/shodan/scan` mit `ips=<csv>`, returns `scan_id`).<br>2. Trigger-Punkt: `precheck_worker.py:69-77` Subscription-Branch nach `set_subscription_status(...)` und vor `publish_event('precheck_complete', ...)`.<br>3. Cap: `ips[:50]` (Freelancer ~5000/mo Reserve, ~1500 Credits/mo bei 30 Subscription-Re-Scans).<br>4. Persistenz: Spalte `subscriptions.shodan_scan_request` (JSONB: `scan_id, requested_at, ips[], status`) — Audit-Trail für späteres Status-Polling und Forensik.<br>5. Rechtliche Mitigation: Pre-Warm erst nach `scan_authorizations`-Upload triggern (= release-Punkt), nicht direkt nach Pre-Check.<br>**One-Off-Order-Pfad (opt-in):**<br>6. Frontend `POST /api/orders` erhält optionales Feld `pre_warm_shodan: boolean` (Default `false`).<br>7. Persistenz: neue Spalte `orders.pre_warm_requested BOOLEAN DEFAULT false` (Migration).<br>8. Trigger: `precheck_worker.py:55-68` Order-Branch prüft `orders.pre_warm_requested` — wenn `true`, gleicher `request_scan`-Pfad wie Subscription. Falls `false`, kein Pre-Warm.<br>9. Frontend-UI: Order-Form zeigt Toggle "Shodan Pre-Warm aktivieren — frischere passive Daten, +24-48h Wartezeit bis Scan-Start". Customer wählt bewusst je nach Time-Sensitivity.<br>10. Customer-Hinweis im UI: bei aktiviertem Pre-Warm soll Admin-Approval erst nach 24-48h erteilt werden, sonst geht der Wert verloren.<br>Pattern 2 (Stale-Refresh in Phase 0a) deferred — kann als Folge-Finding aufgegriffen werden, sobald Pattern 1 produktiv ist und Credit-Verbrauch im realen Betrieb gemessen ist. |
| Quelle | Shodan Scan API https://developer.shodan.io/api Section "Scans" (2026-05-06); Shodan Pricing https://www.shodan.io/about/pricing (2026-05-06, Freelancer ~5000 Scan-Credits/mo); Code-Analyse `precheck_worker.py:55-77`, `phase0a.py:70-89`, `passive/shodan_client.py`. |
| Risiko | **Rechtlich**: Pre-Warm nach Authorization-Upload löst Authorization-Frage. **Credit-Verbrauch**: 50 IPs × 30 Subscription-Re-Scans/mo = 1500 Credits/mo (Freelancer-Reserve ausreichend). **Determinismus**: Cache-Hash via `content_hash` über sortierte Service-Banner — frische Scan-Daten = neuer Hash = erwünschter Cache-Miss. **Failure-Mode**: Shodan-API down → log-warning, Pre-Warm fällt aus, Phase 0a fällt auf bestehende Cached-Daten zurück (kein Block). |
| Priorität | mittel — gewichtiger Wertbeitrag bei Subscription-Lifecycle, kein Aufwand bei One-Off. Strukturelle Architektur-Erweiterung. |

##### F-P0A-005 — Shodan/AbuseIPDB IP-Cap hardcoded `[:15]`

| Feld | Inhalt |
|---|---|
| ID | F-P0A-005 |
| Phase / Stage | Phase 0a — Passive Intel |
| Komponente | `_run_shodan`, `_run_abuseipdb` |
| Code-Stelle | `scan-worker/scanner/phase0a.py:82, 98`; `scan-worker/scanner/packages.py` (Paket-Configs) |
| Dimension | Tool-Parameter |
| Beobachtung | Hardcoded `for ip in ips[:15]:` in beiden Loops, nicht konfigurierbar, kein paketabhängiges Verhalten. /24-IPv4-Bereich → 6% Coverage. Multi-Subdomain mit 50 IPs → 70% verworfen. |
| Live-Messung | Indirekt: bei Targets mit >15 IPs sind Shodan/AbuseIPDB-Daten unvollständig in `passive_intel_summary`. Kein direktes `duration_ms` (Library-Call). |
| Entscheidung | **Option B**: paketabhängige Defaults in `packages.py` (neuer Schlüssel `phase0a_ip_cap`):<br>• `webcheck` / `tlscompliance`: skip Shodan/AbuseIPDB ohnehin (kein Effekt)<br>• `perimeter` / `compliance` / `supplychain`: Default 25<br>• `insurance` (IP-Scope-heavy): Default 50<br>Plus globaler ENV-Override `PHASE0A_IP_CAP` für Premium-Tier-Setups (überschreibt Paket-Default). Implementation: `_run_shodan`/`_run_abuseipdb` lesen `config.get("phase0a_ip_cap", 15)`, slicen `ips[:cap]`. |
| Quelle | Shodan Pricing/Credits https://www.shodan.io/about/pricing (2026-05-06); Code-Analyse `phase0a.py:82, 98`, `packages.py:_PERIMETER_BASE`. |
| Risiko | API-Credit-Verbrauch steigt — Insurance-Default 50 IPs × 100 Scans/mo = 5000 Shodan-Credits → braucht Membership/Freelancer-Tier (mit Freelancer-Plan abgedeckt). KI-Cache: Phase-0a-Output ändert sich → Cache-Hash ändert sich → Re-Scan-Cache-Misses akzeptabel (mehr Daten = neuer Wert). |
| Priorität | niedrig-mittel — bei Single-IP-FQDN-Targets irrelevant, bei IPv4/CIDR/Multi-IP-Targets direkter Coverage-Hebel. |

#### 3.2.2 Übergaben

##### F-P0A-004 — Phase-0a-Subdomain-Daten gehen an Phase 0b verloren

| Feld | Inhalt |
|---|---|
| ID | F-P0A-004 |
| Phase / Stage | Phase 0a → Phase 0b / Übergabe-Kante |
| Komponente | Wiring zwischen `phase0a.run_phase0a` und `phase0.run_phase0` |
| Code-Stelle | `scan-worker/scanner/phase0a.py:77-89, 112-117`; `scan-worker/scanner/phase0.py:206-247`; `scan-worker/scanner/worker.py` (Phase-0a→Phase-0b-Wiring) |
| Dimension | Übergabe |
| Beobachtung | Phase 0a sammelt `shodan_domain.subdomains[]` und `securitytrails.subdomains[]` (gespeichert in `phase0a/*.json`), Phase 0b ruft `run_securitytrails_subdomains` (`phase0.py:206`) und macht damit denselben SecurityTrails-Call **nochmal**. Doppel-Call gegen SecurityTrails-Free-Tier (50 Calls/mo) und +15s Phase-0b-Laufzeit (Live-Messung Ø 15s/Call). Shodan-Subdomain-Liste wird komplett ignoriert (weder KI #1 noch Phase 0b sehen sie). |
| Live-Messung | SecurityTrails Ø 15s (med 14.7s, max 18.7s, n=15) — wird durch Doppel-Call effektiv 2× konsumiert. |
| Entscheidung | **Option B** (primär): `phase0.run_securitytrails_subdomains` komplett entfernen — Phase-0a-Daten sind authoritative. Konkretes Wiring:<br>1. `phase0a.run_phase0a` returned zusätzlich `passive_subdomains: list[str]` (sortiertes Set aus `shodan_domain.subdomains` ∪ `securitytrails.subdomains`).<br>2. `worker.py` reicht das als optionales `seed_subdomains`-Argument an `phase0.run_phase0` weiter (analog zum bestehenden `subdomain_snapshot`-Seed aus Migration 019).<br>3. `phase0.merge_and_group()` mergt Phase-0a-Subdomains in den Discovery-Pool.<br>4. SecurityTrails-Call in Phase 0b entfernt — webcheck-Paket (`phase0a_tools=["whois"]`) verliert SecurityTrails-Discovery, aber webcheck ist Schnellscan und braucht's nicht.<br><br>**Option C zusätzlich angemerkt** (als Folge-Schritt für `subdomain_snapshot`-Adoption, nicht im selben PR notwendig): `subdomain_snapshot_store.save_for_target()` um Phase-0a-Quelle erweitern (`tool_sources`-Feld). So landen Shodan-/SecurityTrails-Subdomains im Snapshot-Cache (Migration 019, TTL 24h) und sind bei Re-Scans direkt verfügbar — Re-Scans innerhalb der TTL können dann auch ohne Phase-0a-Run die Subdomain-Liste rekonstruieren. |
| Quelle | SecurityTrails API Tier-Limits https://docs.securitytrails.com/reference/rate-limits (2026-05-06); Shodan DNS API https://developer.shodan.io/api (2026-05-06); Code-Analyse `phase0a.py:77-89, 112-117`, `phase0.py:206-247`, Migration 019 (`subdomain_snapshot`). |
| Risiko | Discovery-Pool wird breiter (Shodan-Subdomains adoptiert) → mehr `dnsx`-Validierungs-Calls; bisheriges `subscriptions.max_hosts`-Cap (Default 50) bleibt wirksam. KI #1-Cache stabil (Subdomain-Liste war kein KI-Input). Determinismus: sortiertes Set → stabil. webcheck-Paket verliert SecurityTrails-Discovery — vermutlich akzeptabel weil webcheck kein passives Intel macht. |
| Priorität | mittel — API-Tier-Verbrauchs-Cap + 15s Laufzeit-Einsparung; Coverage-Verbesserung durch Shodan-Subdomain-Adoption gering. |

#### 3.2.3 Parallelität

##### F-P0A-001 — Shodan / AbuseIPDB / SecurityTrails: innere API-Calls sequenziell

| Feld | Inhalt |
|---|---|
| ID | F-P0A-001 |
| Phase / Stage | Phase 0a — Passive Intel |
| Komponente | `_run_shodan`, `_run_abuseipdb`, `_run_securitytrails` |
| Code-Stelle | `scan-worker/scanner/phase0a.py:82-85, 98-101, 112-116`; `scanner/passive/base_client.py:34-64` |
| Dimension | Parallelität |
| Beobachtung | Top-Level Phase-0a-Tools laufen parallel (`max_workers=5`), aber **innen** iterieren Shodan und AbuseIPDB sequenziell `for ip in ips[:15]:` mit je 10s Timeout + 2 Retries (Backoff 2/4/8/16/32s bei 429). SecurityTrails macht 3 sequenzielle API-Calls (`lookup_domain`, `get_subdomains`, `get_dns_history`). Worst-Case Shodan: 15×10s = 150s — überschreitet `phase0a_timeout=120s`. |
| Live-Messung | SecurityTrails ø 15s (med 14.7s, max 18.7s, n=15) — passt zur seriellen 3-Calls-Heuristik. Shodan/AbuseIPDB ohne `duration_ms` (Library-Call). |
| Entscheidung | **Option B + C kombiniert**: <br>**B (Shodan/AbuseIPDB IP-Concurrency):** innerer `ThreadPoolExecutor(max_workers=3)` Default + ENV-Override `PASSIVE_INTEL_CONCURRENCY` für Premium-API-Keys. Default schont Free-Tier-Rate-Limits (Shodan ~1 req/s), Premium-User können hochstellen. Worst-Case 15 IPs in 5 Wellen × 10s = ~50s.<br>**C (SecurityTrails Inner-Parallelization):** `lookup_domain`, `get_subdomains`, `get_dns_history` mit `ThreadPoolExecutor(max_workers=3)` parallel. Speedup von 15s auf ~5s.<br>Kombiniert: Phase-0a-Gesamtzeit von typ. 75s auf typ. ~15s. |
| Quelle | Shodan API Rate Limits https://help.shodan.io/the-basics/rate-limiting (2026-05-06); AbuseIPDB API Doku https://docs.abuseipdb.com/#introduction (2026-05-06); Code-Analyse `phase0a.py:70-118`, `base_client.py:34-64`. |
| Risiko | Cache-Invalidierung: keiner (Phase 0a hat keinen Cache, Persistenz pro Order). Determinismus: Output-Dict key-basiert → reproduzierbar. API-Rate-Limit: konservatives `max_workers=3` Default mitigiert Free-Tier-Issue. |
| Priorität | mittel — bei IP-reichen Targets spürbar; Aufwand klein (~30 LOC, drei Funktionen). |

#### 3.2.4 Coverage / Signal-Vollständigkeit

##### F-P0A-003 — Passive-Intel-Quellen-Coverage: URLhaus, GreyNoise, OTX, VirusTotal fehlen

| Feld | Inhalt |
|---|---|
| ID | F-P0A-003 |
| Phase / Stage | Phase 0a — Passive Intel |
| Komponente | `phase0a_tools`-Konfiguration + neue `passive/*_client.py`-Module |
| Code-Stelle | `scan-worker/scanner/packages.py:15`; `scan-worker/scanner/passive/` (Clients-Verzeichnis); Aufruf-Punkt `scan-worker/scanner/phase0a.py:130-141` |
| Dimension | Coverage |
| Beobachtung | Phase 0a nutzt 5 passive Quellen (Shodan, AbuseIPDB, SecurityTrails, WHOIS, DNS-Security). KI #1 bekommt heute nur `shodan_*`, `abuseipdb_score`, `is_tor`, `whois_*`, `dnssec_signed` als `passive_intel`. Etablierte Quellen mit klarem Signal/Severity-Hebel fehlen — insbesondere **URLhaus** (Compromise-Indikator: Customer-Domain als aktive Malware-Distribution = CRITICAL), **GreyNoise** (IP-Noise-Klassifikation für KI #1-Skip-Heuristik), **OTX** (Domain/IP-Threat-Pulses), **VirusTotal Domain-Level** (Reputations-Score). |
| Coverage-Vergleich | Ist 5 passive Quellen. Soll: + URLhaus + GreyNoise + OTX + VirusTotal-Domain → 9. Censys deferred (Free-Tier 250/mo zu eng, Mehrwert ggü. Phase-0b-Discovery unklar). |
| Entscheidung | **Option A + C kombiniert**: vier neue Clients analog `shodan_client.py`:<br>• `urlhaus_client.py` — Domain/IP-Lookup gegen URLhaus-API (`https://urlhaus.abuse.ch/api/` — POST `payload[host]=<host>`); liefert `threat_type`, `tags`. Bei Match → Pflicht-Finding via Severity-Policy-Regel `SP-URLHAUS-*` (CRITICAL).<br>• `greynoise_client.py` — IP-Lookup gegen GreyNoise Community API (`https://api.greynoise.io/v3/community/<ip>`); liefert `noise_classification` + `riot` (legitim-business). Feld in `passive_intel.greynoise` aufgenommen, KI #1-Prompt um GreyNoise-Hint erweitern.<br>• `otx_client.py` — Domain- und IP-Lookups gegen OTX AlienVault API; liefert Threat-Pulses + Indicator-Reports. Feld in `passive_intel.otx`.<br>• `virustotal_client.py` — Domain-Level (1 Call pro Order, nicht pro IP — schont Free-Tier 4/min); liefert `reputation`, `last_analysis_stats`. Feld in `passive_intel.virustotal_domain`.<br>Aufruf in `phase0a.py` analog bestehende Tools (`max_workers=5` → `max_workers=9`). Konfiguration über `phase0a_tools` in `packages.py:15` (Perimeter-Base + neue Tools; webcheck/tlscompliance bleiben mit `whois`-only). |
| Quelle | GreyNoise API https://docs.greynoise.io/reference/get_v3-community-ip (2026-05-06); URLhaus API https://urlhaus.abuse.ch/api/ (2026-05-06); OTX AlienVault API https://otx.alienvault.com/api (2026-05-06); VirusTotal Public API v3 https://docs.virustotal.com/reference/overview (2026-05-06); Censys Search API https://search.censys.io/api (2026-05-06, deferred); Code-Analyse `packages.py:15`, `phase0a.py:130-141`, `passive/`-Verzeichnis. |
| Risiko | **API-Keys**: vier neue ENV-Variablen (`GREYNOISE_API_KEY`, `OTX_API_KEY`, `URLHAUS_AUTH_KEY`, `VIRUSTOTAL_API_KEY`); alle Keys haben Free-Tier. Worker-Container ohne Keys: Tools werden gracefully geskippt (siehe `base_client.py:available`-Pattern). **Laufzeit**: +4 parallele Phase-0a-Calls (`max_workers=5 → 9`); langsamster Tool dominiert weiter (SecurityTrails ø 15s). **Severity-Drift**: URLhaus-Match → neue Severity-Policy-Regel-Familie `SP-URLHAUS-*` → **POLICY_VERSION-Bump nötig**. **KI-Cache**: Phase-0a-Output fließt in KI #1-Input → Cache-Hash ändert sich → Re-Scan-Cache-Misses akzeptabel (neue Daten = neuer Wert). |
| Priorität | mittel — URLhaus allein hat Compromise-Detection-Wert; GreyNoise verbessert KI #1; OTX + VT komplementär. |

##### F-P0A-002 — `dns_security` Coverage: TLS-RPT, BIMI, DMARC-Policy-Detail, NSEC3-Iterations fehlen

| Feld | Inhalt |
|---|---|
| ID | F-P0A-002 |
| Phase / Stage | Phase 0a — Passive Intel / DNS-Security |
| Komponente | `run_all_dns_security` und `check_dnssec` |
| Code-Stelle | `scan-worker/scanner/passive/dns_security.py:24-71, 159-175`; ergänzend `scan-worker/scanner/phase0.py:720-727` (Phase-0b DMARC-Detection) |
| Dimension | Coverage |
| Beobachtung | Phase 0a prüft DNSSEC (basic), CAA, MTA-STS, DANE/TLSA. Es fehlen vier moderne Mail/DNS-Security-Records mit direktem Severity-Hebel. DMARC-Auswertung ist heute über Phase 0b (Detection raw) und Reporter (Severity-Policy ohne Detail) verstreut → kein einheitlicher Parser, keine Severity-Differenzierung `p=none` vs. `p=reject`. |
| Coverage-Vergleich | Ist 4 Checks. Soll: + TLS-RPT (RFC 8460), + BIMI (RFC 9091 draft), + DMARC-Policy-Parser (`p`, `sp`, `pct`, `rua_count`, `ruf_count`, `aspf`, `adkim`), + NSEC3-Iterations-Count im bestehenden `check_dnssec` (RFC 9276 / BSI-CS-018: ≤10). |
| Entscheidung | **Option C** — neues zentrales Modul `mail_security_parsers.py` (Reusability über Phase-0a, Phase-0b, Reporter `severity_policy.py`). Inhalt:<br>• `parse_dmarc(txt) -> DmarcPolicy` mit Feldern `p, sp, pct, rua, ruf, fo, aspf, adkim`<br>• `parse_tls_rpt(txt) -> TlsRptPolicy` mit `version, rua`<br>• `parse_bimi(txt) -> BimiRecord` mit `version, l, a` (URL + VMC)<br>Plus drei neue Phase-0a-Checks: `check_tls_rpt(domain)` (`_smtp._tls.<domain> TXT`), `check_bimi(domain)` (`default._bimi.<domain> TXT`), `check_dmarc_policy(domain)` (parst `_dmarc.<domain>` und liefert die strukturierten Felder, replaced die heutige raw-Detection in Phase 0b). NSEC3-Iterations-Erweiterung im bestehenden `check_dnssec` über `dig <domain> NSEC3PARAM` + Iterations-Feld parsen. Run-Set per Paket: TLS-RPT + DMARC für alle, BIMI nur Compliance/Insurance, NSEC3 für alle. |
| Quelle | TLS-RPT RFC 8460 https://www.rfc-editor.org/rfc/rfc8460.html (2026-05-06); BIMI Draft https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/ (2026-05-06); DMARC RFC 7489 https://datatracker.ietf.org/doc/html/rfc7489 (2026-05-06); NSEC3-Iterations RFC 9276 https://www.rfc-editor.org/rfc/rfc9276.html (2026-05-06); BSI TR-03108-1 §5.4 (Mail-Sicherheits-Mindest-Standards); Code-Analyse `dns_security.py:159-175`, `phase0.py:720-727`. |
| Risiko | **Cache-Invalidierung Reporter:** DMARC-Policy-Detail führt zu Severity-Hebung existierender DMARC-`p=none`-Findings → `POLICY_VERSION`-Bump nötig (`2026-04-30.1` → neuer Tag). Bestehende Reports werden nicht invalidiert (nur neue Scans betroffen). Determinismus: zentraler Parser → deterministische Felder. Phase-0a-Laufzeit: +3 dig-Queries × ~200ms = +600ms (vernachlässigbar gegenüber SecurityTrails 15s). FP-Risiko: keiner (Parser auf RFC-Strict, unbekannte Felder werden ignoriert). |
| Priorität | mittel-hoch — DMARC-Policy-Detail hat direkten Severity-Hebel im Reporter; TLS-RPT/BIMI sind Compliance- und Insurance-Pflicht-Marker; NSEC3-Iterations relevant für BSI-Compliance-Paket. |

### 3.3 Phase 0b — DNS + Discovery + VHost-Probe

#### 3.3.1 Tool-Parameter

##### F-P0B-004 — gobuster_dns Wordlist (`subdomains-top5000.txt`) zu eng

| Feld | Inhalt |
|---|---|
| ID | F-P0B-004 |
| Phase / Stage | Phase 0b — DNS-Bruteforce |
| Komponente | `run_gobuster_dns` |
| Code-Stelle | `scan-worker/scanner/phase0.py:466-520` (Wordlist-Pfad Z. 475); Container-Wordlist-Quelle (zu ergänzen im Dockerfile) |
| Dimension | Coverage |
| Beobachtung | gobuster nutzt `subdomains-top5000.txt` (vermutlich SecLists 2014/2018-Stand). Live-Mess Ø 1.7s, max 7.7s — Wrapper-Timeout 180s wird zu <5% ausgeschöpft. Spielraum für deutlich größere Maintained-Listen. Moderne SaaS-/DevOps-Patterns (`api-v2`, `argocd`, `vault`, `webhook`, `staging-eu`) fehlen oft im Top-5000-Korpus. |
| Live-Messung | gobuster_dns Ø 1.7s, med 0.7s, max 7.7s, n=30 — Tool nutzt sein Zeitbudget heute kaum. |
| Entscheidung | **Option B + C kombiniert** — drei kuratierte Quellen, dedupliziert.<br><br>**Zusammenstellung der Master-Wordlist:**<br>1. `subdomains-top1million-20000.txt` (SecLists, ~20k klassische Patterns) — Basis<br>2. `bitquark-subdomains-top100000.txt` Top-10k (SecLists, Bug-Bounty-derivative) — moderne Web-/SaaS-Patterns<br>3. `n0kovo_subdomains_small.txt` (Repo, ~10k frisch 2024 gepflegt) — aktuelle Cloud/DevOps-Patterns<br><br>**Build-Time-Merge** im Dockerfile: `cat src1 src2 src3 | sort -u > /usr/share/wordlists/vectiscan-subdomains.txt`. Dedupliziert ergibt ~28-32k Einträge (typische Überschneidung 20-30% zwischen den Quellen).<br><br>**Tuning-Anpassung gegen NS-Aggression:**<br>- `--threads 30` (statt 50) als Compromise zwischen Speed und Customer-NS-Friendliness (~830 → ~500 Q/s).<br>- `--timeout 3s` (statt 5s) für schnelleres Fail-Fast bei nicht-existierenden Subdomains.<br>- Restliche Flags (`--wildcard`, `-q`) unverändert.<br><br>Realistic Worst-Case: ~50-90s (DNS-Cache-Hit), max ~120-150s bei Wildcard-/Slow-NS — bleibt unter Wrapper-Timeout 180s. |
| Quelle | SecLists Repo https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS (2026-05-06); bitquark Subdomain-Liste https://github.com/bitquark/dnspop (2026-05-06); n0kovo Subdomains https://github.com/n0kovo/n0kovo_subdomains (2026-05-06); Assetnote Wordlists https://github.com/assetnote/wordlists (2026-05-06, deferred); Code-Analyse `phase0.py:466-520`. |
| Risiko | **Customer-NS-Last:** ~30k DNS-Queries × ~500 Q/s. Cloudflare/Route53/Hetzner unkritisch; Self-Hosted-Customer-NS könnte aggressive wahrnehmen — `--threads 30`-Reduktion mitigiert. **Wildcard-FP:** größere Liste = mehr Wildcard-Antworten — `--wildcard` filter unverändert. **Determinismus:** Build-Time `sort -u` reproduzierbar wenn Wordlist-Quellen pinned-versioniert. **Snapshot-Cache:** bestehende Phase-0b-Snapshots (Migration 019) haben kleineren Pool → Re-Scans innerhalb TTL liefern weniger; akzeptabel. |
| Priorität | mittel — direkter Coverage-Hebel für moderne SaaS-/DevOps-Subdomains. |

##### F-P0B-003 — amass v5 entfernen (Hard-Cap-Bottleneck + `-brute`-Workaround vs. gobuster_dns Doppelarbeit)

| Feld | Inhalt |
|---|---|
| ID | F-P0B-003 |
| Phase / Stage | Phase 0b — Subdomain-Discovery |
| Komponente | `run_amass` |
| Code-Stelle | `scan-worker/scanner/phase0.py:350-463`; Container-Install in `scan-worker/Dockerfile`; Snapshot-Schema Migration 019 (`tool_sources`) |
| Dimension | Tool-Parameter / Architektur |
| Beobachtung | amass v5 hat dokumentierten Race-Bug (`docs/analyse/AMASS-V5-DIAGNOSE.md`): bei `WorkItemsTotal==0` exit 0 mit leerer DB. Workaround `-brute` zwingt ~5000 Wordlist-DNS-Queries als WorkItem-Generator. Damit ist amass effektiv ein zweiter DNS-Bruteforcer parallel zu `gobuster_dns` (auch ~5000 Queries) → Wordlist-Doppelarbeit. Live-Mess zeigt amass Hard-Cap-Hit (300s) in 1/30 Aufrufen — direkter Phase-0b-Bottleneck. |
| Live-Messung | amass Ø 22.1s (med 5.0s, max 300.0s = Hard-Cap, n=30). amass_subs Ø 45ms (n=13). gobuster_dns Ø 1.7s (med 0.7s, max 7.7s, n=30) — ~12× schneller, gleiche semantische Klasse. |
| Entscheidung | **Option A** — amass komplett entfernen. Begründung: F-P0B-002 macht subfinder-Free-Source-Coverage explizit; gobuster_dns macht DNS-Bruteforce; amass-mit-`-brute` ist Doppelarbeit. Worst-Case-Phase-0b sinkt um 300s.<br>Konkrete Schritte:<br>1. `run_amass` aus `phase0.py` entfernen (Funktion + Aufruf).<br>2. `amass`-Install aus `Dockerfile` entfernen (~50MB Image-Reduktion).<br>3. `subdomain_snapshot.tool_sources` Schema bleibt — bestehende Snapshots mit `["amass", ...]` bleiben gültig, neue ohne `amass`-Eintrag.<br>4. Folge-Finding (separat aufzunehmen falls Coverage-Verlust real auftritt): `dnsx -brute` mit Permutation-Wordlist als Ersatz für amass-Permutation-Heuristik. Heute nicht im Scope. |
| Quelle | `docs/analyse/AMASS-V5-DIAGNOSE.md` (Repo-internes Analyse-Dokument); amass v5 Release-Notes https://github.com/owasp-amass/amass/releases (2026-05-06); amass Datasources https://github.com/owasp-amass/amass/blob/master/resources/datasources.yaml (2026-05-06); subfinder vs amass Vergleich https://blog.projectdiscovery.io/best-subdomain-enumeration-tools/ (2026-05-06); Code-Analyse `phase0.py:350-463`. |
| Risiko | Coverage-Verlust real aber begrenzt: amass-Permutation-Heuristik (ALTRA, dns-permute) entfällt — geschätzt <5% Subdomain-Verlust bei Domains mit ungewöhnlichen Patterns. Build-Größe: -50MB. Determinismus: weniger Drift, weniger Quellen. Snapshot-Schema bleibt kompatibel. Ein nachgelagertes `dnsx -brute` als Ersatz wäre die saubere Permutation-Quelle, aber separat zu entscheiden. |
| Priorität | mittel — Worst-Case-Cap (300s 1/30-Pfad), Architektur-Hygiene, Maintainability. |

##### F-P0B-002 — subfinder mit `-all` ohne Provider-API-Keys

| Feld | Inhalt |
|---|---|
| ID | F-P0B-002 |
| Phase / Stage | Phase 0b — Subdomain-Discovery |
| Komponente | `run_subfinder` + Container-Konfig |
| Code-Stelle | `scan-worker/scanner/phase0.py:298-314`; `scan-worker/Dockerfile:204` |
| Dimension | Tool-Parameter |
| Beobachtung | subfinder läuft mit `-all`, aber Container hat keinen `~/.config/subfinder/provider-config.yaml` (Dockerfile legt nur das Verzeichnis an). Premium-Provider (Chaos, BinaryEdge, Censys, GitHub, ZoomEye, Shodan, SecurityTrails) werden silent geskippt — effektive Coverage = nur Free-Provider (crt.sh, hackertarget, wayback, dnsdumpster, alienvault, anubis usw.). Drift zwischen `-all`-Implikation und Realität. |
| Live-Messung | subfinder Ø 3.1s, max 15.4s, n=30 — Performance OK; Coverage-Begrenzung ist nicht zeitlich bedingt. |
| Entscheidung | **Option A** — `-all` durch explizite `-sources`-Liste mit Free-Providern ersetzen. Konkrete Liste:<br><br>```<br>-sources crtsh,hackertarget,wayback,dnsdumpster,alienvault,<br>         anubis,bevigil,bufferover,cero,certspotter,<br>         commoncrawl,digitorus,dnsrepo,fofa,fullhunt,<br>         hudsonrock,leakix,passivetotal,quake,rapiddns,<br>         sitedossier,subdomaincenter,threatbook,virustotal-passive,<br>         waybackarchive,whoisxml,zoomeyeapi<br>```<br><br>Premium-Provider werden orthogonal über Phase 0a/Phase-0a-Erweiterung (F-P0A-003) abgedeckt — kein Doppelarbeit-Risiko. Konfigurations-Risiko (fehlerhafte YAML, Build-Zeit-Rendering) entfällt. |
| Quelle | subfinder Provider-Liste https://github.com/projectdiscovery/subfinder (2026-05-06); subfinder CLI-Doku `-sources`/`-exclude-sources` https://docs.projectdiscovery.io/tools/subfinder/usage (2026-05-06); Code-Analyse `phase0.py:298-314`, `Dockerfile:204`. |
| Risiko | Coverage nominal unverändert (`-all` ohne Keys liefert eh nur Free-Provider). Determinismus verbessert (sichtbare Source-Wahl). Kein Cache-Invalidate (subfinder cacht nicht). |
| Priorität | niedrig-mittel — strukturelle Hygiene und Audit-Fähigkeit; Coverage-Verbesserung indirekt durch explizite Sichtbarkeit. |

##### F-P0B-001 — DKIM-Selektoren-Liste sequenziell und unvollständig

| Feld | Inhalt |
|---|---|
| ID | F-P0B-001 |
| Phase / Stage | Phase 0b — DNS-Records-Block |
| Komponente | DKIM-Detection in `_dig_dns_records` (oder umliegende Funktion) |
| Code-Stelle | `scan-worker/scanner/phase0.py:729-764` |
| Dimension | Coverage + Parallelität (Doppel-Aspekt) |
| Beobachtung | `DKIM_SELECTORS` 25 Einträge. Code-Comment Z. 735-736 sagt explizit „probe gaengige Selektoren parallel; gefundene Selektoren werden gemerkt" — Code Z. 751 ist aber sequenziell (`for sel in DKIM_SELECTORS:`). 25 sequenzielle dig-Queries × ~200-500ms = 5-12s. Liste deckt Microsoft 365, Google Workspace, Mailchimp, SendGrid, SparkPost, Hornetsecurity ab — fehlen Postmark/Amazon SES/Mailgun/Mailjet/Brevo/Zoho sowie real häufige DE-Provider (1&1/IONOS, STRATO, T-Online, GMX). |
| Live-Messung | Live-Mess für DKIM-Subqueries nicht in `scan_results` (Library-Call innerhalb dns_records). Strukturelle Worst-Case-Analyse 5-12s. |
| Entscheidung | **Option B**: Parallelisierung **plus** kuratierte Selektor-Erweiterung.<br>**Parallelisierung:** `concurrent.futures.ThreadPoolExecutor(max_workers=10)` für die DKIM-Probe-Schleife. FIXED_NAMESERVERS (Cloudflare/Google/Quad9) haben gigantische QPS-Limits, kein Rate-Limit-Risiko bei 25-44 parallelen Queries. Worst-Case <2s.<br>**Selektor-Erweiterung (~19 zusätzlich, Total ~44):**<br>```<br>+ pm, amazonses, mailgun, mg, mailjet, sendinblue, zoho,<br>+ s2048, s1024, sig1, sig2, pf2014,<br>+ 1und1, ionos1, ionos2, strato1, strato2, t-online, gmx<br>```<br>Code-Comment-Drift wird durch tatsächlich-parallelen Code aufgelöst. |
| Quelle | DKIM RFC 6376 https://datatracker.ietf.org/doc/html/rfc6376 (2026-05-06); MailSniper-DKIM-Selektoren https://github.com/dafthack/MailSniper/blob/master/Misc/dkim-selectors.txt (2026-05-06); Amazon SES DKIM https://docs.aws.amazon.com/ses/latest/dg/easy-dkim.html (2026-05-06); IONOS DKIM-Setup https://www.ionos.de/hilfe/e-mail/allgemeine-themen/dkim-spf-dmarc-fuer-ihre-domain-konfigurieren/ (2026-05-06); Code-Analyse `phase0.py:729-764`. |
| Risiko | Coverage-Erweiterung: kein FP-Risiko (DKIM-Probes prüfen `v=dkim1`-Tag eindeutig); mehr Treffer = bessere Detection. Parallelisierung: 44 parallele dig-Queries gegen FIXED_NAMESERVERS — kein Rate-Limit-Risiko. Determinismus: `found_selectors` sortiert → reproduzierbar. Reporter-Cache: `consolidated_findings`-Hash ändert sich bei Sites die jetzt erkannt werden (gewollter Cache-Miss). |
| Priorität | mittel-hoch — direkter Severity-Hebel auf bestehende DKIM-Findings (false-positive "DKIM missing" bei DE-Customers ist exakt der dokumentierte Bug-Klasse, der den 2026-05-03-Fix ausgelöst hat); Parallel-Fix räumt Code-Comment-Drift auf. |

#### 3.3.2 Übergaben

##### F-P0B-008 — certspotter nur als Fallback statt parallel zu crt.sh

| Feld | Inhalt |
|---|---|
| ID | F-P0B-008 |
| Phase / Stage | Phase 0b — Certificate-Transparency-Discovery |
| Komponente | `run_certificate_transparency`-Aufrufer + `run_certspotter` |
| Code-Stelle | `scan-worker/scanner/phase0.py:120-203` (crt.sh) + `:250-289` (certspotter) |
| Dimension | Übergabe / Coverage |
| Beobachtung | certspotter wird nur bei komplett leerem crt.sh-Result aufgerufen (Code-Comment Z. 130). Bei partial crt.sh-Result (5 Subdomains statt 50) wird certspotter ignoriert. crt.sh-3-Stufen-Self-Retry blockiert den Phase-0b-Pfad mit bis zu 50s Wartezeit, bevor certspotter überhaupt befragt wird. |
| Live-Messung | crt.sh Ø 6.6s, max 57s, n=30 (1/3 Aufrufe trifft Retry2, 1/4 Retry3). certspotter Ø 0.55s, max 1.25s, n=7 — 10× schneller, aber heute selten aufgerufen. |
| Entscheidung | **Option A** — beide CT-Quellen parallel laufen lassen, Subdomain-Sets vereinigen. Konkret:<br>1. `ThreadPoolExecutor(max_workers=2)` für `run_crtsh` + `run_certspotter`-Submission.<br>2. Beide Resultate per `set.union()` mergen, sortiert.<br>3. Caller-Code (`run_certificate_transparency`) wird zum simplen Aggregator.<br>4. crt.sh-3-Stufen-Self-Retry-Logik bleibt unverändert (defensiv für crt.sh-Instabilität gerechtfertigt).<br>5. Worst-Case-Phase-0b-CT-Discovery fällt auf `max(crt.sh, certspotter) ≈ 50-60s` (crt.sh dominiert), aber Coverage steigt durch Vereinigung. |
| Quelle | crt.sh-Instabilität in Code-Comment `phase0.py:121-130`; certspotter API https://sslmate.com/help/reference/ct-search-api/ (2026-05-06, Free-Tier ~100 Q/h, Premium höher); Code-Analyse `phase0.py:120-203, 250-289`. |
| Risiko | certspotter-Tier-Limit Free 100 Q/h × 30 Orders/Tag = ~30 Q/Tag → unproblematisch. Cache: Phase-0b-Subdomain-Pool wächst → `subdomain_snapshot`-Cache-Miss bei betroffenen Domains. Determinismus: vereinigtes Set sortiert → reproduzierbar. |
| Priorität | mittel — direkte Coverage-Verbesserung (frische CT-Issuances) und Architektur-Hygiene (Fallback-statt-parallel-Antipattern). |

##### F-P0B-005 — CDN-Edge-Dedup rdns-Pattern-Inkonsistenz (Tot-Code-Pfad für Fastly/Akamai)

| Feld | Inhalt |
|---|---|
| ID | F-P0B-005 |
| Phase / Stage | Phase 0b — Host-Aggregation |
| Komponente | `_dedup_cdn_hosts` (Funktionsname laut Code-Logik um Z. 855-891) |
| Code-Stelle | `scan-worker/scanner/phase0.py:861-873`; `scan-worker/scanner/precheck/saas_heuristic.py:15-46` |
| Dimension | Übergabe / Coverage |
| Beobachtung | Reihenfolge-Inkonsistenz: Z. 861 ruft `detect_cloud_provider(ip)` (5 Provider in `_STATIC_RANGES`); wenn `None` → `standalone.append(h)` und Continue. Erst danach kommt der rdns-Check (Z. 867-870) mit 7 Patterns inkl. `fastly`/`akamai`. Da Fastly/Akamai aber NICHT in `_STATIC_RANGES` sind, liefert `detect_cloud_provider` für sie immer `None` → der rdns-Check wird nie erreicht → Tot-Code-Pfad. Konsequenz: Fastly-/Akamai-Edges werden nicht dedupliziert, mehrere IPs derselben Edge erscheinen als separate Hosts → mehr Phase-1/2-Tool-Läufe. |
| Live-Messung | Indirekt: `cdn_edge_collapse`-Log-Events für Fastly/Akamai erscheinen nie in den Logs (Code-Pfad nicht erreichbar). |
| Entscheidung | **Option B** — `_dedup_cdn_hosts` umstrukturieren: rdns-Check **vor** der IP-Range-Prüfung. Wenn rdns einen CDN-Pattern enthält → Host als CDN-Edge geflaggt, auch wenn IP nicht in Static-Ranges. Defensiv-Strategie deckt rotierende/neue CDN-Ranges ab.<br><br>**Implementation-Details:**<br>1. Neuer Helper `saas_heuristic.rdns_provider_patterns() -> dict[str, list[str]]` als zentrale Provider-Tag-Liste (analog `_STATIC_RANGES`-Schlüsseln nach F-PRE-003-Sync).<br>2. `_dedup_cdn_hosts` priorisiert rdns-Match (Z. 866 vorziehen): wenn rdns enthält Provider-Pattern → CDN-Edge → Group-Key.<br>3. Fallback IP-Range-Match nur wenn rdns leer ist.<br>4. False-Positive-Mitigation: rdns-Match auf Suffix-Match einschränken (`rdns.endswith(".cloudflare.net")` statt nur `"cloudflare" in rdns`), um Customer-Strings wie `cdn-cloudflare-failover.example.com` nicht fälschlich zu klassifizieren. |
| Quelle | Code-Analyse `phase0.py:861-873`, `scanner/precheck/saas_heuristic.py:15-46`; Cloudflare IP-Drift-Doku https://www.cloudflare.com/ips/ (2026-05-06, Provider warnt explizit dass Ranges sich ändern können). |
| Risiko | False-Positive bei Customer-rdns mit Provider-Wort: durch Suffix-Match (statt Substring) deutlich reduziert. Determinismus: Group-Reihenfolge identisch (gleiche Sort-Keys). KI-Cache: weniger Hosts in Phase 0b-Output → Cache-Hash ändert sich → Re-Scan-Cache-Misses akzeptabel. F-PRE-003 bleibt unabhängig wertvoll (KI-Hint-Qualität, Admin-Sichtbarkeit). |
| Priorität | mittel — Tot-Code-Pfad ist klarer Bug; CDN-Dedup-Vollständigkeit beeinflusst Scan-Laufzeit direkt (jeder nicht-deduplizierte Edge = ein kompletter Phase-1/2-Lauf mehr). |

#### 3.3.3 Parallelität

##### F-P0B-007 — Multi-VHost-Probe: subprocess-pro-FQDN statt batch httpx

| Feld | Inhalt |
|---|---|
| ID | F-P0B-007 |
| Phase / Stage | Phase 0b — Multi-VHost-Probe |
| Komponente | `_probe_web_hosts` + `_probe_single_fqdn` |
| Code-Stelle | `scan-worker/scanner/phase0.py:1304-1320, 1362-1386` |
| Dimension | Parallelität / Tool-Parameter |
| Beobachtung | Pro FQDN startet ein eigenes httpx-Subprocess (`subprocess.run([httpx, -u <fqdn>, ...])`). Outer-Loop (Hosts) und Inner-Loop (FQDNs) sequenziell. Bei 5 Hosts × 5 FQDNs = 25 Subprocesses × ~2s Wall-Time = ~50s. httpx unterstützt `-l <file>` mit `-threads`-Parallelisierung intern. |
| Live-Messung | `web_probe` ohne `duration_ms` (Library-Call). Vergleich: Phase-1/2-`httpx` Ø 2.1s, max 20.6s, n=105 — analoger Aufruf, gleiche Größenordnung. Bei 25 sequenziellen Probes = ~50s. |
| Entscheidung | **Option A** — `_probe_web_hosts` auf batch-httpx umbauen:<br>1. Alle FQDNs aller Hosts in eine Tempfile schreiben.<br>2. Einen einzigen Aufruf: `httpx -l <file> -json -silent -follow-redirects -status-code -title -timeout 5 -retries 1 -hash sha256 -fr -threads 30`.<br>3. NDJSON parsen, pro Eintrag dem Host via pre-built `fqdn → host`-Dict zuordnen.<br>4. Parking-Detection (mit F-PRE-001 erweitertem `_PARKING_PATTERNS`) im Post-Processing.<br>5. Schema-Auswahl pro FQDN (https vs http): https wenn Status `<500`, sonst http (analog `probe_both_schemes`-Logik in `http_utils.py`).<br>6. Sort nach `fqdn` für Determinismus (httpx-Output-Reihenfolge nicht garantiert bei Threads).<br>Speedup-Ziel: ~50s → ~5-10s (Faktor 5-10×). Code wird einfacher (1 Subprocess statt N). |
| Quelle | httpx CLI-Doku `-l`/`-threads` https://docs.projectdiscovery.io/tools/httpx/usage (2026-05-06); httpx Performance-Tuning https://github.com/projectdiscovery/httpx#scan-with-thread-control (2026-05-06); Code-Analyse `phase0.py:1304-1320, 1362-1386`. |
| Risiko | Output-Mapping: httpx `input`/`host`-Feld zuverlässig. Schema-Probing: httpx ohne explizites Schema probiert beide → 2 Output-Zeilen pro FQDN; Schema-Auswahl deterministisch. Determinismus: nach Sort `fqdn` reproduzierbar. Timeout-Verhalten: `-timeout 5` cappt pro URL, `-threads 30` cappt Concurrency. |
| Priorität | mittel-hoch — direkter Phase-0b-Speedup um Faktor 5-10× in zentralem Pfad; Code-Vereinfachung als Nebeneffekt. |

#### 3.3.4 Coverage / Signal-Vollständigkeit

##### F-P0B-006 — Subdomain-Takeover-Provider-Liste unvollständig

| Feld | Inhalt |
|---|---|
| ID | F-P0B-006 |
| Phase / Stage | Phase 0b — Dangling-CNAME-Klassifikation |
| Komponente | `_TAKEOVER_POSSIBLE` / `_TAKEOVER_NOT_POSSIBLE` Listen + `_classify_dangling_cname` |
| Code-Stelle | `scan-worker/scanner/phase0.py:30-95, 98-117` |
| Dimension | Coverage |
| Beobachtung | `_TAKEOVER_POSSIBLE` 31 Einträge, `_TAKEOVER_NOT_POSSIBLE` 14 Einträge — manuell gepflegt, kein Sync. EdOverflow's `can-i-take-over-xyz` (kanonische Bug-Bounty-Quelle) listet ~70 takeoverable Services. Gap ~40 Einträge inkl. Statuspage/Webflow/Tilda/Acquia/WP-Engine/Bigcartel/Strikingly/Carrd/Smartling. Konsequenz: verwaiste CNAMEs auf nicht-gelistete Provider werden als „low" klassifiziert (`phase0.py:117`) → Reporter sieht kein CRITICAL-Finding. |
| Coverage-Vergleich | Ist 31 takeoverable. Soll: ~70 (EdOverflow). |
| Entscheidung | **Option B** — Sync-Skript `scripts/sync-takeover-list.py` analog `eol-data-sync` (CLAUDE.md `Determinismus-Block`) und F-PRE-003-`cloud-ranges-sync`. Quelle: EdOverflow's `can-i-take-over-xyz` README-Markdown-Tabelle (parsbar). GitLab-Job `takeover-list-sync` manuell oder Wochen-Schedule. Output: JSON-Datei `scan-worker/scanner/data/takeover_providers.json` (`{possible: [{suffix, service, vulnerable: bool}], not_possible: [...]}`), beim Worker-Start in `_TAKEOVER_POSSIBLE`/`_TAKEOVER_NOT_POSSIBLE` geladen. Sync-Filter: nur Einträge mit `vulnerable: yes` in `_TAKEOVER_POSSIBLE`. PunkSecurity dnsReaper-Fingerprints deferred (Option C) als Folge-Erweiterung falls EdOverflow-Coverage nicht reicht. |
| Quelle | EdOverflow can-i-take-over-xyz https://github.com/EdOverflow/can-i-take-over-xyz (2026-05-06); HackTricks Subdomain-Takeover https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover (2026-05-06); PunkSecurity dnsReaper https://github.com/punk-security/dnsReaper (2026-05-06, deferred); Code-Analyse `phase0.py:30-95, 98-117`. |
| Risiko | **Severity-Drift:** mehr CRITICAL-Findings → **POLICY_VERSION-Bump empfohlen** (Severity-Verteilung verschiebt). False-Positive-Risiko gering, weil EdOverflow konservativ verifiziert. Determinismus: gesynced JSON-Datei beim Worker-Start geladen → reproduzierbar bis zum nächsten Sync. |
| Priorität | mittel-hoch — direkter Severity-Hebel auf seltene aber CRITICAL-Findings (echte Takeovers = Compromise-Indikator). |

### 3.4 KI #1 — Host-Strategy

#### 3.4.1 Tool-Parameter
_(noch keine angenommenen Findings)_

#### 3.4.2 Übergaben

##### F-KI1-002 — Hard-Override deckt nur Web-Hosts ab, nicht Mailserver-only

| Feld | Inhalt |
|---|---|
| ID | F-KI1-002 |
| Phase / Stage | KI #1 — Host-Strategy / Hard-Override |
| Komponente | `_enforce_scan_for_live_web_hosts` |
| Code-Stelle | `scan-worker/scanner/ai_strategy.py:350-425` (Definition); `:337` (Aufruf) |
| Dimension | Übergabe |
| Beobachtung | Hard-Override erzwingt `action="scan"` nur für Web-Hosts mit live primary VHost (`status ∈ {200,201,202,204,301,302,401,403,405}`). Mailserver-only-Hosts (Port 25/465/587 ohne Web) haben keinen primary VHost → fallen NICHT in die Override-Bedingung. System-Prompt fordert „Mailserver NICHT skippen" (Z. 219), aber bei KI-Fehlentscheidung gibt es kein Sicherheitsnetz. Konsequenz: SPF/DMARC-Findings + TLS-Audit für Mailserver fehlen im Report. |
| Live-Messung | Strukturelle Lücke aus Code-Analyse; Live-Daten zeigen es nicht direkt. |
| Entscheidung | **Option A** — Hard-Override um Mail-Host-Klausel erweitern. Implementation:<br>```python<br>MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}<br>def _is_mail_host(host, dns_findings):<br>    shodan_ports = set(host.get("passive_intel", {}).get("shodan_ports", []))<br>    if shodan_ports & MAIL_PORTS:<br>        return True<br>    mx_targets = {mx.lower() for mx in dns_findings.get("mx", [])}<br>    host_fqdns = {f.lower() for f in host.get("fqdns", [])}<br>    return bool(host_fqdns & mx_targets)<br>```<br>Wenn KI auf `skip` UND `_is_mail_host(host, dns_findings)` → erzwinge `action="scan"`, `priority=4`, Begründung `[AUTO-OVERRIDE] Mail-Service`. |
| Quelle | Code-Analyse `ai_strategy.py:350-425` (Hard-Override), `:219` (System-Prompt-Regel), `phase0.py:766-779` (MX-Records-Block); BSI TR-03108-1 Mail-Security-Mindest-Standards (Rationale). |
| Risiko | Mehr Auto-Overrides bei Mailservern → +1 Phase-1-Lauf (ø nmap 45s) + Phase-2-Tools pro Mailserver-Host. Bei Top-N-Cap (max 15 Hosts perimeter) verdrängt das ggf. einen niedrig-priorisierten Web-Host. Akzeptabel weil Mail-Security-Findings für Compliance/Insurance-Pakete wichtig sind. Determinismus: Set-Operationen → reproduzierbar. Cache: Override ist post-KI, kein Cache-Effekt. |
| Priorität | mittel — Mail-Security-Compliance-Wert; deckt eine konkret im System-Prompt benannte aber nicht-erzwungene Regel. |

##### F-KI1-001 — `scan_hints` im KI #1-Output ist toter Code

| Feld | Inhalt |
|---|---|
| ID | F-KI1-001 |
| Phase / Stage | KI #1 — Host-Strategy |
| Komponente | `HOST_STRATEGY_SCHEMA` und Output-Konsumenten |
| Code-Stelle | `scan-worker/scanner/ai_strategy.py:250-265` (Schema); kein Konsument im Scanner-Code |
| Dimension | Übergabe / KI-Prompt-Effizienz |
| Beobachtung | Schema verlangt pro Host `scan_hints.shodan_ports[]` und `scan_hints.focus_areas[]`. Grep über Repo (`scan_hints\|focus_areas` in `scan-worker/scanner/`) zeigt nur Schema-Definition selbst — keinen Konsumenten in Phase 1/2/3, KI #2/3, oder Reporter. KI bezahlt Output-Tokens für Felder, die niemand auswertet. |
| Live-Messung | ~30-50 Output-Tokens/Host × ø 30 Hosts × 96 Perimeter-Reports/mo × Haiku-Output 4.0 USD/MTok ≈ ~$0.6/mo. Cache-Hits sparen, aber Cache-Miss-Calls bezahlen voll. |
| Entscheidung | **Option A** — `scan_hints` aus `HOST_STRATEGY_SCHEMA` entfernen. KI liefert nur noch `ip`, `action`, `priority`, `reasoning` pro Host. Top-Level `passive_intel_summary` und `strategy_notes` bleiben (haben Audit-Wert in `phase0/host_strategy.json`, auch wenn sie ebenfalls keinen downstream-Konsumenten haben). System-Prompt entsprechend kürzen. |
| Quelle | Grep `scan_hints\|focus_areas` über `scan-worker/scanner/` — kein Konsument außer Schema-Definition; Code-Analyse `ai_strategy.py:250-265`. |
| Risiko | Cache-Invalidation: System-Prompt-Hash ändert sich → Cache-Miss bei nächstem Re-Scan-Pfad (akzeptabel). Schema-Forward-Compatibility: falls künftig `scan_hints` benötigt, klare Neueinführung mit Begründung. Fallback-Pfad (`ai_strategy.py:326-329`) nutzt `scan_hints` nicht → unverändert. |
| Priorität | niedrig — Cost-Effekt klein (~$0.6/mo), aber strukturelle Hygiene + KI-Prompt-Klarheit. |

#### 3.4.3 Parallelität
_(noch keine angenommenen Findings)_

#### 3.4.4 Coverage / Signal-Vollständigkeit
_(noch keine angenommenen Findings)_

### 3.5 Phase 1 — Tech-Detection

#### 3.5.1 Tool-Parameter
_(noch keine angenommenen Findings)_

#### 3.5.2 Übergaben

##### F-PH1-003 — Screenshot-Pipeline: nur Viewport, pro IP nur 1 Screenshot im Report

| Feld | Inhalt |
|---|---|
| ID | F-PH1-003 |
| Phase / Stage | Phase 1 (Capture) → Reporter (Embedding) |
| Komponente | Playwright `_take_screenshot` + Reporter `_build_screenshot_data` + Upload-Pipeline |
| Code-Stelle | `scan-worker/scanner/tools/redirect_probe.py:77-95` (Capture); `report-worker/reporter/report_mapper.py:644-676` (Embedding); `scan-worker/scanner/upload.py:38-72` (MinIO pro FQDN); `report-worker/reporter/parser.py:1219-1232` (Aggregation) |
| Dimension | Übergabe / Coverage |
| Beobachtung | Drei gekoppelte Probleme:<br>1. **Capture** (`redirect_probe.py:91`): `full_page=False` → nur Viewport 1280×720, lange Marketing-Sites werden nur im oberen Drittel sichtbar.<br>2. **Persistierung**: pro FQDN eine PNG in MinIO (Code FQDN-aware), aber **Report-Embedding** (`report_mapper.py:672-674`) cappt explizit auf `[paths[0]]` mit veraltetem Comment „multiple FQDNs on the same IP often show the same page". Bei Multi-VHost-Probe (Mai 2026) zeigen verschiedene primary VHosts auf derselben IP echt verschiedene Web-Apps.<br>3. **Tool-Naming-Drift**: CLAUDE.md + `docs/scan-flow/perimeter-single-tld.md` nennen `gowitness`, tatsächlich macht Playwright die Screenshots seit Multi-VHost-Migration. |
| Live-Messung | Customer-Feedback (User-Wunsch in Audit): „mit den Screenshots nicht zufrieden, hätte gerne pro FQDN mit echtem Inhalt einen Screenshot im Report". |
| Entscheidung | **Option A** — vollständiger Fix in drei Schritten:<br><br>**1. Capture (`redirect_probe.py:_take_screenshot`):**<br>• `full_page=True` statt `False`<br>• Viewport `page.set_viewport_size({"width": 1440, "height": 900})` für moderne Desktop-Breite<br>• Pillow-Höhencap 3000px nach Capture:<br>```python<br>from PIL import Image<br>img = Image.open(screenshot_path)<br>if img.height > 3000:<br>    img = img.crop((0, 0, img.width, 3000))<br>    img.save(screenshot_path, optimize=True)<br>```<br><br>**2. Embedding (`report_mapper.py:_build_screenshot_data`):**<br>• `[paths[0]]` → `paths` (alle Screenshots der IP)<br>• Filter: nur Screenshots, deren FQDN in `host_inventory.hosts[*].vhosts[*].fqdn` mit `is_primary=true` enthalten ist (Aliases werden weiterhin nicht eingebunden — sie zeigen via Body-Hash-Dup tatsächlich identische Inhalte)<br><br>**3. Label-Mapping pro Screenshot:**<br>• Während `_take_screenshot` zusätzlich Mapping in `host["screenshot_per_vhost"][fqdn] = screenshot_path` speichern<br>• Im Reporter Label `"<fqdn> (IP)"` statt nur `"<IP> (FQDN1, FQDN2, ...)"` verwenden<br><br>**4. Doku-Update:** CLAUDE.md Phase-1-Tool-Liste `gowitness` → `playwright_screenshot`; gleiches in `docs/scan-flow/perimeter-single-tld.md`. |
| Quelle | Playwright `page.screenshot` Doku https://playwright.dev/python/docs/api/class-page#page-screenshot (2026-05-06); Code-Analyse `redirect_probe.py:77-95`, `report_mapper.py:644-676`, `upload.py:38-72`, `parser.py:1219-1232`; User-Feedback im Audit. |
| Risiko | **PDF-Größe:** mehr Screenshots × full_page → PDF wächst von ~2MB auf 5-10MB. Mitigation: 3000px-Cap + JPEG-Konvertierung (optional). Email-Versand-Limit (10-25MB) bleibt eingehalten. **Storage:** MinIO bereits pro FQDN, Wachstum nur durch full_page-Größe. **Generation-Zeit:** full_page +5-10s pro Host (Scroll + Lazy-Loaded-Content). Phase-1-Gesamt-Last steigt akzeptabel (nmap dominiert weiter). **Determinismus:** Screenshots sind nicht pixelgenau reproduzierbar (Cookie-Banner-Animationen, Anti-Aliasing) — kein Cache-Hash-Effekt (Screenshots fließen nicht in KI-Inputs). |
| Priorität | mittel-hoch — direkter Customer-Confidence-Effekt, deckt benannten User-Pain-Point („alle gesehen"-Wahrnehmung). |

#### 3.5.3 Parallelität

##### F-PH1-002 — wafw00f sequenziell pro VHost

| Feld | Inhalt |
|---|---|
| ID | F-PH1-002 |
| Phase / Stage | Phase 1 — Tech-Detection / wafw00f-Block |
| Komponente | `run_phase1` wafw00f-Inner-Loop |
| Code-Stelle | `scan-worker/scanner/phase1.py:793-807` |
| Dimension | Parallelität |
| Beobachtung | Sequenzielle VHost-Iteration `for vh in vhost_fqdns: res = run_wafw00f(vh, ip, ...)`. Bei `MAX_VHOSTS_PER_HOST=5` × Ø 4s/wafw00f = ~20s pro Host. wafw00f hat keinen eigenen Concurrency-Mechanismus, jeder Aufruf eigener Process. |
| Live-Messung | wafw00f Ø 4.0s, med 1.1s, max 57.8s, n=105. Bei aktueller Test-Umgebung ø 3.5 Calls/Order; Multi-VHost-Customer skaliert das auf ~5/Host. |
| Entscheidung | **Option A**: ThreadPoolExecutor `max_workers=5` für die VHost-Inner-Loop. Speedup bei 5-VHost-Hosts: 20s → 4s. wafw00f-Last pro Run ~10 Probes; 5 parallel ergibt ~12.5 Q/s pro Customer — unter Customer-Authorization unkritisch. **Determinismus**: aktuell wird "erstes Ergebnis der Iteration" als `wafw00f_result` (primary) gewählt; mit ThreadPool muss `as_completed` durch deterministische Sort ersetzt werden — erstes positives Ergebnis nach `vhost_fqdns`-Order via Future-Index-Mapping. `vhost_waf_results`-Dict ist key-basiert, kein Reihenfolge-Effekt. |
| Quelle | wafw00f Repo https://github.com/EnableSecurity/wafw00f (2026-05-06); Code-Analyse `phase1.py:793-807`. |
| Risiko | HTTP-Last steigt auf 12.5 Q/s — innerhalb Customer-Authorization. Determinismus durch deterministische primary-Wahl gewährleistet. Cache: kein Cache betroffen. |
| Priorität | niedrig-mittel — Speedup nur bei Multi-VHost-Hosts spürbar; Phase 1 bleibt durch nmap (Ø 45s) dominiert. |

#### 3.5.4 Coverage / Signal-Vollständigkeit

##### F-PH1-001 — CMS-Fingerprinter: DACH-spezifische und moderne CMS fehlen

| Feld | Inhalt |
|---|---|
| ID | F-PH1-001 |
| Phase / Stage | Phase 1 — Tech-Detection / CMS-Fingerprinter |
| Komponente | `CMS_PROBES`, `META_GENERATOR_PATTERNS`, `COOKIE_CMS_MAP`, `HEADER_CMS_PATTERNS` |
| Code-Stelle | `scan-worker/scanner/cms_fingerprinter.py:100-226` |
| Dimension | Coverage |
| Beobachtung | Aktuelle Coverage ~14 CMS in `CMS_PROBES`, ~10 in `META_GENERATOR`. **Pimcore** (AT, häufig DACH-Industrie) und **Sulu CMS** (DE-Symfony) fehlen vollständig — beide hochrelevant für VectiScan-Zielkundenbasis. Auch globale Standards (Shopify, HubSpot, Webflow) und DACH-Special (Plone, SilverStripe, Statamic) fehlen. KI #2/#3 sieht `cms=null` → Phase 2 läuft mit generischer Tool-Konfig, kein WPScan-Äquivalent für andere CMS. |
| Coverage-Vergleich | Ist ~14 CMS. Soll: + 10 (Pimcore, Sulu, Plone, SilverStripe, Statamic, Webflow, Shopify, HubSpot, Wix, Squarespace) → ~24 CMS. Plus Sekundär: WordPress-Plugin-Pfad-Indikatoren als Confidence-Boost. |
| Entscheidung | **Option B** — manuelle Erweiterung um 10 CMS (4 DACH-Pflicht + 6 global/Markt). Konkrete Patterns:<br><br>**`CMS_PROBES`-Erweiterung:**<br>• Pimcore: `probes ["/admin/login", "/website/"]`, body `pimcore`, `/var/areas/`, `/website/var/assets/`, conf 0.85<br>• Sulu: `probes ["/admin/"]`, body `sulu-website`, `sulu/`, cookie `sulu_admin`, conf 0.85<br>• Plone: `probes ["/@@search"]`, body `plone-`, header `x-powered-by: plone`, conf 0.85<br>• SilverStripe: `probes ["/admin/"]`, body `silverstripe`, `ss-`, conf 0.80<br>• Statamic: `probes ["/cp/login"]`, body `statamic`, conf 0.80<br>• Webflow: body `data-wf-domain`, header `x-powered-by: webflow`, conf 0.85<br>• Shopify: header `x-shopify-stage`, body `Shopify\.theme`, conf 0.90<br>• HubSpot CMS: body `_hsq`, `cdn1\.hubspot\.com`, conf 0.85<br>• Wix: body `Wix\.com`, `static\.wixstatic\.com`, conf 0.85<br>• Squarespace: body `Squarespace\.com`, `static1\.squarespace\.com`, conf 0.85<br><br>**`META_GENERATOR_PATTERNS`-Erweiterung:** entsprechende Generator-Strings für Pimcore/Sulu/Statamic/Webflow/Shopify/HubSpot.<br><br>**Probe-Cap-Mitigation:** CMS_PROBES-Cap (heute 20 HTTP-Reqs laut Baseline §2.8) auf 25 anheben, Early-Exit ab Konfidenz 0.70 unverändert. |
| Quelle | Pimcore Architektur https://pimcore.com/docs/platform/ (2026-05-06); Sulu CMS Doku https://docs.sulu.io/en/2.5/book/getting-started/installation.html (2026-05-06); Plone https://docs.plone.org/manage/installing/installation.html (2026-05-06); Wappalyzer Technologies https://github.com/dochne/wappalyzer/tree/main/src/technologies (2026-05-06, deferred als Sync-Quelle); Code-Analyse `cms_fingerprinter.py:100-226`. |
| Risiko | Probe-HTTP-Requests +10-20 → Cap-Anhebung 20→25 nötig. Early-Exit erhalten → bei klarer Detection (z.B. WordPress) bleiben Probes minimal. KI #2 (CMS-Korrektur) System-Prompt unverändert; neue CMS bekommen keine KI-Korrektur-Override (akzeptabel). Cache: kein Cache-Invalidate. POLICY_VERSION nicht betroffen. |
| Priorität | mittel — direkter Coverage-Hebel auf DACH-Zielkundenbasis (Pimcore/Sulu) und globale Standards. |

### 3.6 KI #2 / KI #3

#### 3.6.1 Tool-Parameter
_(noch keine angenommenen Findings)_

#### 3.6.2 Übergaben
_(noch keine angenommenen Findings)_

#### 3.6.3 Parallelität

##### F-KI3-001 — KI #3 (`plan_phase2_config`) sequenziell pro Host

| Feld | Inhalt |
|---|---|
| ID | F-KI3-001 |
| Phase / Stage | KI #3 — Phase-2-Config |
| Komponente | `plan_phase2_config`-Aufrufer |
| Code-Stelle | `scan-worker/scanner/worker.py:558-572`; `scan-worker/scanner/ai_strategy.py:609-665` |
| Dimension | Parallelität |
| Beobachtung | KI #3 sequenziell pro Host in for-Schleife. Mit Rule-Engine-Hit (`try_rule_based_config`): sub-second. Ohne Match: Haiku Ø 2-3s + Cache-Miss-Penalty. Bei 15 Hosts (perimeter max-hosts) ohne Rule-Match-Anteil: 30-45s sequenziell. |
| Live-Messung | AI-Calls haben `duration_ms=0` in `scan_results` (Library-Calls); Timing in `ai_call_costs.duration_ms`. Strukturelle Worst-Case-Analyse. |
| Entscheidung | **Option A** — `ThreadPoolExecutor(max_workers=5)` für Host-Iteration. Worst-Case fällt von 30-45s auf max(2-3s) pro Welle = ~6-9s. Cache-Hash basiert auf tech_profile pro Host (host_scope=ip), Output-Reihenfolge irrelevant (`adaptive_configs[ip] = ...`-Dict key-basiert). Fehler-Handling: Exception einer Future → andere Hosts unbetroffen. |
| Quelle | Anthropic API Rate-Limits https://docs.anthropic.com/en/api/rate-limits (2026-05-06, Tier-1 50 RPM Haiku, höhere Tiers vermutlich); Code-Analyse `worker.py:558-572`, `ai_strategy.py:609-665`. |
| Risiko | API-Rate-Limit: bei `max_workers=5` × 15 Hosts ohne Rule-Hit = ~3 parallele Wellen × 5 = 15 Calls in ~10s = 90 RPM. Tier-1 (50 RPM) wäre knapp; Tier-2+ (1000 RPM) unproblematisch. Mitigation: Backoff bei 429-Response (vorhanden im Anthropic-SDK). Determinismus: Cache-Hash deterministisch, Dict-Output reihenfolgenunabhängig. |
| Priorität | mittel — Speedup nur bei vielen Hosts ohne Rule-Match spürbar; bei typischer Rule-Engine-Hit-Rate ~70%+ ist Effekt begrenzt. |

#### 3.6.4 Coverage / Signal-Vollständigkeit

##### F-KI2-001 — KI #2 Schema/System-Prompt fehlen DACH-CMS-Erkennungsregeln

| Feld | Inhalt |
|---|---|
| ID | F-KI2-001 |
| Phase / Stage | KI #2 — Tech-Analysis / CMS-Korrektur |
| Komponente | `TECH_ANALYSIS_SYSTEM`, `TECH_ANALYSIS_SCHEMA` |
| Code-Stelle | `scan-worker/scanner/ai_strategy.py:432-463` |
| Dimension | Coverage |
| Beobachtung | Schema (Z. 455) suggeriert Closed-List für `cms`: `"WordPress\|TYPO3\|Shopware\|Joomla\|Drupal\|Exchange\|null"` — KI mappt F-PH1-001-CMS (Pimcore/Sulu/Plone/Craft/Statamic/etc.) ggf. fälschlich auf eines davon oder auf null. System-Prompt hat CMS-spezifische Korrektur-Regeln nur für WordPress/Exchange/TYPO3/Neos — DACH-CMS-Indikatoren fehlen. Drift zwischen Phase-1-Detection und KI-2-Korrektur möglich (Phase 1 erkennt Pimcore korrekt, KI #2 setzt cms=null). |
| Coverage-Vergleich | Ist 6 CMS in Schema-Liste, 4 CMS-spezifische Regeln im System-Prompt. Soll: Open-List-Schema + 5 zusätzliche DACH-CMS-Indikatoren + Phase-1-Bestätigungs-Regel. |
| Entscheidung | **Option B** — Open-List-Schema + Phase-1-Bestätigungs-Regel + DACH-CMS-Indikatoren.<br><br>**Schema-Update:** `cms` als Open-List mit Beispielen statt Closed-List (`"<CMS-Name oder null; Liste nicht abschließend, häufig: WordPress, TYPO3, Shopware, Drupal, Joomla, Pimcore, Sulu, Plone, Craft CMS, Statamic, Contao, NEOS, Ghost, PrestaShop, Magento, Exchange, Webflow, Shopify, HubSpot, Wix, Squarespace>"`).<br><br>**System-Prompt-Erweiterung:**<br>1. Phase-1-Bestätigungs-Regel: „Wenn Phase-1-CMS-Fingerprinter mit Konfidenz ≥0.85 ein CMS gemeldet hat UND keine widersprüchlichen Signale (Redirect, OWA-Title, Fehlerseite) — bestätige die Detection." Defensive gegen KI-Überschreibung.<br>2. DACH-CMS-Indikatoren: Pimcore (`/var/areas/`, `pimcore`-Cookie), Sulu (`sulu_admin`-Cookie, `sulu-website`-Body), Plone (`x-powered-by: plone`, `/@@search`), Craft CMS (`/cpresources/`, `craftcms.com`), Statamic (`/cp/login`, `statamic`-Body). |
| Quelle | F-PH1-001 (CMS-Fingerprinter-Erweiterung); Code-Analyse `ai_strategy.py:432-463`; Pimcore/Sulu/Plone-Detection-Marker aus F-PH1-001 abgeleitet. |
| Risiko | Cache-Invalidation: System-Prompt-Hash ändert sich → Re-Scan-Cache-Miss bei Bestands-Orders, TTL 30 Tage (`CACHE_TTL_TECH_ANALYSIS`), akzeptabel. KI-Output-Variabilität sinkt durch Phase-1-Bestätigungs-Regel (weniger „raten"). Determinismus leicht verbessert. POLICY_VERSION nicht direkt betroffen. |
| Priorität | mittel — direkter Folge-Schritt zu F-PH1-001/F-KI3-002. Ohne diesen Fix gehen F-PH1-001-CMS in KI #2 ggf. verloren. |

##### F-KI3-002 — Rule-Engine: neue CMS aus F-PH1-001 nicht erfasst, kein Static-Hoster-/Hosted-CMS-Branch

| Feld | Inhalt |
|---|---|
| ID | F-KI3-002 |
| Phase / Stage | KI #3 / `try_rule_based_config` |
| Komponente | `try_rule_based_config` |
| Code-Stelle | `scan-worker/scanner/phase2_config_rules.py:24-136` |
| Dimension | Coverage |
| Beobachtung | Generic-CMS-Branch (Z. 124) prüft nur 5 CMS (drupal/typo3/joomla/shopware/magento). Mit F-PH1-001 (10 neue CMS: Pimcore, Sulu, Plone, SilverStripe, Statamic, Webflow, Shopify, HubSpot, Wix, Squarespace) fallen alle in den kein-Match-Pfad → unnötige KI-Calls + Determinismus-Risiko. Static-Hoster (GitHub Pages, Netlify, Vercel, Cloudflare Pages) und Microsoft Exchange/OWA haben kein Match. |
| Coverage-Vergleich | Ist 5 CMS in Generic-Branch, 0 Static-Hoster, kein Hosted-CMS-Branch. Soll: + 5 selbst-gehostete CMS (Pimcore/Sulu/Plone/SilverStripe/Statamic/Contao/NEOS/Craft/Ghost/PrestaShop) im Generic-Branch + neuer Hosted-CMS-Branch (Shopify/Webflow/Wix/Squarespace/HubSpot) + Static-Hoster-Branch. |
| Entscheidung | **Option B** — drei Erweiterungen:<br><br>**1. Generic-CMS-Set erweitern:**<br>```python<br>GENERIC_CMS = {<br>    "drupal", "typo3", "joomla", "shopware", "magento",<br>    "pimcore", "sulu", "plone", "silverstripe", "statamic",<br>    "contao", "neos", "craft cms", "ghost", "prestashop"<br>}<br>```<br><br>**2. Neuer Hosted-CMS-Branch (vor Generic):**<br>```python<br>HOSTED_CMS = {"shopify", "webflow", "wix", "squarespace", "hubspot cms"}<br>if cms in HOSTED_CMS:<br>    return _config(<br>        policy="passive-only", spider_depth=4, ajax=False,<br>        cats=["xss"],  # einzige relevante Klasse für Hosted<br>        rate=30, threads=2,<br>        skip_tools=["zap_active", "feroxbuster", "ffuf", "wpscan", "nikto"],<br>        reason=f"rule:hosted-cms-{cms}",<br>    )<br>```<br><br>**3. Neuer Static-Hoster-Branch (nach Hosted-CMS):**<br>```python<br>STATIC_HOSTERS = (".github.io", ".netlify.app", ".vercel.app",<br>                  ".pages.dev", ".fly.dev", ".surge.sh")<br>if any(primary_fqdn.endswith(p) for p in STATIC_HOSTERS):<br>    return _config(<br>        policy="passive-only", spider_depth=3, ajax=False,<br>        cats=[], rate=30, threads=2,<br>        skip_tools=["zap_active", "feroxbuster", "ffuf", "wpscan", "nikto"],<br>        reason="rule:static-hoster",<br>    )<br>```<br><br>Exchange-Branch (Option C) deferred — KI-Pfad funktioniert dort akzeptabel, separates Folge-Finding falls Probleme. |
| Quelle | F-PH1-001 (CMS-Coverage-Erweiterung); Hosted-CMS-Charakteristik (Shopify/Webflow/Wix/Squarespace machen Server-Härtung selbst, Active-Scans erzeugen 403/429); Code-Analyse `phase2_config_rules.py:24-136`. |
| Risiko | Mehr Rule-Engine-Hits → weniger KI-Calls → Cost-Reduktion (~$0.024/Order × N Hosts). Determinismus-Verbesserung (Rule-basiert 100% reproduzierbar; KI-Output variiert leicht). Static-Hoster-Skip: bei legitimen Web-Apps auf `*.fly.dev` (echte Backend-Anwendungen) verliert Active-Scan — heute kein Override-Mechanismus, separat zu adressieren falls Customer-Beschwerden kommen. |
| Priorität | mittel — direkter Folge-Schritt zu F-PH1-001; sollte zusammen umgesetzt werden, sonst neue CMS aus F-PH1-001 erzeugen unnötige KI-Calls. |

### 3.7 Phase 2 — Deep-Scan (alle Stages)

#### 3.7.1 Tool-Parameter

##### F-PH2-001 — `ffuf_sensitive` Hard-Cap-Hit durch zu große Wordlist

| Feld | Inhalt |
|---|---|
| ID | F-PH2-001 |
| Phase / Stage | Phase 2 / Stage 2 — Sensitive-File-Discovery |
| Komponente | `run_ffuf` mode=`sensitive` |
| Code-Stelle | `scan-worker/scanner/phase2.py:596-624` |
| Dimension | Tool-Parameter / Coverage |
| Beobachtung | Wordlist `raft-medium-files.txt` (17.5k Einträge) bei `-rate 100 -t 60` ergibt 175s Laufzeit. `-maxtime 180` cappt den Run vor vollständiger Wordlist-Abarbeitung — letzte ~500-1000 Einträge werden nicht gefuzzt. |
| Live-Messung | ffuf_sensitive Ø 173.3s, med 171.4s, max 180.1s, n=74 — exakt am Hard-Cap, in nahezu jedem Run. Wordlist zu ~96% ausgeschöpft, Long-Tail abgeschnitten. |
| Entscheidung | **Option A** — Wordlist-Wechsel `raft-medium-files.txt` (17.5k) → `raft-small-files.txt` (10k). Laufzeit fällt auf ~100s, kein Hard-Cap-Hit mehr. Hit-Rate auf hochwertige Sensitive-Files (`.env`, `.git/HEAD`, `backup.zip`, `dump.sql`, `config.php.bak`, `.DS_Store`, `.svn/`) bleibt vergleichbar (raft-small ist Subset mit High-Value-Patterns; Long-Tail von raft-medium wird heute ohnehin durch `-maxtime 180` abgeschnitten). |
| Quelle | SecLists Discovery/Web-Content https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content (2026-05-06, raft-small 10063 Einträge, raft-medium 17751); Live-Mess Baseline §6; Code-Analyse `phase2.py:596-624`. |
| Risiko | Coverage-Verlust geschätzt <2% (raft-medium-Long-Tail wird heute eh abgeschnitten). Determinismus: Wordlist hardcoded. Cache: Output-Normalizer sorgt für stabilen Cache-Hash. |
| Priorität | mittel — eliminiert Hard-Cap-Bottleneck, Phase-2 ~70s schneller pro VHost. |

#### 3.7.2 Übergaben
_(noch keine angenommenen Findings)_

#### 3.7.3 Parallelität
_(noch keine angenommenen Findings)_

#### 3.7.4 Coverage / Signal-Vollständigkeit

##### F-PH2-002 — Phase 2: nuclei + katana implementieren (nikto + dalfox deferred)

| Feld | Inhalt |
|---|---|
| ID | F-PH2-002 |
| Phase / Stage | Phase 2 / Stage 1+2+3 |
| Komponente | Tool-Wrapper-Lücke in `phase2.py` |
| Code-Stelle | `scan-worker/scanner/phase2.py` (kein `run_nuclei` / `run_nikto` / `run_dalfox` / `run_katana`); `scan-worker/Dockerfile:24-30, 69-...` (Tools sind installiert); Baseline §2.11/§6 (dokumentiert) |
| Dimension | Coverage |
| Beobachtung | Vier Tools im Dockerfile gepinnt (nuclei v3.7.1, katana v1.1.3, nikto, dalfox), in Baseline §2.11 + output_normalizer + Tests dokumentiert/referenziert — aber **kein `run_*`-Wrapper im phase2.py-Code, kein Aufruf in `run_phase2`**. Nur `run_testssl`, `run_gobuster_dir`, `run_header_check`, `run_httpx`, `run_wpscan`, `run_ffuf`, `run_feroxbuster`, `run_zap_scan` werden tatsächlich ausgeführt. Live-Mess in Baseline §6 hat keine duration_ms-Werte für die 4 Tools — passt zu „läuft nie". |
| Live-Messung | Bestätigt durch Abwesenheit in Live-Mess-Tabelle (Baseline §6). |
| Entscheidung | **Option B (modifiziert)** — Schritt-weise Implementation, **nuclei und katana zuerst**, **nikto und dalfox deferred** auf TODO-Liste (User-Entscheidung: „da gab es Probleme").<br><br>**Schritt 1: nuclei** (höchster Coverage-Gewinn, ~10k Templates):<br>```python<br>def run_nuclei(fqdn, ip, host_dir, order_id):<br>    cmd = ["nuclei", "-target", f"https://{fqdn}",<br>           "-tags", "cve,exposure,misconfiguration,default-credentials,injection",<br>           "-severity", "critical,high,medium",<br>           "-rl", "100", "-timeout", "5",<br>           "-json", "-o", output_path, "-silent"]<br>```<br>Templates aus `~/.config/nuclei-templates/` (Standard-Pfad). In Stage 3 von `run_phase2` integrieren. Severity-Cap verhindert Info-Findings-Flut. Output via `output_normalizer.normalize_nuclei`.<br><br>**Schritt 2: katana** (entlastet ZAP-Spider, liefert echte URL-Listen für `ffuf_param`):<br>```python<br>def run_katana(fqdn, ip, host_dir, order_id):<br>    cmd = ["katana", "-u", f"https://{fqdn}",<br>           "-jc", "-d", "3", "-c", "10",<br>           "-kf", "all",<br>           "-json", "-o", output_path]<br>```<br>In Stage 3 vor nuclei laufen (liefert URL-Pool); Output ergänzt `katana_urls` für `ffuf_param`-Mode (heute oft mit `katana_urls=None`).<br><br>**Schritt 3+4 deferred (TODO):** nikto + dalfox — Implementation zurückgestellt wegen früherer Probleme. Wandern als deferred-Findings in **Anhang A**. |
| Quelle | nuclei Doku https://docs.projectdiscovery.io/tools/nuclei/usage (2026-05-06); nuclei-templates Repo https://github.com/projectdiscovery/nuclei-templates (2026-05-06, ~10k Templates); katana Doku https://docs.projectdiscovery.io/tools/katana/usage (2026-05-06); Code-Analyse `scan-worker/scanner/phase2.py` (vollständig durchsucht); Dockerfile-Installs Z. 24-30, 69-...; Baseline §2.11/§6. |
| Risiko | **Phase-2-Laufzeit steigt** (nuclei ~100s, katana ~30-60s pro Host) → Mitigation: parallele Stage-Ausführung (nuclei + katana parallel zu ZAP). **Findings-Volumen explodiert** → Severity-Cap auf critical/high/medium, FP-Filter (`fp_filter.py`) um nuclei-Patterns erweitern, Severity-Policy um `SP-NUCLEI-CVE-*`-Regeln ergänzen → **POLICY_VERSION-Bump nötig**. **Reporter-Parser** (`parser.py`) muss um nuclei-Templates+Matchers-Mapping erweitert werden. **Cache-Schema:** Phase-2-Output erweitert → `content_hash` ändert sich → Re-Scan-Cache-Misses akzeptabel. |
| Priorität | **hoch** — größte gefundene Coverage-Lücke des Audits. Pentest-Tool ohne nuclei-Templates verliert CVE-Detection-Coverage massiv gegenüber Mitbewerbern. nuclei + katana sollten Top-Priorität in Roadmap. |

### 3.8 Phase 3 + KI #4

#### 3.8.1 Tool-Parameter
_(noch keine angenommenen Findings)_

#### 3.8.2 Übergaben

##### F-KI4-001 — KI #4 Finding-Truncation `[:100]` ohne Severity-Pre-Sort

| Feld | Inhalt |
|---|---|
| ID | F-KI4-001 |
| Phase / Stage | KI #4 — Cross-Tool-Confidence |
| Komponente | `plan_phase3_prioritization` Truncation + `_build_finding_summary` |
| Code-Stelle | `scan-worker/scanner/ai_strategy.py:864`; `scan-worker/scanner/phase3.py:46-62` |
| Dimension | Übergabe |
| Beobachtung | `summary_truncated = finding_summary[:100]` ohne vorhergehende Sortierung. `_build_finding_summary` erstellt Liste in Korrelator-Cluster-Auftrittsreihenfolge — willkürlich. Bei >100 Findings könnten CRITICAL-CVE in Position 150 KI #4 nie erreichen → kein Confidence-Boost → niedrigere Selection-Priorität im finalen Report. ZAP-Active produziert Ø 50-200 Findings; nach F-PH2-002 (nuclei) sind 200-500 realistisch. |
| Live-Messung | ZAP-Active Ø 105s, max 390s, n=4 — Findings-Volume aus Stichprobe ablesbar. KI #4 selbst hat `duration_ms=0` (Library-Call). |
| Entscheidung | **Option C** — Severity-Pre-Sort + Cap-Erhöhung 100→150 + Critical/High-Guarantee.<br><br>**Implementation:**<br>```python<br># In _build_finding_summary:<br>SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}<br>summary.sort(key=lambda e: (<br>    SEVERITY_RANK.get((e.get("severity") or "info").lower(), 5),<br>    0 if e.get("cve") else 1,<br>    -float(e.get("confidence") or 0),<br>))<br><br># In ai_strategy.py vor Truncation:<br>critical_high = [f for f in finding_summary<br>                 if (f.get("severity") or "").lower() in ("critical", "high")]<br>others = [f for f in finding_summary<br>          if (f.get("severity") or "").lower() not in ("critical", "high")]<br>cap = int(os.environ.get("KI4_FINDING_CAP", "150"))<br>summary_truncated = critical_high + others[:max(0, cap - len(critical_high))]<br>```<br>Sonnet 4.6 Context-Window 200K → +50 Findings × ~80 Tokens = ~4K zusätzliche Input-Tokens, vernachlässigbar gegenüber 24K Output-Limit. |
| Quelle | Anthropic Sonnet 4.6 Context-Window https://docs.anthropic.com/en/docs/about-claude/models (2026-05-07); Code-Analyse `ai_strategy.py:864`, `phase3.py:46-62`. |
| Risiko | Token-Kosten +~$0.012/Call (vernachlässigbar). Determinismus: Severity-Sort deterministisch. Cache-Hash ändert sich → Re-Scan-Cache-Misses akzeptabel (neue Sort-Reihenfolge = neuer Wert). POLICY_VERSION nicht betroffen. |
| Priorität | mittel — direkter Coverage-Effekt bei großen Scans (>100 Findings); wird kritisch nach F-PH2-002. |

#### 3.8.3 Parallelität

##### F-PH3-001 — NVD-Lookup-Batch sequenziell + zu enger `max_lookups`-Cap

| Feld | Inhalt |
|---|---|
| ID | F-PH3-001 |
| Phase / Stage | Phase 3 / Threat-Intel-Anreicherung |
| Komponente | `NVDClient.lookup_batch` + Aufruf in `phase3.py` |
| Code-Stelle | `scan-worker/scanner/correlation/threat_intel.py:119-128`; `scan-worker/scanner/phase3.py:211, 221` |
| Dimension | Parallelität / Tool-Parameter |
| Beobachtung | NVD-Lookup iteriert sequenziell (`for cve_id in cve_ids[:max_lookups]: data = self.lookup_cve(cve_id)`). Pro CVE 1 API-Call. Rate-Limits: ohne API-Key 5 req/30s (6s/CVE), mit Key 50 req/30s (0.6s/CVE). Heute paketabhängig: webcheck `max_lookups=5`, andere `max_lookups=50`. EPSS macht echtes Batching (Z. 219-237) — NVD-API hat keinen Batch-Endpoint, einzige Option ist Parallelisierung. |
| Live-Messung | Phase-3-Tools haben kein direktes `duration_ms`. Strukturelle Worst-Case-Analyse: 50 CVEs × 6s (no key) = 300s; 100 CVEs × 0.6s (key) = 60s. |
| Entscheidung | **Option B + C kombiniert**, mit zusätzlich abgestimmten Werten:<br>**1. Parallelisierung** mit dynamischer Concurrency:<br>```python<br>workers = 5 if os.environ.get("NVD_API_KEY") else 2<br>```<br>**2. 429-Backoff** zwingend implementieren (exponential, max 30s) — ohne Backoff überschreitet `max_workers=5` × 0.6s = 8 RPS das Rate-Limit von 1.67 RPS und triggert 429-Errors nach 50 Calls.<br>**3. `max_lookups`-Cap erhöht:**<br>• non-webcheck: **50 → 100** (deckt 95% real-life-Scans, Worst-Case mit Key ~30-60s)<br>• webcheck: **5 → 10** (Schnellscan-Charakter erhalten)<br>**4. ENV-Override `NVD_MAX_LOOKUPS`** für Edge-Cases (Insurance/Compliance mit hoher CVE-Last → 200/300). Default unset → Paket-Default. |
| Quelle | NVD API Doku https://nvd.nist.gov/developers/vulnerabilities (2026-05-06, Rate-Limits 5/30s ohne Key, 50/30s mit Key); NVD API-Key https://nvd.nist.gov/developers/request-an-api-key (2026-05-06); Code-Analyse `threat_intel.py:119-128, 207-258`, `phase3.py:211, 221`. |
| Risiko | **429-Hits bei fehlendem Backoff** — Backoff zwingend mitkommend. **Cache-Hit-Rate** dämpft Effekt: NVDClient hat 24h-Redis-Cache, Re-Scans treffen 80%+ Cache. **Determinismus**: Output-Dict key-basiert, reihenfolgenunabhängig. **Phase-3-Laufzeit** steigt im Erst-Scan-Fall ~30s, akzeptabel weil Phase 3 nicht zeitkritisch. |
| Priorität | mittel-hoch — wird kritisch nach F-PH2-002 (nuclei → mehr CVE-Findings); heute begrenzt sichtbar weil Phase 2 wenig CVE-Findings liefert. |

#### 3.8.4 Coverage / Signal-Vollständigkeit
_(noch keine angenommenen Findings)_

### 3.9 tar.gz / MinIO + Reporter-Parser

#### 3.9.1 Tool-Parameter
_(noch keine angenommenen Findings)_

#### 3.9.2 Übergaben

##### F-PH9-001 — Screenshots-Upload sequenziell + Bucket-Existence-Check pro Scan

| Feld | Inhalt |
|---|---|
| ID | F-PH9-001 |
| Phase / Stage | tar.gz / MinIO Upload-Pipeline |
| Komponente | `upload_screenshots`, `pack_results`, `upload_to_minio` |
| Code-Stelle | `scan-worker/scanner/upload.py:25-35, 38-73, 76-97` |
| Dimension | Übergabe / Storage |
| Beobachtung | (1) Storage-Redundanz: Screenshots sind in tar.gz UND in separatem `scan-screenshots`-Bucket. (2) `upload_screenshots` sequenziell pro PNG (~200ms × 30 Screenshots = ~6s). (3) `bucket_exists` zwei MinIO-Roundtrips pro Scan in `upload_screenshots` (Z. 51) + `upload_to_minio` (Z. 85). |
| Live-Messung | Upload-Pipeline hat kein direktes `duration_ms`. Strukturelle Worst-Case-Analyse. |
| Entscheidung | **Option B** — Quick-Win ohne Reporter-Architektur-Änderung. Storage-Redundanz akzeptiert für Reporter-Autonomie:<br>1. `upload_screenshots`: `ThreadPoolExecutor(max_workers=10)` für PNG-Loop. 30 PNGs parallel → ~1s.<br>2. Bucket-Existence-Check beim Worker-Start (`worker.py:main`) einmalig prüfen + erstellen, in Modul-State cachen. Pro Scan keine Roundtrips mehr.<br>3. Screenshots bleiben in tar.gz UND separatem Bucket — Reporter-Autonomie unverändert.<br>Storage-Redundanz-Eliminierung (Option A) wird Folge-Schritt nach F-PH1-003 (full_page Screenshots), wenn die tar.gz-Größe real schmerzt. |
| Quelle | MinIO Python SDK Doku https://min.io/docs/minio/linux/developers/python/API.html (2026-05-07); Code-Analyse `scanner/upload.py`. |
| Risiko | MinIO-Client Thread-Safety: pro Worker-Thread eigenen Client instanziieren oder bestehenden Client wenn nicht thread-safe (zu verifizieren in Implementation). Bucket-Cache: bei externem Bucket-Reset Worker-Restart nötig — akzeptabel. Determinismus: Output-Dict key-basiert. |
| Priorität | niedrig-mittel — Speedup ~5s pro Scan, nice-to-have; wird wichtiger nach F-PH1-003. |

#### 3.9.4 Coverage / Signal-Vollständigkeit
_(noch keine angenommenen Findings)_

### 3.10 KI #5 — Reporter

#### 3.10.1 Tool-Parameter
_(noch keine angenommenen Findings)_

#### 3.10.2 Übergaben
_(noch keine angenommenen Findings)_

#### 3.10.3 Parallelität
_(noch keine angenommenen Findings)_

#### 3.10.4 Coverage / Signal-Vollständigkeit
_(noch keine angenommenen Findings)_

### 3.11 Deterministische Reporter-Pipeline

#### 3.11.1 Tool-Parameter

##### F-RPT-006 — `claude_client.call_claude` Smart-Truncation: dead `per_host_cap` + zu enger 120K-Char-Cap

| Feld | Inhalt |
|---|---|
| ID | F-RPT-006 |
| Phase / Stage | Reporter / KI #5 (Sonnet/Opus) / Smart-Truncation in `call_claude` |
| Komponente | `claude_client.call_claude` Truncation-Loop |
| Code-Stelle | `report-worker/reporter/claude_client.py:622-646`; `report-worker/reporter/deterministic_pipeline.py:83-128` (`_writeback_to_claude` preserviert KI-Felder) |
| Dimension | Tool-Parameter |
| Beobachtung | Bei `len(consolidated_findings) > 120_000` Chars (≈30K Tokens) laeuft Smart-Truncation. Code-Comment verspricht "preserve complete host sections, prioritize variety". Tatsaechlich:<br>• Z. 631 `re.split(r'(={50,}[\s\S]*?HOST:)', consolidated_findings)` — splittet nach `===...HOST:`-Trennern.<br>• Z. 635 `per_host_cap = MAX_FINDINGS_CHARS // max(len(host_sections) // 2, 1)` — berechnet Pro-Host-Schranke, **die im nachfolgenden Loop nie verwendet wird**.<br>• Z. 637-644: Loop haengt Sections greedy aneinander, bis `total > MAX_FINDINGS_CHARS`. Letzte passende Section wird gekuerzt + "GEKUERZT"-Marker.<br><br>Reale Wirkung: erste Hosts (alphabetisch / nach Insertion-Reihenfolge des Parsers) bekommen volle Daten, letzte Hosts werden komplett abgeschnitten oder verschwinden. Comment "prioritize variety" ist falsch — keine Variety-Logik existiert. Bei 15 Perimeter-Hosts × ~10K Chars/Host = 150K → ~5 letzte Hosts haben keinen Beitrag zur KI-Narrative.<br><br>Wichtig: post-AI deterministische Pipeline (severity_policy, EOL-Detector, Title-Templates) laeuft unabhaengig — Findings cut-Hosts gehen nicht verloren auf Severity-Ebene. Aber: KI-Beschreibungen, KI-Recommendations, KI-Impact-Texte fuer cut-Hosts fehlen → PDF zeigt deterministische Default-Narrative statt KI-formulierter Begruendung. `_writeback_to_claude` preserviert `description`/`recommendation` aus KI-Output — wenn KI fuer einen Host nichts gesehen hat, bleiben Felder leer/Default. |
| Live-Messung | Strukturell. Wirkung sichtbar bei Compliance/Insurance-Scans mit >10 Hosts. Bei kleineren Scans (1-5 Hosts, je <20K) greift Truncation nie. |
| Entscheidung | **Option D (A + C kombiniert)**: Cap auf 150K Chars heben UND `per_host_cap` korrekt anwenden. Konkrete Aenderung in `claude_client.py:622-646`:<br><br>```python<br># Smart truncation — fairer Round-Robin pro Host, nicht greedy<br>MAX_FINDINGS_CHARS = 150000  # ≈37.5K Tokens, deckt 95% realer Eingaben<br>                              # bei +$0.11/Report Opus-Input (akzeptabel)<br><br>if len(consolidated_findings) > MAX_FINDINGS_CHARS:<br>    log.warning("consolidated_findings_truncated",<br>                original_len=len(consolidated_findings),<br>                truncated_to=MAX_FINDINGS_CHARS,<br>                domain=domain)<br>    host_sections = re.split(<br>        r'(={50,}[\s\S]*?HOST:)', consolidated_findings,<br>    )<br>    # Sections kommen als [pre, delim, body, delim, body, ...]<br>    n_real_hosts = max((len(host_sections) - 1) // 2, 1)<br>    per_host_cap = MAX_FINDINGS_CHARS // n_real_hosts<br><br>    truncated = host_sections[0]  # alles vor erstem HOST:<br>    i = 1<br>    while i < len(host_sections) - 1:<br>        delim = host_sections[i]<br>        body = host_sections[i + 1] if i + 1 < len(host_sections) else ""<br>        section = delim + body<br>        if len(section) > per_host_cap:<br>            section = section[:per_host_cap] + (<br>                "\n--- HOST-DATEN GEKUERZT (Pro-Host-Cap) ---\n"<br>            )<br>        if len(truncated) + len(section) > MAX_FINDINGS_CHARS:<br>            break<br>        truncated += section<br>        i += 2<br>    consolidated_findings = truncated<br>```<br><br>**Begruendung**:<br>• Cap auf 150K (≈37.5K Input-Tokens) deckt 95% realer Eingaben ohne Truncation. Opus 4.6/4.7 hat 200K-Window; nach Reservation fuer System-Prompt (~5K) und max_tokens (16K Output) bleiben ~180K nutzbar — 150K mit Sicherheitsmarge.<br>• Pro-Host-Cap als Round-Robin-Sicherheitsnetz fuer Multi-100-Host-Edge-Cases (alle Hosts bekommen ihren fairen Anteil).<br>• Dead-Code-Comment "preserve complete host sections, prioritize variety" auf realitaetstreues Wording aktualisieren ("equal share per host, drop overflow").<br>• Kein Variety-Heuristik-Aufwand — Severity-gewichtete Truncation (Option B) waere komplexer und liefert nur marginal besseres Ergebnis.<br><br>**Test-Erweiterung**: zwei pytest-Cases:<br>1. `test_truncation_per_host_cap_enforced` — 200K Chars input mit 10 gleich-grossen Host-Sections → jeder Host bleibt ≤15K im Output.<br>2. `test_truncation_skipped_under_cap` — Input <150K bleibt unveraendert (Cap nicht aktiviert). |
| Quelle | Code-Analyse `report-worker/reporter/claude_client.py:622-646`; `report-worker/reporter/deterministic_pipeline.py:83-128`. Anthropic Pricing https://www.anthropic.com/pricing — Abgerufen 2026-05-07. Anthropic Model Context Windows https://docs.anthropic.com/en/docs/about-claude/models — Abgerufen 2026-05-07. |
| Risiko | KI-Input-Kosten steigen ~25% (~$0.11/Report) bei grossen Scans; dafuer vollstaendige KI-Narrative fuer alle Hosts. Cache-Hash aendert sich (Inhalt anders) → einmaliger Cache-Miss bei naechstem Re-Scan jedes Order-Re-Runs, danach stabil. Determinismus unveraendert (post-AI Pipeline unangetastet). Failure-Mode: Cap >170K naehert sich Modell-Output-Reservation → max_tokens-Truncation koennte vermehrt eintreten; bei 150K Cap noch genug Marge. |
| Priorität | mittel — sichtbarer Quality-Effekt bei Compliance/Insurance/SupplyChain-Scans mit >10 Hosts (PDF-Reports mit fehlenden KI-Narratives fuer letzte Hosts). Aufwand klein (2 Konstanten + Loop-Refactor + Comment-Fix, ~25 LOC + 2 Tests). |


#### 3.11.2 Übergaben

##### F-RPT-002 — `selection.consolidate` mergt unterschiedliche Findings desselben `finding_type` falsch zusammen

| Feld | Inhalt |
|---|---|
| ID | F-RPT-002 |
| Phase / Stage | Reporter / Deterministische Pipeline / Konsolidierung über Hosts |
| Komponente | `selection.consolidate` / `_normalized_evidence_hash` / `STABLE_EVIDENCE_KEYS` |
| Code-Stelle | `report-worker/reporter/selection.py:96-124, 140-182`; `report-worker/reporter/eol_detector.py:226-282`; `report-worker/reporter/deterministic_pipeline.py:200-215`; `report-worker/reporter/title_policy.py:148-224` |
| Dimension | Übergabe |
| Beobachtung | `_normalized_evidence_hash` schluesselt nur ueber 4 Felder (`finding_type`, `policy_id`, `cvss_vector`, `stable_evidence` mit 8 Keys). Kritische Differenzierungs-Felder fehlen, mit konkreten Folgen: <br><br>**(1) EOL-Findings**: `eol_detector._build_finding` setzt KEIN `evidence`-Dict → `stable_evidence={}`. Beispiel: Host A mit PHP 5.6, Host B mit Python 2.7 — beide `finding_type=software_eol`, beide matchen SP-EOL-002/003 (je nach `primary_tech`-Flag) mit identischem `cvss_vector` → identischer Hash → falsche Konsolidierung. Title-Template `{tech} {version} ist End-of-Life...` rendert anschliessend mit `title_vars` aus dem ersten Finding; das zweite EOL-System verschwindet still aus dem Report. <br>**(2) SP-DB-001 DB-Port-Exposition**: Port 3306 (MySQL) Host A + Port 5432 (Postgres) Host B → gleicher `finding_type=database_port_exposed`, gleicher `cvss_vector` → konsolidieren falsch. <br>**(3) SP-WP-001 WordPress-Plugin-Vuln**: zwei verschiedene Plugins auf zwei Hosts → falsch gemergt. <br>**(4) SP-JS-001 JS-Library-Vuln**: jQuery 1.x auf Host A + Bootstrap 3.x auf Host B → falsch gemergt. <br>**(5) SP-CSP-005**: dual-representation-Risiko zwischen `evidence.missing_directive` und `title_vars.directive`. <br><br>Tests bestaetigen das Verhalten: `test_selection.py:70-79, 103-109`. Sekundaer-Effekt: `apply_titles` (`deterministic_pipeline.py:208-215`) rendert Title nach Konsolidierung neu und verliert die `(N Hosts betroffen)`-Annotation aus `consolidate`; Multi-Host-Information landet ausschliesslich in `affected_hosts[]` und muss vom PDF-Mapper separat gerendert werden. |
| Live-Messung | Nicht direkt aus §6 messbar — strukturelle Code-Analyse. Auswirkung sichtbar bei jedem Multi-Tech-Host (Insurance/Compliance-Pakete besonders, da Top-N hoeher → mehr Konsolidierungs-Entscheidungen). |
| Entscheidung | **Option C (Hybrid)**: `_normalized_evidence_hash` um `title_vars`-Beitrag erweitern, Coverage parallel zu evidence aufrechterhalten. Konkrete Aenderung in `selection.py:102-124`:<br><br>```python<br>STABLE_TITLE_VARS = (<br>    "port", "tech", "version", "plugin", "library",<br>    "directive", "selector",<br>)<br><br>def _normalized_evidence_hash(finding: dict) -> str:<br>    evidence = finding.get("evidence")<br>    if not isinstance(evidence, dict):<br>        evidence = {}<br>    stable_evidence = {<br>        k: evidence.get(k)<br>        for k in STABLE_EVIDENCE_KEYS<br>        if k in evidence and evidence.get(k) is not None<br>    }<br>    title_vars = finding.get("title_vars") or {}<br>    if not isinstance(title_vars, dict):<br>        title_vars = {}<br>    stable_tv = {<br>        k: str(title_vars.get(k)).strip().lower()<br>        for k in STABLE_TITLE_VARS<br>        if title_vars.get(k) not in (None, "", "?")<br>    }<br>    keypart = {<br>        "finding_type": finding.get("finding_type") or finding.get("type"),<br>        "policy_id": finding.get("policy_id"),<br>        "cvss_vector": finding.get("cvss_vector"),<br>        "evidence": stable_evidence,<br>        "title_vars": stable_tv,<br>    }<br>    serialized = json.dumps(keypart, sort_keys=True, separators=(",", ":"))<br>    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]<br>```<br><br>**Begruendung**:<br>• `STABLE_EVIDENCE_KEYS` bleibt unveraendert — Tools, die evidence-Dicts strukturiert befuellen (ZAP/header-Findings/cookie-Findings), brauchen keine Anpassung.<br>• Neuer `STABLE_TITLE_VARS`-Pfad faengt EOL-Detector-Findings (kein evidence, aber `title_vars`) und alle Templates mit konkreten Differenzierungs-Vars ab.<br>• `.strip().lower()`-Normalisierung minimiert Hash-Drift bei KI-Wording-Variationen ("MySQL" vs "mysql").<br>• Filter `title_vars.get(k) not in (None, "", "?")` stellt sicher, dass das `?`-Sicherheitsnetz aus `title_policy.py` nicht zur Hash-Diskriminierung beitraegt (zwei Findings mit fehlender Var sollen weiterhin konsolidieren).<br><br>**Test-Erweiterung**: zwei neue pytest-Cases in `test_selection.py`:<br>1. `test_eol_different_tech_not_consolidated` — software_eol mit `title_vars.tech="php"` vs `tech="python"` → 2 Gruppen.<br>2. `test_db_port_different_ports_not_consolidated` — database_port_exposed mit `title_vars.port="3306"` vs `port="5432"` → 2 Gruppen.<br><br>**Sekundaer-Issue (verbunden, nicht eigenes Finding)**: die `(N Hosts betroffen)`-Annotation, die `consolidate` an den Title haengt, geht durch `apply_titles` verloren. Wird im Rahmen dieses Fixes mitnotiert: `apply_title_template` koennte den Suffix wiederherstellen, wenn `affected_hosts` >1 ist. Wenn das jetzt nicht mit umgesetzt werden soll, als Folge-Finding aufgreifen sobald Konsolidierung korrekt arbeitet (sonst dupliziert sich der Effekt). |
| Quelle | Code-Analyse `report-worker/reporter/selection.py:96-124, 140-182`; `report-worker/reporter/eol_detector.py:226-282`; `report-worker/reporter/deterministic_pipeline.py:200-215`; `report-worker/reporter/title_policy.py:148-224, 236-329`; Tests `report-worker/tests/test_selection.py:60-110`. Kein Web-Lookup noetig (interner Logik-Bug). |
| Risiko | Cache-Invalidierung bei Re-Scans bestehender Orders, weil `consolidation_groups`-Wert (in `selection_stats`) sich aendert; Determinismus-KPI (Migration 024) zeigt voraussichtlich fuer 1-2 Re-Scans einen Drift-Score, danach stabil. Keine POLICY_VERSION-Bump noetig (Konsolidierungs-Logik liegt unterhalb der Policy-Schicht). FP-Rate sinkt (mehr getrennte Findings, keine faelschlich kombinierten). KI-Cache nicht betroffen (Konsolidierung ist post-AI). |
| Priorität | **hoch** — direkter Reporter-Quality-Fehler bei Multi-Tech-Hosts; betrifft Insurance- und Compliance-Pakete besonders (Top-N 15-20 → mehr Konsolidierungs-Entscheidungen); EOL-Findings aus F-RPT-001 wuerden ohne diese Korrektur weiterhin falsch zusammengelegt. |

##### F-RPT-007 — `eol_detector.merge_into_claude_findings` Dedup versagt bei Claude-Findings ohne `host_ip`

| Feld | Inhalt |
|---|---|
| ID | F-RPT-007 |
| Phase / Stage | Reporter / Deterministische Pipeline / EOL-Detector → Claude-Merge |
| Komponente | `eol_detector.merge_into_claude_findings` Dedup-Schluessel |
| Code-Stelle | `report-worker/reporter/eol_detector.py:370-402`, `:226-282`; `report-worker/reporter/deterministic_pipeline.py:155-170`; `report-worker/reporter/title_policy.py:41` (`_VERSION_RE`-Pattern als Vorlage) |
| Dimension | Übergabe |
| Beobachtung | Dedup-Key ist `(host_ip, finding_type, version)` aus `title_vars.version`. Claude-Findings haben aber haeufig **kein** `host_ip`-Feld — KI sieht nur den consolidated_findings-Text mit FQDN/affected, nicht den vollen Phase-0b-Inventar. Typisch setzt KI `affected="example.com:80"` oder `host="example.com"`, nicht `host_ip="1.2.3.4"`. <br><br>**Konkrete Fehl-Faelle**: <br>1. Claude-Finding ohne host_ip (Apache-EOL fuer `example.com` mit `host_ip=""`); EOL-Detector findet exakt dasselbe via tech_profile mit `host_ip="1.2.3.4"` und `fqdns=["example.com"]`. Keys: `("", "software_eol", "2.2")` vs `("1.2.3.4", "software_eol", "2.2")` → mismatch → kein Dedup → **DOPPEL-Finding** im Report (einmal mit KI-Beschreibung, einmal mit eol_detector-Default-Beschreibung). <br>2. Claude-Finding ohne `title_vars.version` (z.B. "Veraltete Apache-Version" ohne explizite Version im title_vars-Dict): key=(ip, "software_eol", ""). EOL-Detector hat exakte Version. Keys: `(ip, "software_eol", "")` vs `(ip, "software_eol", "2.2")` → mismatch → Doppel-Finding. <br>3. Mehrere Claude-Findings ohne host_ip kollidieren im dict-build (Z. 384-385 `by_key[key] = f` ueberschreibt bei Kollision); Edge-Case ohne direkten Output-Effekt, weil `merged = list(claude_findings or [])` alle behaelt — `by_key` ist nur Lookup. <br><br>**Real-World-Haeufigkeit**: KI #5 produziert `host_ip` selten (System-Prompt liefert tech_profiles als JSON, in `host_inventory.hosts[]` steckt `ip`-Feld — KI sieht es, kopiert es aber nicht zuverlaessig in Output-Findings). Bei FQDN-basierten Scans (Mehrheit der Customer-Orders) entstehen regelmaessig EOL-Doppel-Findings bei kritischen EOL-Software (Exchange, Apache, OpenSSL, PHP, Windows-Server). <br><br>**Title-Templates** rendern beide Doppel-Findings identisch (`SP-EOL-001..004`), aber `description`/`recommendation` unterscheiden sich (KI-Text vs eol_detector-Default). |
| Live-Messung | Strukturell. Wirkung sichtbar in PDF-Reports mit zwei EOL-Findings fuer dasselbe Tech-Stack auf demselben Host. |
| Entscheidung | **Option D (A + C kombiniert)**: Host-Resolution + Version-Recovery aus Title. Konkrete Aenderung in `eol_detector.py:370-402`:<br><br>```python<br>def merge_into_claude_findings(<br>    claude_findings: list[dict[str, Any]],<br>    eol_findings: list[dict[str, Any]],<br>    *,<br>    tech_profiles: list[dict[str, Any]] | None = None,<br>) -> list[dict[str, Any]]:<br>    # ip_to_fqdn-Map aus tech_profiles aufbauen (FQDN-only Claude-Findings)<br>    ip_to_fqdn: dict[str, str] = {}<br>    fqdn_to_ip: dict[str, str] = {}<br>    for tp in tech_profiles or []:<br>        ip = tp.get("ip", "")<br>        fqdns = tp.get("fqdns") or []<br>        if ip and fqdns:<br>            ip_to_fqdn[ip] = fqdns[0].lower()<br>            for fq in fqdns:<br>                fqdn_to_ip[fq.lower()] = ip<br><br>    def _normalize_host(f: dict) -> str:<br>        # Bevorzugt fqdn > host > host_ip; alle Eintraege zur Primary-FQDN-Form<br>        fqdn = (f.get("fqdn") or f.get("host") or "").lower().strip()<br>        host_ip = f.get("host_ip") or ""<br>        if not fqdn and host_ip in ip_to_fqdn:<br>            fqdn = ip_to_fqdn[host_ip]<br>        if fqdn:<br>            return fqdn<br>        return host_ip<br><br>    def _extract_version(f: dict) -> str:<br>        # Erst title_vars.version, dann Title-Regex-Fallback<br>        tv = f.get("title_vars") or {}<br>        if isinstance(tv, dict) and tv.get("version"):<br>            return str(tv["version"])<br>        title = f.get("title") or ""<br>        m = re.search(r"\b(\d+(?:\.\d+){1,3}(?:[a-z]\d?)?)\b", title)<br>        return m.group(1) if m else ""<br><br>    by_key: dict[tuple, dict] = {}<br>    for f in claude_findings or []:<br>        key = (_normalize_host(f), f.get("finding_type", ""), _extract_version(f))<br>        by_key[key] = f<br><br>    merged = list(claude_findings or [])<br>    added = 0<br>    for ef in eol_findings:<br>        key = (_normalize_host(ef), ef.get("finding_type", ""), _extract_version(ef))<br>        if key in by_key:<br>            by_key[key]["_deterministic_source"] = ef.get(<br>                "_deterministic_source", "eol_detector",<br>            )<br>            continue<br>        merged.append(ef)<br>        added += 1<br>    if added:<br>        log.info("eol_detector_added_to_findings count=%d", added)<br>    return merged<br>```<br><br>Plus Aenderung in `deterministic_pipeline.py:163-165` — `tech_profiles` weiterreichen:<br>```python<br>findings_in = merge_into_claude_findings(<br>    findings_in, eol_findings, tech_profiles=tech_profiles,<br>)<br>```<br><br>**Begruendung**:<br>• `_normalize_host` resolved Claude-FQDN-Findings auf gleichen Identifier wie EOL-Detector-Findings (die sowohl `host_ip` als auch `fqdn` haben).<br>• `_extract_version` faengt Edge-Case 2 ab (KI-Title "Apache 2.2 ist EOL" ohne explizites title_vars.version-Feld).<br>• `tech_profiles` als optionaler Parameter — bei leerem Inventar (Edge-Case fehlerhafter Parse) Fallback auf direkten host/fqdn/host_ip-Vergleich.<br>• Kein Eingriff in EOL-Detector-Output-Schema.<br><br>**Test-Erweiterung**: drei pytest-Cases:<br>1. `test_merge_dedup_with_fqdn_only_claude_finding` — Claude-Finding mit `host="example.com"` ohne host_ip; EOL-Finding mit beiden Feldern → 1 merged Finding.<br>2. `test_merge_recovers_version_from_title` — Claude-Finding ohne title_vars.version aber Title="Apache 2.2 ist EOL" → version="2.2" abgeleitet → Dedup greift.<br>3. `test_merge_no_tech_profiles_falls_back` — `tech_profiles=None` → bisheriges Verhalten. |
| Quelle | Code-Analyse `report-worker/reporter/eol_detector.py:226-282, 370-402`; `report-worker/reporter/deterministic_pipeline.py:155-170`; Version-Regex-Vorlage `report-worker/reporter/title_policy.py:41`. Kein Web-Lookup noetig (interner Logik-Bug). |
| Risiko | Reduzierte Doppel-Findings → Selection waehlt andere Top-N-Reihenfolge (weniger redundante EOL-Findings, mehr Diversitaet in Top-N) → Determinismus-Drift einmalig 1-2 Re-Scans, danach stabil. KI-Cache nicht betroffen (post-AI). Edge-Case: wenn `tech_profiles` leer (z.B. fehlerhafter Parse), Fallback auf bisheriges Verhalten (kein Regression). FP-Rate sinkt (keine Doppel-Eintraege fuer dieselbe EOL-Software). |
| Priorität | mittel-hoch — direkter Reporter-Quality-Effekt (keine Doppel-EOL-Findings), wirkt zusammen mit F-RPT-002 (Konsolidierung) auf Multi-Tech-Hosts; bei FQDN-basierten Scans (Mehrheit) regelmaessig auftretend. |

##### F-RPT-005 — QA-Check `_check_severity_evidence` läuft VOR severity_policy → wirkungsloser Cap mit irreführendem Audit-Log

| Feld | Inhalt |
|---|---|
| ID | F-RPT-005 |
| Phase / Stage | Reporter / Worker-Pipeline-Reihenfolge / Übergabe QA-Check ↔ severity_policy |
| Komponente | `qa_check._check_severity_evidence` + `_apply_auto_fixes` (severity_capped-Auto-Fix) ↔ `severity_policy.apply_policy` |
| Code-Stelle | `report-worker/reporter/worker.py:467-492`; `report-worker/reporter/qa_check.py:172-248, 444-500`; `report-worker/reporter/severity_policy.py:1012-1106`; `report-worker/reporter/deterministic_pipeline.py:135-241` |
| Dimension | Übergabe |
| Beobachtung | In `worker.py:469` laeuft `run_qa_checks` mit `_apply_auto_fixes`, das `_check_severity_evidence` ausfuehrt: HIGH/CRITICAL-Findings ohne CVE und ohne CVSS≥7.0 ODER Findings die regex-Patterns wie `veraltete?.software`, `oeffentlich.erreichbar`, `fehlende?.security.header`, `weak.cipher`, `server.banner`, `eol`, `end.of.life` matchen, werden auf MEDIUM (CVSS 5.3) gecappt — mit `auto_fix=True` direkt an der Finding-Severity. Auf Zeile 476-478 wird ein `severity_capped`-Log-Event mit `old`/`new`/`reason` geschrieben. <br><br>Direkt danach (`worker.py:484`) laeuft `apply_deterministic_pipeline` → `severity_policy.apply_policy` (`severity_policy.py:1012-1106`): Fuer jedes Finding mit erkanntem `finding_type` (≈95% nach finding_type_mapper-Regex + AI-Fallback aus F-RPT-004) wird `policy.final_severity` gesetzt — ueberschreibt die QA-gecappte Severity. <br><br>**Beispielfaelle**: <br>• "Exchange Server 2016 ist End-of-Life" → QA cappt HIGH→MEDIUM (Pattern `eol`/`end.of.life`); SP-EOL-001 (`tech="exchange"`) setzt HIGH zurueck. Audit-Log: wirkungslos. <br>• "WordPress 4.5 mehrere Major-Versionen hinter" → QA cappt; SP-EOL-004 setzt HIGH zurueck. <br>• "Datenbank-Port 3306 oeffentlich erreichbar" → QA cappt HIGH→MEDIUM (Pattern `oeffentlich.erreichbar`); SP-DB-001 setzt HIGH zurueck. <br>• "Server-Banner mit Version" → QA cappt; SP-DISC-001 setzt INFO (geringer als QA-Cap, also QA-Cap ohnehin obsolet). <br>• "Veraltete Apache-Software 2.2" → QA cappt HIGH→MEDIUM; SP-EOL-003 setzt MEDIUM (deckt sich, kein effektiver Override). <br><br>**Determinismus-Implikation**: das Audit-Feld `severity_provenance.tool_severities` (severity_policy.py:1057) speichert `original_severity` aus dem Finding — das ist die QA-modifizierte Severity, NICHT die urspruengliche KI-Severity. Folge: das Provenance-Audit zeigt Tool-Severity = "medium" auch wenn die KI urspruenglich "high" gesagt hat (weil QA dazwischen modifiziert hat). Verzerrt Forensik-Tiefe in `scripts/diff-orders.py`. <br><br>**Nettowirkung**: <br>• Findings MIT `policy_id` (≈95%): QA-Cap ist redundant, Audit-Log irrefuehrend. <br>• SP-FALLBACK-Findings (≈5%, Mapper hat keine Zuordnung): QA-Cap steht, einziger tatsaechlicher Wirkbereich → Sicherheitsnetz fuer nicht-policy-abgedeckte KI-Halluzinationen. |
| Live-Messung | Strukturell — kein direkter §6-Bezug. Wirkung primaer in Audit-Log-Klarheit und Forensik-Tiefe; reale Severities aendern sich nur fuer SP-FALLBACK-Findings. |
| Entscheidung | **Option A1 (QA-Check NACH severity_policy mit SP-FALLBACK-Filter)**: Severity-Evidence-Cap aus dem ersten QA-Lauf ausgliedern und gezielt nur auf SP-FALLBACK-Findings nach der Policy-Anwendung anwenden. Konkrete Aenderung:<br><br>**1. `qa_check.py`**: `_check_severity_evidence` aus der Standard-Check-Liste in `run_qa_checks` herausnehmen (oder Parameter `apply_severity_cap=False` einfuehren). Restliche QA-Checks (CVSS, CWE, duplicates, required_fields, EPSS, NIS2, CWE-semantic) bleiben in der ersten Phase.<br><br>**2. `worker.py:467-492`**: nach `apply_deterministic_pipeline` und vor `_recalculate_overall_risk` einen neuen Helper aufrufen:<br><br>```python<br># -- 4b. Report QA — programmatic checks (ohne severity-evidence-Cap) ---<br>qa_report = run_qa_checks(<br>    claude_output, package=package, enrichment=enrichment,<br>    apply_severity_cap=False,<br>)<br>...<br># -- 4c. Deterministische Pipeline ----<br>apply_deterministic_pipeline(claude_output, ...)<br><br># -- 4d. Severity-Cap NUR fuer SP-FALLBACK-Findings ----<br>fallback_findings = [<br>    f for f in claude_output.get("findings", [])<br>    if (f.get("policy_id") or "") == "SP-FALLBACK"<br>]<br>if fallback_findings:<br>    cap_issues = _check_severity_evidence(fallback_findings)<br>    cap_fixes = _apply_auto_fixes(<br>        {"findings": fallback_findings}, cap_issues,<br>    )<br>    if cap_fixes:<br>        log.info("severity_cap_applied_to_fallback",<br>                 count=cap_fixes,<br>                 total_fallback=len(fallback_findings))<br><br># -- 4e. Recalculate overall_risk after QA + Policy + Fallback-Cap --<br>_recalculate_overall_risk(claude_output)<br>```<br><br>**3. Provenance-Erhaltung**: weil der Cap jetzt NACH severity_policy laeuft, sollte das Finding ein zusaetzliches Audit-Feld `_qa_cap_applied=True` bekommen, damit `severity_provenance` und das `_qa_cap_applied`-Flag zusammen die volle Audit-Geschichte transportieren (KI → SP-FALLBACK → QA-Cap).<br><br>**Begruendung**:<br>• Audit-Log enthaelt keine wirkungslosen `severity_capped`-Events mehr (nur die ~5% wo der Cap tatsaechlich greift).<br>• severity_policy bleibt unangetastet — Determinismus der Policy-Schicht garantiert.<br>• Sicherheitsnetz fuer SP-FALLBACK-Halluzinationen erhalten.<br>• `severity_provenance.tool_severities` zeigt jetzt die KI-Original-Severity (weil QA nicht mehr vorher modifiziert) → Forensik-Diff vollstaendiger.<br>• `_recalculate_overall_risk` sieht weiterhin die finalen Severities. |
| Quelle | Code-Analyse `report-worker/reporter/worker.py:467-492`; `report-worker/reporter/qa_check.py:172-248, 444-500`; `report-worker/reporter/severity_policy.py:1012-1106`; `report-worker/reporter/deterministic_pipeline.py:135-241`. Kein Web-Lookup noetig (interner Reihenfolge-Bug). |
| Risiko | Audit-Log-Klarheit verbessert (keine wirkungslosen `severity_capped`-Events mehr); FP-Rate fuer SP-FALLBACK-Findings unveraendert; Determinismus unveraendert (Cap-Logik gleich, nur Anwendungs-Scope eingeschraenkt); KI-Cache nicht betroffen. Severity-Provenance-Felder werden um eine Ebene reichhaltiger (`tool_severities` zeigt KI-Original statt QA-modifizierten Wert) — `scripts/diff-orders.py --policy-ids` kann jetzt zwischen "KI sagte X, Policy sagte Y" und "KI sagte X, Fallback-Cap reduzierte auf Y" unterscheiden. |
| Priorität | niedrig-mittel — kein direkter Output-Quality-Hebel (95% der Findings unveraendert), aber Audit-/Forensik-/Determinismus-Hygiene + reduzierte Verwirrung beim Lesen von `scripts/diff-orders.py`-Outputs. Aufwand klein (~30 LOC + 1-2 Tests). |

#### 3.11.3 Parallelität

##### F-RPT-004 — `finding_type_mapper` AI-Fallback-Loop sequenziell

| Feld | Inhalt |
|---|---|
| ID | F-RPT-004 |
| Phase / Stage | Reporter / Deterministische Pipeline / finding_type-AI-Fallback |
| Komponente | `finding_type_mapper.annotate_finding_types` AI-Fallback-Loop |
| Code-Stelle | `report-worker/reporter/finding_type_mapper.py:382-393`; `report-worker/reporter/ai_finding_type_fallback.py:125-229` |
| Dimension | Parallelität |
| Beobachtung | Wenn der Regex-Mapper kein finding_type findet, sammelt `annotate_finding_types` die betroffenen Findings in `needs_ai`-Liste und iteriert anschliessend **sequenziell** durch `map_finding_type_via_ai` (Haiku-Call). Pro Call: Cache-Hit ~10 ms (Redis), Cache-Miss 1–3 s (Haiku Live-Call mit `max_tokens=200`, `temperature=0.0`). Cache-TTL 30 Tage, Namespace `reporter_v1_finding_type_fallback`, Cache-Key basiert auf `content_hash` ueber normalisierten Title+Description+CWE — hoch deterministisch. <br><br>Realistischer Per-Scan-Aufwand: bei kalter Cache (neue Vendor-Strings, neue Title-Wordings, frische POLICY_VERSION-Bumps die Cache invalidieren) koennen 5–20 Findings den AI-Fallback brauchen; sequenziell = 5–60 s zusaetzliche Reporter-Latenz. Bei warmem Cache typisch 1–3 Findings × ~10 ms = vernachlaessigbar. |
| Live-Messung | Nicht direkt im Baseline §6 vermerkt (Reporter-interner Pfad, Library-Call ohne `duration_ms`-Persistenz). Strukturelle Code-Analyse + Anthropic-API-Latenz-Profil (Haiku Median ~800 ms, P95 ~2 s). |
| Entscheidung | **Option A (ThreadPoolExecutor max_workers=5)**: AI-Fallback-Loop parallelisieren, ~15 LOC Aenderung in `finding_type_mapper.py:382-393`:<br><br>```python<br>if use_ai_fallback and needs_ai:<br>    try:<br>        from reporter.ai_finding_type_fallback import map_finding_type_via_ai<br>        from concurrent.futures import ThreadPoolExecutor<br>        with ThreadPoolExecutor(max_workers=5) as ex:<br>            futs = {ex.submit(map_finding_type_via_ai, f): f for f in needs_ai}<br>            for fut in futs:<br>                f = futs[fut]<br>                try:<br>                    ai_type = fut.result(timeout=10)<br>                except Exception:<br>                    ai_type = None<br>                if ai_type:<br>                    f["finding_type"] = ai_type<br>                    f["_finding_type_source"] = "ai_fallback"<br>    except Exception as e:<br>        import logging<br>        logging.getLogger(__name__).warning(<br>            "ai_fallback_unavailable err=%s", e)<br>```<br><br>**Begruendung**:<br>• Concurrency-Cap 5 schont Anthropic-Rate-Limits (Haiku Tier-1: 50 RPM = 0.83 req/s; max_workers=5 × 1 s Latenz = 5 req/s — bleibt unter Limit; SDK-Retry/Backoff bereits aktiv bei 429).<br>• Per-Future-Timeout 10 s verhindert haengende Reporter-Pipeline bei API-Stillstand.<br>• Determinismus unveraendert: jede Mutation an einem eigenen Finding-Dict, kein Shared-State.<br>• Anthropic Python-SDK ist threadsafe (`anthropic.Anthropic`-Client kann concurrent benutzt werden — neuer Client pro Call wegen `os.environ.get()` ist ohnehin pro Aufruf instanziiert).<br>• Cache-Lookup und Live-Call laufen im selben Thread pro Future → kein Cache-Doppelschreib-Risiko; Anthropic-SDK kann unabhaengig vom Cache parallelisieren. |
| Quelle | Code-Analyse `report-worker/reporter/finding_type_mapper.py:382-393`; `report-worker/reporter/ai_finding_type_fallback.py:125-229`. Anthropic Rate-Limits https://docs.anthropic.com/en/api/rate-limits — Abgerufen 2026-05-07. Anthropic SDK (Python, Concurrent Calls) https://docs.anthropic.com/en/api/client-sdks#python — Abgerufen 2026-05-07. |
| Risiko | Rate-Limit-Drift bei mehreren parallelen Report-Worker-Instanzen (Mitigation: SDK-Backoff aktiv, max_workers konservativ 5); Cache-Determinismus unveraendert (Reads/Writes pro Finding eigene Schluessel); Failure-Mode: einzelner Future-Timeout fuehrt zu None fuer dieses Finding → SP-FALLBACK statt KI-Fallback (akzeptabel, gleiches Verhalten wie heute bei API-Fehler). Kosten unveraendert (gleiche Anzahl Calls). |
| Priorität | niedrig-mittel — Wirkung primaer bei Cold-Cache-Szenarien (neue Customer-Reports, POLICY_VERSION-Bumps, Title-Template-Aktualisierungen); bei warmem Cache marginal. Aufwand minimal (~15 LOC). |

#### 3.11.4 Coverage / Signal-Vollständigkeit

##### F-RPT-003 — `business_impact._classify_finding` matcht nur englische Keywords gegen deutsche KI-Narratives

| Feld | Inhalt |
|---|---|
| ID | F-RPT-003 |
| Phase / Stage | Reporter / Deterministische Pipeline / business_impact-Recompute |
| Komponente | `business_impact._classify_finding` / `PACKAGE_WEIGHTS` / `RANSOMWARE_PORTS` |
| Code-Stelle | `report-worker/reporter/business_impact.py:79-122, 32-50, 52`; Pipeline-Reihenfolge `report-worker/reporter/deterministic_pipeline.py:185-219` |
| Dimension | Coverage |
| Beobachtung | `_classify_finding` matcht ausschliesslich englische Keywords (`encryption`, `authentication`, `default`, `credential`, `exposure`, `disclosure`, `access`, `authorization`, `permission`, `database`, ...) gegen `title + description`. Reporter (Sonnet/Opus) generiert aber deutsche Narratives — `description` ist mehrere Absaetze deutsch, `title` ebenfalls deutsch (KI-Original; Title-Templates greifen erst NACH `business_impact.recompute` in Pipeline-Reihenfolge). Konsequenz: Package-Weights fuer `insurance` (rdp_smb 2.0, default_login 1.8, encryption 1.3), `compliance` (encryption 1.5, access_control 1.3, logging 1.3), `supplychain` (api_security 1.5, authentication 1.5, data_exposure 1.3) werden bei deutschen Narratives systematisch unterschritten → niedrigere business_impact_scores → falsche Top-N-Reihenfolge. <br><br>Konkrete Beispiel-Luecken: "Verschluesselung", "Zertifikat" (encryption), "Standardzugangsdaten", "Werkseinstellung" (default_login), "Zugriff", "Berechtigung", "Autorisierung", "Privileg", "Umgehung" (access_control), "Authentifizierung", "Anmeldung", "Sitzung" (authentication), "Offenlegung", "Preisgabe", "Datenleck", "vertraulich", "Datenbank", "sensibel" (data_exposure), "Remoteverbindung", "Fernwartung", "Fernzugriff" (rdp_smb), "Protokollierung", "Ueberwachung" (logging). <br><br>Zusatz-Beobachtung: `RANSOMWARE_PORTS = {3389, 445, 139, 5900, 5985, 5986}` deckt typische Vektoren ab — **Telnet 23** und **VNC alt 5800** fehlen (Telnet ist Insurance-relevant, OT/Legacy-Verbreitung, mehrfach in CISA-KEV-Listen 2024-2026). |
| Live-Messung | Strukturelle Code-Analyse — direkter Effekt sichtbar bei jedem Insurance/Compliance/SupplyChain-Report mit deutschem Reporter-Output (= gesamte aktuelle Kundenbasis). |
| Coverage-Vergleich | Ist 8 Kategorien × ~5 englische Keywords = ~40 Keywords + 6 Ransomware-Ports. Soll: deterministisches `policy_id`-Mapping (60+ Eintraege parallel zu `SEVERITY_POLICIES`) + 2 zusaetzliche Ports (23, 5800). Sprach-Coverage wird nicht ueber Keyword-Erweiterung sondern ueber Architektur-Wechsel geloest. |
| Entscheidung | **Option B (policy_id-Mapping)**: Keyword-Match in `_classify_finding` durch deterministisches Policy-ID-Lookup ersetzen. Konkrete Aenderung in `business_impact.py:79-122`:<br><br>```python<br>POLICY_ID_TO_CATEGORIES: dict[str, set[str]] = {<br>    # Header / Encryption-Hardening<br>    "SP-HDR-001": {"encryption"}, "SP-HDR-002": {"encryption"},<br>    "SP-HDR-003": {"encryption"}, "SP-HDR-004": {"encryption"},<br>    "SP-HDR-005": set(), "SP-HDR-006": {"access_control"},<br>    "SP-HDR-007": set(), "SP-HDR-008": set(),<br>    "SP-HDR-009": {"encryption"},<br>    # CSP<br>    "SP-CSP-001": {"access_control"}, "SP-CSP-002": {"access_control"},<br>    "SP-CSP-003": {"access_control"}, "SP-CSP-004": {"access_control"},<br>    "SP-CSP-005": {"access_control"},<br>    # Cookies<br>    "SP-COOK-001": {"encryption"}, "SP-COOK-002": {"access_control"},<br>    "SP-COOK-003": {"access_control"}, "SP-COOK-004": {"encryption", "authentication"},<br>    "SP-COOK-005": {"access_control", "authentication"},<br>    # CSRF<br>    "SP-CSRF-001": {"access_control", "authentication"},<br>    "SP-CSRF-002": {"access_control"}, "SP-CSRF-003": {"access_control"},<br>    # Disclosure<br>    "SP-DISC-001": set(), "SP-DISC-002": set(),<br>    "SP-DISC-003": {"data_exposure"}, "SP-DISC-004": {"data_exposure"},<br>    "SP-DISC-005": {"data_exposure"}, "SP-DISC-006": {"data_exposure"},<br>    "SP-DISC-007": {"data_exposure"}, "SP-DISC-008": {"data_exposure"},<br>    "SP-DISC-009": {"data_exposure"},<br>    # TLS<br>    "SP-TLS-001": {"encryption"}, "SP-TLS-002": {"encryption"},<br>    "SP-TLS-003": {"encryption"}, "SP-TLS-004": {"encryption"},<br>    "SP-TLS-005": {"encryption"}, "SP-TLS-006": {"encryption"},<br>    "SP-TLS-007": {"encryption"},<br>    # DNS / Mail-Auth<br>    "SP-DNS-001": {"encryption"}, "SP-DNS-002": {"encryption"},<br>    "SP-DNS-003": {"encryption"},<br>    "SP-DNS-004": {"authentication"}, "SP-DNS-005": {"authentication"},<br>    "SP-DNS-006": {"authentication"}, "SP-DNS-007": {"authentication"},<br>    "SP-DNS-008": {"authentication", "encryption"},<br>    "SP-DNS-009": {"authentication"}, "SP-DNS-010": {"authentication"},<br>    # CVE — KEV-Pfade hoechstes Risiko<br>    "SP-CVE-001": {"encryption", "access_control"},<br>    "SP-CVE-002": {"access_control"}, "SP-CVE-003": {"access_control"},<br>    "SP-CVE-004": {"access_control"},<br>    # EOL — meistens Daten-/Encryption-Risiko<br>    "SP-EOL-001": {"data_exposure", "encryption", "access_control"},<br>    "SP-EOL-002": {"data_exposure", "access_control"},<br>    "SP-EOL-003": {"data_exposure", "access_control"},<br>    "SP-EOL-004": {"access_control"},<br>    # WordPress / User-Enum<br>    "SP-WP-001": {"access_control"}, "SP-WP-002": {"data_exposure"},<br>    "SP-ENUM-001": {"data_exposure"},<br>    # Database-Port<br>    "SP-DB-001": {"data_exposure", "default_login"},<br>    # CORS / JS / SRI / SSH<br>    "SP-CORS-001": {"access_control", "api_security"},<br>    "SP-JS-001": {"access_control"},<br>    "SP-SRI-001": {"access_control"},<br>    "SP-SSH-001": {"default_login", "access_control"},<br>    # Fallback bei unbekanntem policy_id<br>    "SP-FALLBACK": set(),<br>}<br><br>def _classify_finding(finding: dict) -> set[str]:<br>    categories: set[str] = set()<br>    # Primaer: policy_id (deterministisch, sprachunabhaengig)<br>    pid = (finding.get("policy_id") or "").strip()<br>    if pid in POLICY_ID_TO_CATEGORIES:<br>        categories |= POLICY_ID_TO_CATEGORIES[pid]<br>    # Sekundaer: Port-basierte rdp_smb-Erkennung (orthogonal zu policy_id)<br>    port = finding.get("port")<br>    if port:<br>        try:<br>            if int(port) in RANSOMWARE_PORTS:<br>                categories.add("rdp_smb")<br>        except (ValueError, TypeError):<br>            pass<br>    return categories<br><br>RANSOMWARE_PORTS = {3389, 445, 139, 5900, 5985, 5986, 23, 5800}<br>```<br><br>**Begruendung**:<br>• Determinismus: 100% reproduzierbar, Sprache irrelevant — egal ob Reporter Deutsch, Englisch oder Spanisch generiert.<br>• Maintenance-Aufwand parallel zu severity_policy: bei neuen `policy_id`-Eintraegen MUSS Mapping mitgepflegt werden — durchsetzbar via Test, der jedes `SEVERITY_POLICIES`-Eintrag mit `POLICY_ID_TO_CATEGORIES` cross-checkt (Fail bei Luecken).<br>• Pipeline-Reihenfolge bleibt unveraendert (`severity_policy` setzt `policy_id`, dann `business_impact.recompute` liest `policy_id`).<br>• `RANSOMWARE_PORTS` um 23 (Telnet) und 5800 (VNC alt) erweitern — aus CISA-KEV abgeleitete Insurance-Relevanz.<br><br>**Test-Erweiterung** in `report-worker/tests/test_business_impact.py` (oder neu): <br>1. `test_policy_id_categories_complete` — jeder `policy_id` aus `SEVERITY_POLICIES` ist auch in `POLICY_ID_TO_CATEGORIES` (verhindert silent gaps bei neuen Regeln).<br>2. `test_classify_finding_via_policy_id` — Findings mit `policy_id="SP-DB-001"` und `policy_id="SP-CVE-001"` bekommen die erwarteten Kategorien.<br>3. `test_ransomware_ports_includes_telnet_vnc_old` — 23 und 5800 in der Konstante.<br>4. `test_classify_finding_no_keyword_dependency` — Finding mit deutschem Title/Description aber bekanntem policy_id liefert dieselben Kategorien wie Finding mit englischem Text. |
| Quelle | Code-Analyse `report-worker/reporter/business_impact.py:79-122, 32-50, 52`; Pipeline-Reihenfolge `report-worker/reporter/deterministic_pipeline.py:185-219`; Severity-Policy-Liste `report-worker/reporter/severity_policy.py:114-770`; CISA KEV (Telnet/VNC-Eintraege) https://www.cisa.gov/known-exploited-vulnerabilities-catalog — Abgerufen 2026-05-07. |
| Risiko | Score-Drift bei Re-Scans bestehender Insurance/Compliance/SupplyChain-Orders — `business_impact_score`-Werte aendern sich → Top-N-Reihenfolge aendert sich → Determinismus-KPI (Migration 024) zeigt Drift fuer 1-2 Re-Scans, danach stabil. KI-Cache nicht betroffen (business_impact ist post-AI). Severity-Policy-Cache nicht betroffen. Performance: Dict-Lookup statt 8 substring-Schleifen → leichter Performance-Gewinn (vernachlaessigbar). FP-Rate unveraendert (Klassifikation bestimmt nur Score-Multiplikator, nicht Severity). |
| Priorität | mittel — relevant fuer DACH-Customer-Reports (= aktuelle Kundenbasis); Wirkung auf Insurance/Compliance/SupplyChain Top-N-Reihenfolge; Severity-Hebel niedriger als F-RPT-001 (KNOWN_VULN_BUILDS) und F-RPT-002 (Konsolidierung), aber strukturell sauber und erhoeht Determinismus. |

##### F-RPT-001 — `KNOWN_VULN_BUILDS` Coverage: nur 5 historische Mega-Schwachstellen, OSV-Sync-Aufbau

| Feld | Inhalt |
|---|---|
| ID | F-RPT-001 |
| Phase / Stage | Reporter / EOL-Detector / KNOWN_VULN_BUILDS |
| Komponente | `KNOWN_VULN_BUILDS`-Dict, `_version_starts_with`-Matcher, `_normalize_vendor_product`-Vendor-Mapping |
| Code-Stelle | `report-worker/reporter/eol_detector.py:137-155` (Daten); `:158-215` (Matcher + Normalisierung) |
| Dimension | Coverage |
| Beobachtung | KNOWN_VULN_BUILDS hat 5 Build→CVE-Mappings (2014–2021): ProxyShell, ProxyLogon, Heartbleed, Apache-CVE-2021-41773, Apache-CVE-2021-42013. Mega-Schwachstellen 2022–2026 mit eindeutigen Banner-Markern fehlen komplett (Apache-Smuggling, nginx mp4-Module, Confluence/GitLab/TeamCity/PHP-CGI/Citrix-Bleed/MOVEit). KNOWN_VULN_BUILDS ist Pflicht-Finding-Hook VOR `finding_type_mapper` — Phase-3-Threat-Intel hilft nicht, weil sie nur CVEs anreichert, die bereits als Findings existieren. Bei reinem Banner-Match ohne Tool-Finding ist KNOWN_VULN_BUILDS der einzige Trigger. EOL-Confidence-kritisch (User-Begründung: „bei exponierter EOL-Software ist HIGH immer berechtigt"). |
| Coverage-Vergleich | Ist 5 Build-Mappings (alle ≥4 Jahre alt). Soll: Initial-Liste +15-20 manuelle Entries (2022-2026), plus laufender Sync gegen OSV-DB für continuous Coverage. |
| Entscheidung | **Option E** — Combined Approach mit OSV als Hauptquelle:<br><br>**1. Initial-Liste (~20 Manual-Entries):** Bootstrap mit allen relevanten 2022-2026 Mega-Schwachstellen als sofort wirksame Coverage:<br>• Apache httpd: CVE-2023-25690 (≤2.4.55), CVE-2024-38476 (<2.4.60)<br>• nginx: CVE-2022-41741/41742 (1.5.7–1.23.1)<br>• Atlassian Confluence: CVE-2023-22515 (8.0.0–8.5.1)<br>• GitLab: CVE-2023-7028 (16.1.0–16.7.1)<br>• JetBrains TeamCity: CVE-2024-27198 (<2023.11.4)<br>• PHP-CGI: CVE-2024-4577 (Windows, <8.3.8)<br>• Citrix NetScaler: CVE-2023-4966 (Citrix Bleed)<br>• Progress MOVEit: CVE-2023-34362 (≤2023.0.6)<br>• Plus weitere ~10 (Fortinet, Ivanti, ScreenConnect, weitere Exchange-CUs, WS_FTP)<br><br>**2. Sync-Skript `scripts/sync-known-vuln-builds.py`** gegen OSV-API:<br>• Endpoint: `POST https://api.osv.dev/v1/query` mit Vendor/Product-Filter<br>• OSV liefert structured `affected.ranges.events: [{introduced, fixed}]` — direkt nutzbar für Range-Matching<br>• Filter: CISA-KEV-Listing **oder** EPSS >0.7 **oder** CVSS ≥9.0<br>• Vendor/Product-Normalisierung über `_normalize_vendor_product`-Logik (erweitert)<br>• Server-Software-Ecosystem-Filter (excludes npm/pip/gem/maven)<br>• Output: structured `KNOWN_VULN_BUILDS`-Format mit `version_range` statt nur `version`<br>• gefilterte Datei `scan-worker/data/known_vuln_builds.json`, beim Worker-Start geladen<br><br>**3. Range-Matcher erweitern** in `eol_detector.py`:<br>• Heute `_version_starts_with` nur Prefix-Match<br>• Neu: Range-Vergleich (`<=`, `>=`, `<`, `>`) für OSV-Range-Events<br>• Backwards-kompatibel: alte Dict-Einträge ohne `version_range` nutzen Prefix-Match<br><br>**4. GitLab-Job `known-vuln-builds-sync`** analog `eol-data-sync` (Wochen-Schedule + manueller Trigger).<br><br>**5. POLICY_VERSION-Bump** beim ersten Rollout.<br><br>**Realistic Eingriff-Umfang:** ~600 LOC + 2-3 Tage Implementation. Bestehendes `KNOWN_VULN_BUILDS`-Schema bleibt dict-basiert (backwards-kompatibel), Wert-Struktur erweitert sich um `version_range`. Keine DB-Migration. Kein Eingriff in Pipeline-Reihenfolge. |
| Quelle | OSV API https://google.github.io/osv.dev/api/ (2026-05-07); OSV Schema https://ossf.github.io/osv-schema/ (2026-05-07); CISA KEV https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (2026-05-07); GHSA https://github.com/github/advisory-database (2026-05-07); Apache HTTP CVEs https://httpd.apache.org/security/vulnerabilities_24.html (2026-05-07); nginx Advisories https://nginx.org/en/security_advisories.html (2026-05-07); Code-Analyse `eol_detector.py:137-155, 158-215`. |
| Risiko | **Severity-Drift**: mehr CRITICAL-Findings → POLICY_VERSION-Bump, deterministisch handhabbar. **Range-Matching-Edge-Cases**: Build-Strings wie `2.4.59-RHEL-1.el9_4` (Distro-Backports) — Mitigation: Strip von `-`-Suffix beim Vendor-Match + Hinweis im Finding-Beschreibung „bei Distro-Backports Vendor-Status prüfen". **Sync-Datei-Größe**: gefilterte OSV-Entries für Server-Software ~500-1000, JSON ~2-5 MB; Worker-Image-Größe steigt minimal. **Determinismus**: gepinnte Sync-Datei im Worker-Image, reproduzierbar bis zum nächsten Sync. |
| Priorität | **hoch** — direkter Severity-Hebel; EOL-Confidence-Kritisch (User-Statement: bei exponierter EOL-Software ist HIGH-Severity immer berechtigt); Reporter-Quality bei Banner-Match-Funden deutlich höher; laufende Maintenance via Sync. |

---

## 4. Übergreifende Themen

### 4.1 Output-Normalizer-Coverage

##### F-XS-001 — Output-Normalizer fehlen für 4 Phase-2-Schluesseltools (testssl, ffuf, katana, feroxbuster)

### 4.2 Cache-Architektur-Symmetrie

##### F-XS-002 — `content_hash`-Cache-Modus bei KI #2 und KI #3 nicht genutzt (asymmetrisch zu KI #1)

### 4.3 Maintained-Listen-Sync-Strategie

##### F-XS-003 — Vier Sync-pflichtige Datenquellen ohne Shared-Helper → Code-Drift-Risiko

| Feld | Inhalt |
|---|---|
| ID | F-XS-003 |
| Phase / Stage | Übergreifend / Wartung / Maintained-Listen-Sync |
| Komponente | Sync-Skripte + GitLab-Jobs fuer EOL (existiert), Cloud-Provider-Ranges (F-PRE-003), Takeover-Provider (F-P0B-006), KNOWN_VULN_BUILDS/OSV (F-RPT-001) |
| Code-Stelle | `scripts/sync-eol-data.py` (existiert); `.gitlab-ci.yml:eol-data-sync`-Job (existiert); geplante Skripte aus F-PRE-003 (`scripts/sync-cloud-ranges.py`), F-P0B-006 (`scripts/sync-takeover-list.py`), F-RPT-001 (`scripts/sync-known-vuln-builds.py`) |
| Dimension | Übergabe (Maintenance-Pattern) |
| Beobachtung | Aus dem Audit ergeben sich vier Sync-pflichtige Datenquellen, die mit dem etablierten EOL-Sync-Pattern parallel laufen sollten:<br>• **EOL-Daten** (existiert): `scripts/sync-eol-data.py` → `report-worker/reporter/eol_data_generated.py`, GitLab-Job `eol-data-sync`, Auto-Commit per CI-Bot.<br>• **Cloud-Provider-Ranges** (F-PRE-003): pflegt `_STATIC_RANGES` in `scan-worker/scanner/precheck/saas_heuristic.py:15-46`.<br>• **Subdomain-Takeover-Provider** (F-P0B-006): EdOverflow's `can-i-take-over-xyz`, pflegt Takeover-Indikator-Set in `scan-worker/scanner/phase0.py:30-117`.<br>• **KNOWN_VULN_BUILDS** (F-RPT-001): OSV-DB + CISA-KEV + GHSA, pflegt `report-worker/reporter/eol_detector.py:137-155` plus generierte Datei.<br><br>Aktueller EOL-Sync hat etablierte Building-Blocks, die fuer drei neue Skripte direkt wiederverwendbar waeren: HTTP-Fetch + Retry, JSON/YAML/Text-Parsing, Atomic-Write, `git diff --quiet`-Check, CI-Bot-Auto-Commit mit `[skip ci]`-Marker, Schedule-vs-manual-Trigger via GitLab-Variable, Failure-Mode (allow_failure: true).<br><br>**Risiken bei drei separaten Implementierungen**:<br>1. Code-Drift: jedes Skript pflegt eigene HTTP/Retry/Parse-Logik → Bug-Fixes muessen 4× repliziert werden.<br>2. CI-Bot-Auth-Drift: Push-Token-Management 4× konfiguriert → unterschiedliche Schreib-Permissions.<br>3. Atomic-Write-Drift: bei einem Skript vergessen → halb-synchronisiertes generated-File in Production moeglich.<br>4. Schedule-Drift: vier separate GitLab-Schedules zu pflegen, fehlende Schedules werden still vergessen.<br>5. Validation-Drift: jedes Skript prueft anders, ob das Sync-Ergebnis sinnvoll ist (Mindest-Anzahl Eintraege, Schema-Validitaet). |
| Live-Messung | Strukturell — kein direkter §6-Bezug. Wirkung sichtbar erst bei Maintenance-Aufwand der drei vorgeschlagenen neuen Sync-Pipelines. |
| Entscheidung | **Option A + D kombiniert** — Shared-Helper-Lib fuer Python-Code + GitLab-Job-Template fuer CI-Boilerplate.<br><br>**(A) Shared-Helper-Modul `scripts/_sync_lib.py`** (~200 LOC) extrahiert HTTP-Fetch, Retry, Atomic-Write, Git-Diff-Check, CI-Commit-Pattern in wiederverwendbare Bausteine:<br><br>```python<br># scripts/_sync_lib.py<br>def fetch_with_retry(<br>    url: str, *, retries: int = 3, timeout: int = 30,<br>    headers: dict | None = None,<br>) -> str: ...<br><br>def atomic_write_python_module(<br>    target_path: Path, *, header: str, data_name: str,<br>    data_dict: dict[Any, Any], dict_type_hint: str,<br>) -> None: ...<br><br>def has_git_changes(path: Path) -> bool: ...<br><br>def commit_and_push_if_changed(<br>    path: Path, *, commit_message: str,<br>    bot_email: str = "ci-bot@vectiscan.local",<br>    bot_name: str = "VectiScan CI Bot",<br>) -> bool: ...<br><br>def validate_min_entries(<br>    data: dict | list, *, min_count: int, source_name: str,<br>) -> None: ...<br>```<br><br>**Pilot-Refactor**: bestehendes `sync-eol-data.py` als ersten Konsumenten umbauen (Output-File-Hash vor/nach Refactor identisch — Verhaltens-Garantie). Dann F-PRE-003 / F-P0B-006 / F-RPT-001-PRs nutzen die Lib direkt — pro neues Skript nur ~80-120 LOC quelle-spezifisch.<br><br>**(D) GitLab-Job-Template** als YAML-Anchor in `.gitlab-ci.yml`:<br><br>```yaml<br>.sync-job-template: &sync-job-template<br>  stage: ops<br>  tags: [vectigal]<br>  rules:<br>    - if: $CI_PIPELINE_SOURCE == "schedule" && $SYNC_ENABLED == "true"<br>    - if: $CI_PIPELINE_SOURCE == "web"<br>      when: manual<br>      allow_failure: true<br><br>eol-data-sync:<br>  <<: *sync-job-template<br>  script:<br>    - python3 scripts/sync-eol-data.py<br>    - python3 scripts/_sync_commit.py report-worker/reporter/eol_data_generated.py<br><br>cloud-ranges-sync:<br>  <<: *sync-job-template<br>  script:<br>    - python3 scripts/sync-cloud-ranges.py<br>    - python3 scripts/_sync_commit.py scan-worker/data/cloud_ranges_generated.json<br><br># Analog fuer takeover-list-sync und known-vuln-builds-sync<br>```<br><br>**Begruendung**:<br>• A allein adressiert Code-Drift in Python-Skripten; D allein adressiert CI-Drift im YAML.<br>• Kombination spart bei drei neuen Sync-Skripten ~400 LOC und vier separate Schedule-Konfigurationen werden zu einem einheitlichen Pattern.<br>• Reihenfolge: zuerst `_sync_lib.py` als Pilot mit `sync-eol-data.py`-Refactor (kein neues Verhalten), dann GitLab-Anchor, dann pro F-PRE-003 / F-P0B-006 / F-RPT-001-PR ein neues Sync-Skript auf der Lib.<br>• `_sync_commit.py` als CLI-Wrapper um `commit_and_push_if_changed` reduziert YAML-Boilerplate weiter (statt 15 Zeilen Bash pro Job → 1 Python-Aufruf).<br><br>**Test-Erweiterung**: pro Helper-Funktion ein pytest-Case in `scripts/tests/test_sync_lib.py`:<br>1. `test_fetch_with_retry_handles_429` — exponential backoff bei Rate-Limit.<br>2. `test_atomic_write_no_partial_file` — Crash mid-write hinterlaesst kein halb-synchronisiertes File.<br>3. `test_has_git_changes_detects_diff` — Stub-Diff-Setup im tempdir.<br>4. `test_validate_min_entries_raises_below_threshold` — Sync-Validation-Gate. |
| Quelle | Code-Analyse `scripts/sync-eol-data.py`; `.gitlab-ci.yml` (`eol-data-sync`-Job); Folge-Findings F-PRE-003, F-P0B-006, F-RPT-001; CLAUDE.md (Determinismus-Block, Cleanup-Skript-Pattern). Kein Web-Lookup noetig (interner Pattern-Match). |
| Risiko | Einmaliger Refactor des EOL-Skripts ohne Verhaltens-Aenderung (Output identisch); Test mit Generated-File-Hash-Vergleich vor/nach Pilot-Refactor. Drei neue Sync-Skripte profitieren direkt; Maintenance-Aufwand sinkt langfristig. Failure-Mode unveraendert (allow_failure: true). Bei Bug im Shared-Helper sind alle 4 Skripte betroffen — Mitigation: Test-Coverage und Pilot-Phase. |
| Priorität | niedrig-mittel — kein direkter Output-Quality-Hebel, aber strukturelle Voraussetzung fuer Wartbarkeit der drei vorgeschlagenen Sync-Pipelines (F-PRE-003, F-P0B-006, F-RPT-001). Aufwand vor allem im EOL-Refactor (Pilot); spart bei jedem nachfolgenden Sync-Skript Aufwand und Drift-Risiko. |

| Feld | Inhalt |
|---|---|
| ID | F-XS-002 |
| Phase / Stage | Übergreifend / Cache-Architektur / KI #2 + KI #3 (Haiku) |
| Komponente | `ai_strategy.plan_tech_analysis` (KI #2), `ai_strategy.plan_phase2_config` (KI #3) — Cache-Mode-Asymmetrie zu KI #1 |
| Code-Stelle | `scan-worker/scanner/ai_strategy.py:304-311` (KI #1, MIT content_hash); `:506-512` (KI #2, OHNE content_hash); `:673-680` (KI #3, OHNE content_hash); `scan-worker/scanner/ai_cache.py:50-119` (3-Modi-Cache) |
| Dimension | Übergabe (Cache-Determinismus) |
| Beobachtung | 3-Modi-Cache (`content_hash` > `order_scope` > `input_hash`) ist nur fuer KI #1 (`plan_host_strategy`) komplett genutzt. KI #2 (`plan_tech_analysis`) und KI #3 (`plan_phase2_config`) uebergeben nur `order_scope` + impliziten `input_hash`, **kein** `content_hash` → Order-uebergreifende Cache-Hits fuer identische Tech-Profile sind unmoeglich. <br><br>**Konsequenzen**: <br>• KI #2 (CMS-Korrektur): tech_profiles[] + redirect_data Input. Zwei verschiedene Orders mit identischen Tech-Profilen (z.B. derselbe Customer scannt subdomain1.example.com und subdomain2.example.com — beide WordPress, beide selber Server) → keine Cache-Hits zwischen den Orders. Re-Scans 1 Monat spaeter → derselbe Cache-Miss. <br>• KI #3 (Phase-2-Config): per Host. C1 Rule-Engine faengt eindeutige Faelle ab (gut), aber wenn KI gerufen wird (no rule match), kein Order-uebergreifender Cache. Identische Hosts in zwei Orders → 2× Haiku-Calls. <br>• KI #1 funktioniert schon korrekt (content_hash ueber `domain + package + hosts + dns_findings`). <br><br>**Kosten-Impact moderat**: Haiku $1/$5 per 1M Tokens → ~$0.003 pro Call. Bei 30 Re-Scans/mo + 5 Hosts/Order → 150 KI-#3-Calls/mo Verluste = ~$0.45/mo. Klein. <br><br>**Determinismus-Effekt wichtiger als Kosten**: identische Inputs sollen IMMER identische Outputs liefern. Order-Scope-Only-Cache verfehlt den Kerngedanken des Determinismus-Blocks (`docs/deterministic/03-ai-determinism.md`). |
| Live-Messung | Strukturell. Cache-Hit-Quoten in `ai_call_costs`-Tabelle (Migration 022) wuerden bestaetigen — niedrige content_hash-Hit-Rate fuer ki2_tech_analysis und ki3_phase2_config Namespaces erwartet. |
| Entscheidung | **Option A (KI #2 + KI #3 symmetrisch)** — `content_hash` bei beiden ergaenzen, analog KI #1:<br><br>```python<br># KI #2 (plan_tech_analysis) — Z. 506-512<br>from scanner.ai_cache import compute_content_hash<br>ch = compute_content_hash(<br>    json.dumps(tech_profiles_summary, sort_keys=True, ensure_ascii=False),<br>    json.dumps(redirect_data, sort_keys=True, ensure_ascii=False),<br>)<br>result = _call_haiku(<br>    TECH_ANALYSIS_SYSTEM, user_prompt,<br>    cache_namespace="ki2_tech_analysis",<br>    cache_ttl_seconds=CACHE_TTL_TECH_ANALYSIS,<br>    order_scope=order_id or None,<br>    order_id=order_id,<br>    content_hash=ch,<br>)<br><br># KI #3 (plan_phase2_config) — pro Host, Z. 673-680<br>ch = compute_content_hash(<br>    json.dumps(enriched_profile, sort_keys=True, ensure_ascii=False),<br>    package,<br>)<br>result = _call_haiku(<br>    PHASE2_CONFIG_SYSTEM, user_prompt,<br>    cache_namespace="ki3_phase2_config",<br>    cache_ttl_seconds=CACHE_TTL_PHASE2_CONFIG,<br>    order_scope=order_id or None,<br>    host_scope=ip or None,<br>    order_id=order_id,<br>    content_hash=ch,<br>)<br>```<br><br>**Begruendung**:<br>• Symmetrisch zur bereits etablierten KI-#1-Architektur — Determinismus-Konsistenz.<br>• Order-Scope bleibt als Sekundaer-Cache erhalten (regenerate-report-Pfad).<br>• `content_hash` ueber sortierte JSON-Inputs — stabil bei identischen Tech-Profilen ueber Orders hinweg, mitprofitiert von Output-Normalizer-Stabilitaet (F-XS-001).<br><br>**Test-Erweiterung**: pro KI ein neuer pytest-Case in `scan-worker/tests/test_ai_strategy.py`:<br>1. `test_ki2_tech_analysis_content_hash_cache_hit_across_orders` — zwei Calls mit identischen tech_profiles aber verschiedenen order_id → 2. Call ist Cache-Hit.<br>2. `test_ki3_phase2_config_content_hash_cache_hit_across_orders` — analog. |
| Quelle | Code-Analyse `scan-worker/scanner/ai_strategy.py:268-348` (KI #1 als Vorlage), `:466-525` (KI #2), `:609-720` (KI #3); `scan-worker/scanner/ai_cache.py:50-119` (3-Modi-Cache); CLAUDE.md (Determinismus-Block AI-Cache-Modi). Kein Web-Lookup noetig. |
| Risiko | Cache-Hit-Quote steigt fuer Re-Scans und Multi-Order-Setups; Determinismus-KPI verbessert; Cache-Volumen in Redis waechst minimal (+~30% mehr Keys, weil content_hash-Keys zusaetzlich zu order_scope-Keys gespeichert werden — Redis-Disk-Bedarf vernachlaessigbar). Failure-Mode: bei kompletter Cache-Disk-Drift bleibt content_hash als Order-cross-cutting Sicherheitsnetz. Kein Eingriff in KI-Output-Schema oder downstream-Konsumer. |
| Priorität | mittel — Determinismus-Vollstaendigkeit > direkter Kosten-Hebel; symmetrische Architektur zum bereits etablierten KI-#1-Pfad. |

| Feld | Inhalt |
|---|---|
| ID | F-XS-001 |
| Phase / Stage | Übergreifend (Phase 1 + Phase 2 + Reporter-Cache) |
| Komponente | `output_normalizer._NORMALIZERS` |
| Code-Stelle | `scan-worker/scanner/output_normalizer.py:307-347`; Aufrufer `scan-worker/scanner/tools/__init__.py:365-394`; 3-Modi-Cache `report-worker/reporter/claude_client.py:683-715` |
| Dimension | Übergabe (Cache-Determinismus) |
| Beobachtung | `_NORMALIZERS` deckt 8 Tools ab: `httpx`, `wafw00f`, `dnsx`, `nmap`, `zap`(+3 Aliase), `nuclei`, `nikto`, `wpscan`. <br><br>Tools OHNE Normalizer mit relevanter Volatilitaet (Cache-Hash-Drift-Risiko): <br>**Hoch-Impact (Phase 2 Hauptbeitraege zu consolidated_findings)**: <br>• `testssl` — Phase 1 (TLSCompliance) + Phase 2; Timestamps in JSON, Run-IDs, runtime-counters → KI-Cache invalidiert bei jedem Re-Run trotz identischem Cipher-Profil. <br>• `ffuf` — Phase 2 sensitive-paths; `time` pro Request, `resultfile`-Path mit Run-ID, Reihenfolge variiert. <br>• `katana` — Phase 2 crawl; `timestamp` pro Endpoint, Crawl-Order variiert. <br>• `feroxbuster` — Phase 2 directory-enum; Timestamps, Discovery-Order variiert. <br>**Mittel-Impact**: dalfox (deferred F-PH2-002-DEFERRED-2), subfinder, gobuster_dns. <br>**Niedrig-Impact**: crtsh/certspotter, whois, shodan/abuseipdb/securitytrails (separater Phase-0a-Cache, bereits sortiert). <br>**Kein Impact**: cms_fingerprinter (interne Library, deterministisch by design). <br><br>**Konsequenz**: KI-Cache-Architektur hat 3 Modi (`content_hash` > `order_scope` > `input_hash`). `content_hash` ist die wertvollste Order-uebergreifende Reproduzierbarkeit, gehasht ueber `consolidated_findings + tech_profiles + host_inventory`. Wenn testssl/ffuf/katana ihre Volatilitaet via Parser in `consolidated_findings` durchschlagen, ist content_hash unbrauchbar → Cache-Miss bei jedem Re-Scan trotz identischer Server-Antworten. Reporter (KI #5) trifft das doppelt — Cache-Prefix M2 deckt nur `static_prefix` (host_inventory + tech_profiles) ab, der `variable_suffix` (consolidated_findings) drift bei Volatilitaet → voller Input-Preis bei jedem Re-Run. |
| Live-Messung | Indirekt aus `ai_call_costs`-Tabelle (Migration 022) messbar ueber Cache-Hit-Quoten. Strukturell: Phase 2 enthaelt 4 von 7 Tools ohne Normalizer; testssl ist alleine fuer TLSCompliance-Paket der Hauptbeitrag. |
| Coverage-Vergleich | Ist 8 Tools (5 Phase-Tools + 3 Cache-Aliase fuer ZAP). Soll: +4 Phase-2-Tools (testssl, ffuf, katana, feroxbuster) → 12 Tools (oder 9 distinct Normalizer-Funktionen). |
| Entscheidung | **Option A (vier Priorität-1-Normalizer)** — adressiert die groessten Cache-Drift-Quellen, Phase-2-Tools mit hoechstem Beitrag zu consolidated_findings:<br><br>**1. `normalize_testssl`** (~40 LOC) — JSON-Output, strippt:<br>• Top-Level: `Invocation`, `at`, `version`, `openssl`, `runtime`-Felder<br>• Per-section: `id` (Run-ID), `cve`-Listen sortieren alphabetisch<br>• Cipher-Listen: alphabetisch nach `cipher_name` sortieren<br>• Output: `json.dumps(data, indent=2, sort_keys=True)`<br><br>**2. `normalize_ffuf`** (~25 LOC) — JSON-Output, strippt:<br>• Top-Level: `time`, `resultfile`, `commandline`, `config.commandline`, `config.outputfile`<br>• `results[]`: nach `url` alphabetisch sortieren, je `time` und `host` (variiert) entfernen<br><br>**3. `normalize_katana`** (~30 LOC) — JSON-Lines, strippt:<br>• Pro Zeile: `timestamp`, `request.timestamp`, `response.timestamp`<br>• Zeilen alphabetisch nach `endpoint`/`url` sortieren<br><br>**4. `normalize_feroxbuster`** (~25 LOC) — JSON-Lines mit Discovery-Output:<br>• Pro Zeile: `timestamp`, `wildcard`<br>• Zeilen alphabetisch nach `url`<br><br>Plus Eintraege im `_NORMALIZERS`-Dict. Total: ~150 LOC + 4 Tests.<br><br>**Reihenfolge**: testssl zuerst (TLSCompliance-Paket lebt davon), dann ffuf/katana/feroxbuster.<br><br>**Folgeschritt** (nicht in dieser PR): Phase-0a/0b-Tools (subfinder, gobuster_dns, dalfox bei Aktivierung) als Option C aufgreifen, sobald A im Betrieb messbar Cache-Hit-Quoten verbessert. |
| Quelle | Code-Analyse `scan-worker/scanner/output_normalizer.py:307-347`; `scan-worker/scanner/tools/__init__.py:365-394`; `report-worker/reporter/claude_client.py:683-715` (3-Modi-Cache-Architektur); CLAUDE.md (Determinismus-Block, AI-Cache-Modi). testssl JSON-Schema: https://github.com/drwetter/testssl.sh — Abgerufen 2026-05-07. ffuf Output-Format: https://github.com/ffuf/ffuf — Abgerufen 2026-05-07. katana Output: https://docs.projectdiscovery.io/tools/katana/usage — Abgerufen 2026-05-07. feroxbuster Output: https://github.com/epi052/feroxbuster — Abgerufen 2026-05-07. |
| Risiko | Cache-Hit-Quote steigt bei Re-Scans ohne Server-Aenderung (TLSCompliance ~80%+ erwartet, Perimeter ~50% erwartet); Determinismus-KPI (Migration 024) verbessert; einmaliger Cache-Miss nach Rollout (alte Hashes aus volatilen Outputs invalid). Failure-Mode: Normalizer-Exception faellt auf Original zurueck (try/except in `normalize()`). Output-Inhalt der Tool-Outputs unveraendert (Strip ist nicht-destruktiv fuer inhaltsrelevante Daten). FP-Rate unveraendert. |
| Priorität | **hoch** — direkter Hebel auf KI-Kosten und Determinismus-Garantie; jeder Normalizer adressiert mehrere Phasen + Reporter gleichzeitig; testssl ist alleine TLSCompliance-Bedingung fuer Cache-Hits. |

---

## 5. Priorisierungs-Tabelle aller angenommenen Findings

| ID | Phase | Dimension | Empfehlung-Kurz | Aufwand | Erwarteter Impact | Risiko |
|---|---|---|---|---|---|---|
| F-PRE-001 | Pre-Check | Coverage | Parking-Pattern-Liste +13 dt./eng./Provider, plus Allowlist-Status-Code-Marker für Redirect-Variante | S (1 PR, ~30 Patterns + ~10 Hosts) | mittel — eingesparte KI #1- und Phase-1-Calls auf Parking-Hosts | keiner |
| F-PRE-002 | Pre-Check | Parallelität | `resolve_all` 5 DNS-Queries parallelisieren via ThreadPoolExecutor | XS (~10 LOC) | niedrig — kappt Worst-Case 25s → 5s bei langsamen NS | keiner |
| F-PRE-003 | Pre-Check | Coverage | Cloud-Provider-Sync-Skript + GitLab-Job; +8 Provider (IONOS/STRATO/OVH/Hetzner-Online/DO/Fastly/Akamai/Vercel) | M (Sync-Skript + Initial-Mapping + GitLab-Job) | mittel — KI #1-Hint-Qualität + CDN-Dedup + Admin-Sichtbarkeit DE-Hoster | gering |
| F-P0A-001 | Phase 0a | Parallelität | Shodan/AbuseIPDB IP-Loop (max_workers=3, ENV-Override) + SecurityTrails 3-Calls parallel | S (~30 LOC, 3 Funktionen) | mittel — Phase-0a typ. 75s → 15s | gering (Rate-Limit konservativ gedeckelt) |
| F-PRE-004 | Pre-Check | Parameter | nmap-Light: `--max-retries 2` + `--host-timeout 30s` + `-n` + `--open` | XS (4 Flags) | mittel — Worst-Case-Cap CIDR/DROP-Firewall | kein FP-Risiko |
| F-PRE-005 | Pre-Check | Coverage | nmap-Light: kuratierte 57-Port-Liste via `-p` (S1 RCE + S2 KMU-Mgmt + S3 Industrial) statt `--top-ports 10` | XS (1 String-Konstante) | mittel — Admin-Sichtbarkeit, KI #1-Signal, Live-Detection für Custom-Port-Hosts | kein FP-Risiko, CIDR-Worst-Case bleibt unter Wrapper-Timeout |
| F-P0A-002 | Phase 0a | Coverage | Neues `mail_security_parsers.py` (zentral), + TLS-RPT, + BIMI, + DMARC-Policy-Parser, + NSEC3-Iterations | M (1 neues Modul + 3 Checks + DMARC-Migration aus Phase 0b) | mittel-hoch — Severity-Hebel DMARC, Compliance/Insurance-Marker | POLICY_VERSION-Bump nötig |
| F-P0A-003 | Phase 0a | Coverage | + URLhaus + GreyNoise + OTX + VirusTotal-Domain (4 neue passive Clients) | M (4 neue Module ~100 LOC each + Phase-0a-Wiring) | mittel — URLhaus-Compromise-Detection (CRITICAL-Hebel) + KI #1-Signalqualität | POLICY_VERSION-Bump (SP-URLHAUS-*); 4 ENV-Keys |
| F-P0A-004 | Phase 0a | Übergabe | Phase-0a-Subdomains an Phase 0b durchreichen, SecurityTrails-Doppelcall in `phase0.py:206` entfernen (+ Folge-C: Snapshot-Cache-Adoption) | S (Wiring + Entfernen + 1 neues Argument) | mittel — API-Tier-Cap + 15s Laufzeit-Einsparung | gering (webcheck verliert SecurityTrails-Discovery) |
| F-P0A-005 | Phase 0a | Parameter | `phase0a_ip_cap` paketabhängig (perimeter/compl/supply 25, insurance 50) + ENV-Override `PHASE0A_IP_CAP` | XS (Config-Schlüssel + 2 Slice-Aufrufe) | niedrig-mittel — Coverage-Hebel bei Multi-IP-Targets | API-Credit-Verbrauch ↑ (Freelancer-Tier deckt) |
| F-P0A-006 | Phase 0a | Parameter | Shodan on-demand Pre-Warm: Subscription default-on, One-Off opt-in via `orders.pre_warm_requested` | M (neue Methode + 2 Trigger-Pfade + Persistenz-Spalte + Frontend-Toggle) | mittel — frischere Shodan-Daten in Subscription-Re-Scans und Premium-One-Offs | rechtlich gelöst durch Auth-Upload-Gate; Credit-Verbrauch ~1500/mo plus opt-in-Verbrauch |
| F-P0B-001 | Phase 0b | Coverage + Parallelität | DKIM-Probe parallelisieren (max_workers=10) + ~19 fehlende Selektoren (DE-Provider + SES/Postmark/Mailgun/Mailjet/Brevo/Zoho) | S (1 ThreadPool + Selektor-Liste) | mittel-hoch — false-positive "DKIM missing" Klasse bei DE-Customers; Code-Comment-Drift fix | kein FP-Risiko; Reporter-Cache-Miss bei betroffenen Sites |
| F-P0B-002 | Phase 0b | Parameter | subfinder `-all` → explizite `-sources`-Liste mit Free-Providern | XS (1 Flag-Wechsel) | niedrig-mittel — strukturelle Hygiene, Audit-Fähigkeit | keiner |
| F-P0B-003 | Phase 0b | Parameter / Architektur | amass komplett entfernen (Hard-Cap 300s + `-brute`-Doppelarbeit zu gobuster_dns) | S (Funktion entfernen + Dockerfile bereinigen) | mittel — Phase-0b-Worst-Case -300s, -50MB Image | <5% Subdomain-Coverage-Verlust (Permutation-Heuristik) |
| F-P0B-004 | Phase 0b | Coverage | gobuster Wordlist: SecLists 20k + bitquark 10k + n0kovo small (~30k dedupliziert), `--threads 30` `--timeout 3s` | S (Build-Time-Merge + 2 Flag-Anpassungen) | mittel — moderne SaaS-/DevOps-Patterns | NS-Last ↑ (auf Cloudflare/Route53 unkritisch); Snapshot-Cache verarmt während TTL |
| F-P0B-005 | Phase 0b | Übergabe | CDN-Edge-Dedup: rdns-Suffix-Match vor IP-Range-Prüfung; zentraler `rdns_provider_patterns`-Helper | S (Funktion umstrukturieren + Helper) | mittel — Fastly/Akamai-Edges werden korrekt dedupliziert | False-Positive durch Suffix-Match minimal |
| F-P0B-006 | Phase 0b | Coverage | Subdomain-Takeover-Liste-Sync via EdOverflow's `can-i-take-over-xyz` (~70 Services); GitLab-Job `takeover-list-sync` | M (Sync-Skript + JSON-Loader + GitLab-Job) | mittel-hoch — CRITICAL-Severity bei echten Takeovers (Statuspage/Webflow/Tilda/...) | POLICY_VERSION-Bump empfohlen |
| F-P0B-007 | Phase 0b | Parallelität | Multi-VHost-Probe: batch-httpx via `-l <file> -threads 30` statt subprocess-pro-FQDN | S (eine Funktion umbauen + NDJSON-Parser) | mittel-hoch — ~50s → ~5-10s in zentralem Pfad | keiner; Code wird einfacher |
| F-P0B-008 | Phase 0b | Übergabe | crt.sh + certspotter parallel statt Fallback-Pattern; Set-Vereinigung | S (ThreadPoolExecutor + Set-Merge) | mittel — frische CT-Issuances, kein Fallback-Antipattern | certspotter-Tier-Limit (Free reicht) |
| F-KI1-001 | KI #1 | Übergabe | `scan_hints` aus `HOST_STRATEGY_SCHEMA` entfernen (toter Output) | XS (Schema-Edit + System-Prompt-Kürzung) | niedrig — ~$0.6/mo, KI-Prompt-Klarheit | Cache-Miss bei Re-Scans (akzeptabel) |
| F-KI1-002 | KI #1 | Übergabe | Hard-Override um Mailserver-Klausel erweitern (Port-25/465/587 oder MX-Match) | XS (~20 LOC, eine Helper-Funktion) | mittel — Mail-Security-Compliance bei KI-Fehlentscheidung | mehr Phase-1/2-Last bei Mailserver-Hosts (akzeptabel) |
| F-PH1-001 | Phase 1 | Coverage | CMS-Fingerprinter +10 CMS (Pimcore, Sulu, Plone, SilverStripe, Statamic, Webflow, Shopify, HubSpot, Wix, Squarespace) | S (10 Pattern-Sets + Probe-Cap 20→25) | mittel — DACH-Zielkundenbasis-Coverage + globale Standards | keiner |
| F-PH1-002 | Phase 1 | Parallelität | wafw00f-VHost-Loop parallelisieren (max_workers=5) | XS (ThreadPool) | niedrig-mittel — Multi-VHost-Hosts 20s → 4s | HTTP-Last ↑ 12.5 Q/s (im Auth-Scope) |
| F-PH1-003 | Phase 1 | Übergabe | Screenshots: full_page + alle primary VHosts ins PDF + Label pro FQDN; Tool-Naming-Drift `gowitness` → `playwright_screenshot` | M (3 Code-Stellen + Pillow-Höhencap + Doku-Update) | mittel-hoch — Customer-Confidence „alles gesehen" | PDF +3-5MB; Phase-1 +5-10s/Host |
| F-KI3-001 | KI #3 | Parallelität | KI #3 Host-Iteration via ThreadPoolExecutor max_workers=5 | XS (ThreadPool, ~10 LOC) | mittel — bei vielen Hosts ohne Rule-Match 30-45s → 6-9s | API-Rate-Limit bei niedrigen Tiers, Backoff im SDK |
| F-KI3-002 | KI #3 | Coverage | Rule-Engine: Generic-CMS-Set + 10 CMS, neuer Hosted-CMS-Branch, neuer Static-Hoster-Branch | S (3 Code-Blöcke in einer Datei) | mittel — KI-Cost-Reduktion, Determinismus-Verbesserung | Static-Hoster-Skip bei Edge-Cases (kein Override heute) |
| F-KI2-001 | KI #2 | Coverage | Schema Open-List + Phase-1-Bestätigungs-Regel + DACH-CMS-Indikatoren (Pimcore/Sulu/Plone/Craft/Statamic) | XS (Schema-String + 2 Prompt-Regeln) | mittel — verhindert KI-Drift bei F-PH1-001-CMS | Cache-Miss bei Re-Scans (akzeptabel, TTL 30d) |
| F-PH2-001 | Phase 2 | Parameter | ffuf_sensitive Wordlist `raft-medium` (17.5k) → `raft-small` (10k) | XS (1 Pfad-Konstante) | mittel — Phase-2 ~70s/VHost schneller, kein Hard-Cap-Hit | Coverage-Verlust <2% (Long-Tail wurde eh abgeschnitten) |
| F-PH2-002 | Phase 2 | Coverage | nuclei + katana implementieren (Stage 3); nikto + dalfox deferred | L (2 neue Wrapper + Reporter-Parser-Erweiterung + Severity-Policy-Regeln + FP-Filter) | **hoch** — massive CVE-Detection-Coverage-Erweiterung | Phase-2-Laufzeit +2-3 Min/Host; POLICY_VERSION-Bump; Findings-Flut → Severity-Cap mitigiert |
| F-PH3-001 | Phase 3 | Parallelität | NVD-Lookup parallel (max_workers dynamisch + 429-Backoff) + max_lookups 50→100 (webcheck 5→10) + ENV-Override | S (ThreadPool + Backoff + 2 Konstanten) | mittel-hoch — wichtig nach F-PH2-002, Cache dämpft Re-Scans | 429-Hits ohne Backoff (Backoff zwingend mit) |
| F-KI4-001 | KI #4 | Übergabe | Severity-Pre-Sort + Cap 100→150 + Critical/High-Guarantee | XS (~15 LOC) | mittel — wichtige Findings erreichen KI #4 zuverlässig | Cache-Miss bei Re-Scans (akzeptabel) |
| F-PH9-001 | tar.gz/MinIO | Übergabe | Screenshots-Upload parallel (max_workers=10) + Bucket-Existence-Check beim Worker-Start cachen | XS (ThreadPool + One-Time-Check) | niedrig-mittel — ~5s/Scan schneller | MinIO-Thread-Safety zu verifizieren |
| F-RPT-001 | Reporter | Coverage | KNOWN_VULN_BUILDS: Initial-Liste +20 manuelle Entries 2022-2026 + OSV-Sync-Skript + Range-Matcher | L (~600 LOC, 2-3 Tage) | **hoch** — EOL-Confidence-Kritisch, Severity-Hebel bei Banner-Match | POLICY_VERSION-Bump; Distro-Backport-Edge-Cases via Hinweis im Finding |
| F-RPT-002 | Reporter | Übergabe | `selection.consolidate` Hash um `title_vars` (port/tech/version/plugin/library/directive/selector) erweitern (Hybrid evidence + title_vars) | S (~30 LOC + 2 Tests) | **hoch** — Multi-Tech-Hosts; verhindert dass EOL/DB/Plugin/Library-Findings faelschlich konsolidieren | Cache-Invalidierung 1-2 Re-Scans (Determinismus-Drift erwartet, danach stabil); kein POLICY_VERSION-Bump |
| F-RPT-003 | Reporter | Coverage | `business_impact._classify_finding` durch `POLICY_ID_TO_CATEGORIES`-Lookup ersetzen + RANSOMWARE_PORTS um 23, 5800 erweitern + Cross-Check-Test SEVERITY_POLICIES↔Mapping | S (~80 LOC Mapping + 1 Funktion + 4 Tests) | mittel — DACH-Reports bekommen korrekten Insurance/Compliance/SupplyChain-Boost; sprachunabhaengig | Score-Drift 1-2 Re-Scans (Top-N-Reihenfolge aendert sich), kein POLICY_VERSION-Bump |
| F-RPT-004 | Reporter | Parallelität | `finding_type_mapper` AI-Fallback-Loop mit ThreadPoolExecutor (max_workers=5, per-Future-Timeout 10 s) parallelisieren | XS (~15 LOC) | niedrig-mittel — Cold-Cache-Szenarien 5–60 s schneller; warm-Cache marginal | Rate-Limit-konservativ; SDK-Backoff aktiv; Determinismus unveraendert |
| F-RPT-005 | Reporter | Übergabe | QA-Check `_check_severity_evidence` nach severity_policy verschieben + nur auf SP-FALLBACK-Findings anwenden + Audit-Flag `_qa_cap_applied` | S (~30 LOC + 1-2 Tests) | niedrig-mittel — Audit-Log-Klarheit, Forensik-Diff vollstaendiger, Sicherheitsnetz fuer SP-FALLBACK erhalten | Determinismus unveraendert; severity_provenance reichhaltiger |
| F-RPT-006 | Reporter | Parameter | `claude_client.call_claude` MAX_FINDINGS_CHARS 120K→150K + `per_host_cap` Round-Robin korrekt anwenden + Comment-Fix | S (~25 LOC + 2 Tests) | mittel — vollstaendige KI-Narrative bei Multi-Host-Scans (Compliance/Insurance/SupplyChain >10 Hosts) | KI-Input-Kosten +25% (~$0.11/Report); Cache-Miss einmalig nach Rollout |
| F-RPT-007 | Reporter | Übergabe | `eol_detector.merge_into_claude_findings` Dedup mit Host-Resolution (FQDN↔IP) + Version-Recovery aus Title-Regex | S (~30 LOC + 3 Tests) | mittel-hoch — keine Doppel-EOL-Findings bei FQDN-basierten Scans (Mehrheit der Customer-Orders) | Determinismus-Drift einmalig; Fallback bei leerem tech_profiles |
| F-XS-001 | Übergreifend | Übergabe (Cache) | Output-Normalizer fuer testssl, ffuf, katana, feroxbuster ergaenzen (~150 LOC + 4 Tests) | M (4 Funktionen + Dict-Eintraege) | **hoch** — Cache-Hit-Quote TLSCompliance ~80%+, Perimeter ~50%, Reporter-Cache-Wirksamkeit | Einmaliger Cache-Miss nach Rollout; sonst nur Verbesserung |
| F-XS-002 | Übergreifend | Übergabe (Cache) | KI #2 + KI #3 mit `content_hash`-Cache-Modus symmetrisch zu KI #1 ausstatten | XS (~10 LOC + 2 Tests) | mittel — Cache-Hits Order-uebergreifend bei identischen Tech-Profilen; Determinismus-Symmetrie | Cache-Volumen +~30% Redis-Keys (vernachlaessigbar) |
| F-XS-003 | Übergreifend | Übergabe (Maintenance) | Shared-Helper `scripts/_sync_lib.py` (HTTP/Atomic-Write/Git-Diff/CI-Commit) + GitLab-`.sync-job-template`-Anchor; EOL-Skript als Pilot-Refactor | M (Helper ~200 LOC + Pilot-Refactor + Anchor) | niedrig-mittel — strukturelle Voraussetzung fuer Sync-Skripte aus F-PRE-003/F-P0B-006/F-RPT-001, spart ~400 LOC + Drift | EOL-Output-Hash vor/nach identisch; Bug-Blast-Radius ueber Test-Coverage minimiert |

---

## Anhang A — Zur späteren Diskussion (deferred)

### F-PH2-002-DEFERRED-1 — nikto-Implementation
- Aus F-PH2-002 deferred (User: „da gab es Probleme").
- Tool im Dockerfile installiert, Baseline §2.11 dokumentiert, output_normalizer kennt `normalize_nikto`, aber kein Wrapper in `phase2.py`.
- Vorgesehene Konfig: `nikto -h <url> -Format json -o <out> -Tuning x468a` (skippt Auth-Required + DDoS-Tests).
- 6700+ Legacy-Web-Server-Checks (CGI-Bugs, Default-Files). Mehrwert ggü. nuclei/ZAP-Active vermutlich begrenzt für moderne Sites, aber Compliance-Wert für Insurance-Pakete.
- Wieder aufzugreifen sobald nuclei + katana stabil laufen und die ursprünglichen nikto-Probleme adressiert wurden.

### F-PH2-002-DEFERRED-2 — dalfox-Implementation
- Aus F-PH2-002 deferred (User: „da gab es Probleme").
- Tool im Dockerfile installiert, Baseline §2.11 dokumentiert, aber kein Wrapper in `phase2.py`.
- Vorgesehene Konfig: `dalfox url <url> --format json -o <out> --skip-bav`.
- Spezialisierter XSS-Scanner. Mehrwert ggü. ZAP-Active-XSS-Klasse oft niedrig wenn ZAP korrekt konfiguriert.
- Wieder aufzugreifen sobald die ursprünglichen dalfox-Probleme adressiert wurden.

---

## Anhang B — Abgelehnte Findings

_(leer)_

---

## Quellen

**Parking-Page-Detection (F-PRE-001):**
- Marktanteile Parking-Plattformen: https://www.cnstats.org/dns-zones/parking — Abgerufen 2026-05-06
- Namecheap Parking-Default-Page: https://parkingpage.namecheap.com/ — Live-Inspektion 2026-05-06
- Code-Analyse: `scan-worker/scanner/common/http_utils.py:18-34, 93-97`

**DNS-Resolution (F-PRE-002):**
- dnspython Resolver-Doku: https://dnspython.readthedocs.io/en/stable/resolver-class.html — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/common/dns_utils.py:39-44, 122-130`

**nmap-Light Pre-Check (F-PRE-004):**
- nmap Performance-Doku: https://nmap.org/book/performance.html — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/common/nmap_utils.py:10-30`, `scan-worker/scanner/precheck/runner.py:138-170, 173-210`

**nmap-Light Port-Coverage (F-PRE-005):**
- nmap-services Top-N: https://nmap.org/book/nmap-services.html — Abgerufen 2026-05-06
- SANS ISC Top-Ports: https://isc.sans.edu/data/topports.html — Abgerufen 2026-05-06
- Shodan Industrial-Control-Systems Kategorie: https://www.shodan.io/explore/category/industrial-control-systems — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/common/nmap_utils.py:21-22`, `scan-worker/scanner/precheck/runner.py:148-150`

**Phase 0a Parallelität (F-P0A-001):**
- Shodan API Rate Limits: https://help.shodan.io/the-basics/rate-limiting — Abgerufen 2026-05-06
- AbuseIPDB API Doku: https://docs.abuseipdb.com/#introduction — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/phase0a.py:70-118`, `scan-worker/scanner/passive/base_client.py:34-64`

**Maintained-Listen-Sync-Strategie (F-XS-003):**
- Code-Analyse: `scripts/sync-eol-data.py`
- Code-Analyse: `.gitlab-ci.yml` (`eol-data-sync`-Job)
- Verweis auf Folge-Findings: F-PRE-003 (Cloud-Provider-Sync), F-P0B-006 (Takeover-Sync), F-RPT-001 (KNOWN_VULN_BUILDS-Sync)

**Cache-Architektur-Symmetrie KI #2/#3 (F-XS-002):**
- Code-Analyse: `scan-worker/scanner/ai_strategy.py:268-348` (KI #1 Vorlage), `:466-525` (KI #2), `:609-720` (KI #3)
- Code-Analyse: `scan-worker/scanner/ai_cache.py:50-119` (3-Modi-Cache)

**Output-Normalizer-Coverage (F-XS-001):**
- testssl JSON-Schema: https://github.com/drwetter/testssl.sh — Abgerufen 2026-05-07
- ffuf Output-Format: https://github.com/ffuf/ffuf — Abgerufen 2026-05-07
- katana Output-Format: https://docs.projectdiscovery.io/tools/katana/usage — Abgerufen 2026-05-07
- feroxbuster Output: https://github.com/epi052/feroxbuster — Abgerufen 2026-05-07
- Code-Analyse: `scan-worker/scanner/output_normalizer.py:307-347`
- Code-Analyse: `scan-worker/scanner/tools/__init__.py:365-394`
- Code-Analyse: `report-worker/reporter/claude_client.py:683-715`

**EOL-Detector Merge-Dedup (F-RPT-007):**
- Code-Analyse: `report-worker/reporter/eol_detector.py:226-282, 370-402`
- Code-Analyse: `report-worker/reporter/deterministic_pipeline.py:155-170`
- Version-Regex-Vorlage: `report-worker/reporter/title_policy.py:41`

**KI #5 Smart-Truncation (F-RPT-006):**
- Anthropic Pricing: https://www.anthropic.com/pricing — Abgerufen 2026-05-07
- Anthropic Model Context Windows: https://docs.anthropic.com/en/docs/about-claude/models — Abgerufen 2026-05-07
- Code-Analyse: `report-worker/reporter/claude_client.py:622-646`
- Code-Analyse: `report-worker/reporter/deterministic_pipeline.py:83-128`

**QA-Check ↔ severity_policy Reihenfolge (F-RPT-005):**
- Code-Analyse: `report-worker/reporter/worker.py:467-492`
- Code-Analyse: `report-worker/reporter/qa_check.py:172-248, 444-500`
- Code-Analyse: `report-worker/reporter/severity_policy.py:1012-1106`
- Code-Analyse: `report-worker/reporter/deterministic_pipeline.py:135-241`

**finding_type AI-Fallback Parallelisierung (F-RPT-004):**
- Anthropic Rate-Limits: https://docs.anthropic.com/en/api/rate-limits — Abgerufen 2026-05-07
- Anthropic SDK (Python, Concurrent Calls): https://docs.anthropic.com/en/api/client-sdks#python — Abgerufen 2026-05-07
- Code-Analyse: `report-worker/reporter/finding_type_mapper.py:382-393`
- Code-Analyse: `report-worker/reporter/ai_finding_type_fallback.py:125-229`

**Business-Impact Klassifikation (F-RPT-003):**
- CISA KEV Catalog (Telnet/VNC-Eintraege): https://www.cisa.gov/known-exploited-vulnerabilities-catalog — Abgerufen 2026-05-07
- Code-Analyse: `report-worker/reporter/business_impact.py:79-122, 32-50, 52`
- Code-Analyse: `report-worker/reporter/deterministic_pipeline.py:185-219`
- Code-Analyse: `report-worker/reporter/severity_policy.py:114-770`

**Konsolidierungs-Hash `selection.consolidate` (F-RPT-002):**
- Code-Analyse: `report-worker/reporter/selection.py:96-124, 140-182`
- Code-Analyse: `report-worker/reporter/eol_detector.py:226-282`
- Code-Analyse: `report-worker/reporter/deterministic_pipeline.py:200-215`
- Code-Analyse: `report-worker/reporter/title_policy.py:148-224, 236-329`
- Tests: `report-worker/tests/test_selection.py:60-110`

**KNOWN_VULN_BUILDS Coverage (F-RPT-001):**
- OSV API: https://google.github.io/osv.dev/api/ — Abgerufen 2026-05-07
- OSV Schema (Range-Events): https://ossf.github.io/osv-schema/ — Abgerufen 2026-05-07
- CISA KEV Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json — Abgerufen 2026-05-07
- GHSA Database: https://github.com/github/advisory-database — Abgerufen 2026-05-07
- Apache HTTP Server CVEs: https://httpd.apache.org/security/vulnerabilities_24.html — Abgerufen 2026-05-07
- nginx Security Advisories: https://nginx.org/en/security_advisories.html — Abgerufen 2026-05-07
- Code-Analyse: `report-worker/reporter/eol_detector.py:137-155, 158-215`

**MinIO-Upload-Pipeline (F-PH9-001):**
- MinIO Python SDK Doku: https://min.io/docs/minio/linux/developers/python/API.html — Abgerufen 2026-05-07
- Code-Analyse: `scan-worker/scanner/upload.py:25-35, 38-73, 76-97`

**KI #4 Truncation/Sortierung (F-KI4-001):**
- Anthropic Sonnet 4.6 Context-Window: https://docs.anthropic.com/en/docs/about-claude/models — Abgerufen 2026-05-07
- Code-Analyse: `scan-worker/scanner/ai_strategy.py:864`, `scan-worker/scanner/phase3.py:46-62`

**NVD-Lookup-Parallelisierung (F-PH3-001):**
- NVD API Doku: https://nvd.nist.gov/developers/vulnerabilities — Abgerufen 2026-05-06
- NVD API-Key Registration: https://nvd.nist.gov/developers/request-an-api-key — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/correlation/threat_intel.py:119-128, 207-258`, `scan-worker/scanner/phase3.py:211, 221`

**Phase 2 Tool-Coverage (F-PH2-002):**
- nuclei Doku: https://docs.projectdiscovery.io/tools/nuclei/usage — Abgerufen 2026-05-06
- nuclei-templates Repo: https://github.com/projectdiscovery/nuclei-templates — Abgerufen 2026-05-06
- katana Doku: https://docs.projectdiscovery.io/tools/katana/usage — Abgerufen 2026-05-06
- nikto (deferred): https://github.com/sullo/nikto — Abgerufen 2026-05-06
- dalfox (deferred): https://github.com/hahwul/dalfox — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/phase2.py`, `scan-worker/Dockerfile:24-30, 69-...`

**ffuf_sensitive Wordlist (F-PH2-001):**
- SecLists Discovery/Web-Content: https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/phase2.py:596-624`

**KI #3 Rule-Engine-Erweiterung (F-KI3-002):**
- Verweis auf F-PH1-001 (CMS-Coverage-Erweiterung)
- Code-Analyse: `scan-worker/scanner/phase2_config_rules.py:24-136`

**KI #3 Parallelisierung (F-KI3-001):**
- Anthropic API Rate-Limits: https://docs.anthropic.com/en/api/rate-limits — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/worker.py:558-572`, `scan-worker/scanner/ai_strategy.py:609-665`

**Screenshot-Pipeline (F-PH1-003):**
- Playwright `page.screenshot` Doku: https://playwright.dev/python/docs/api/class-page#page-screenshot — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/tools/redirect_probe.py:77-95`, `report-worker/reporter/report_mapper.py:644-676`, `scan-worker/scanner/upload.py:38-72`, `report-worker/reporter/parser.py:1219-1232`

**wafw00f-VHost-Parallelisierung (F-PH1-002):**
- wafw00f Repo: https://github.com/EnableSecurity/wafw00f — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/phase1.py:793-807`

**CMS-Fingerprinter Coverage (F-PH1-001):**
- Pimcore Architektur: https://pimcore.com/docs/platform/ — Abgerufen 2026-05-06
- Sulu CMS Doku: https://docs.sulu.io/en/2.5/book/getting-started/installation.html — Abgerufen 2026-05-06
- Plone Installation: https://docs.plone.org/manage/installing/installation.html — Abgerufen 2026-05-06
- Wappalyzer Technologies (deferred Sync-Quelle): https://github.com/dochne/wappalyzer/tree/main/src/technologies — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/cms_fingerprinter.py:100-226`

**CT-Discovery parallel (F-P0B-008):**
- certspotter API: https://sslmate.com/help/reference/ct-search-api/ — Abgerufen 2026-05-06
- crt.sh-Instabilität: dokumentiert in Code-Comment `scan-worker/scanner/phase0.py:121-130`
- Code-Analyse: `scan-worker/scanner/phase0.py:120-203, 250-289`

**Multi-VHost-Probe Batch (F-P0B-007):**
- httpx CLI-Doku: https://docs.projectdiscovery.io/tools/httpx/usage — Abgerufen 2026-05-06
- httpx Performance-Tuning: https://github.com/projectdiscovery/httpx#scan-with-thread-control — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/phase0.py:1304-1320, 1362-1386`

**Subdomain-Takeover-Liste (F-P0B-006):**
- EdOverflow can-i-take-over-xyz: https://github.com/EdOverflow/can-i-take-over-xyz — Abgerufen 2026-05-06
- HackTricks Subdomain-Takeover: https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover — Abgerufen 2026-05-06
- PunkSecurity dnsReaper (deferred): https://github.com/punk-security/dnsReaper — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/phase0.py:30-95, 98-117`

**CDN-Edge-Dedup (F-P0B-005):**
- Cloudflare IP-Drift-Doku: https://www.cloudflare.com/ips/ — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/phase0.py:861-873`, `scan-worker/scanner/precheck/saas_heuristic.py:15-46`

**gobuster_dns Wordlist (F-P0B-004):**
- SecLists Repo: https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS — Abgerufen 2026-05-06
- bitquark Subdomain-Liste (dnspop): https://github.com/bitquark/dnspop — Abgerufen 2026-05-06
- n0kovo Subdomains: https://github.com/n0kovo/n0kovo_subdomains — Abgerufen 2026-05-06
- Assetnote Wordlists (deferred, zu groß für Pre-Check): https://github.com/assetnote/wordlists — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/phase0.py:466-520`

**amass-Entfernung (F-P0B-003):**
- amass v5 Release-Notes: https://github.com/owasp-amass/amass/releases — Abgerufen 2026-05-06
- amass Datasources YAML: https://github.com/owasp-amass/amass/blob/master/resources/datasources.yaml — Abgerufen 2026-05-06
- subfinder vs amass Vergleich (ProjectDiscovery): https://blog.projectdiscovery.io/best-subdomain-enumeration-tools/ — Abgerufen 2026-05-06
- Repo-Doku: `docs/analyse/AMASS-V5-DIAGNOSE.md`
- Code-Analyse: `scan-worker/scanner/phase0.py:350-463`, `scan-worker/Dockerfile`

**subfinder Provider-Konfig (F-P0B-002):**
- subfinder Provider-Liste: https://github.com/projectdiscovery/subfinder — Abgerufen 2026-05-06
- subfinder CLI-Doku: https://docs.projectdiscovery.io/tools/subfinder/usage — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/phase0.py:298-314`, `scan-worker/Dockerfile:204`

**DKIM-Selektoren Phase 0b (F-P0B-001):**
- DKIM RFC 6376: https://datatracker.ietf.org/doc/html/rfc6376 — Abgerufen 2026-05-06
- MailSniper Maintained-Selektoren: https://github.com/dafthack/MailSniper/blob/master/Misc/dkim-selectors.txt — Abgerufen 2026-05-06
- Amazon SES DKIM-Doku: https://docs.aws.amazon.com/ses/latest/dg/easy-dkim.html — Abgerufen 2026-05-06
- IONOS DKIM-Setup-Guide: https://www.ionos.de/hilfe/e-mail/allgemeine-themen/dkim-spf-dmarc-fuer-ihre-domain-konfigurieren/ — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/phase0.py:729-764`

**Phase 0a IP-Cap (F-P0A-005):**
- Shodan Pricing/Credits: https://www.shodan.io/about/pricing — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/phase0a.py:82, 98`, `scan-worker/scanner/packages.py:_PERIMETER_BASE`

**Shodan on-demand Pre-Warm (F-P0A-006):**
- Shodan Scan API: https://developer.shodan.io/api Section "Scans" — Abgerufen 2026-05-06
- Shodan Pricing (Freelancer-Tier): https://www.shodan.io/about/pricing — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/precheck_worker.py:55-77`, `scan-worker/scanner/phase0a.py:70-89`, `scan-worker/scanner/passive/shodan_client.py`

**Phase 0a → Phase 0b Übergabe (F-P0A-004):**
- SecurityTrails API Tier-Limits: https://docs.securitytrails.com/reference/rate-limits — Abgerufen 2026-05-06
- Shodan DNS API: https://developer.shodan.io/api — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/phase0a.py:77-89, 112-117`, `scan-worker/scanner/phase0.py:206-247`, Migration 019 (`subdomain_snapshot`)

**Passive-Intel-Quellen (F-P0A-003):**
- GreyNoise API: https://docs.greynoise.io/reference/get_v3-community-ip — Abgerufen 2026-05-06
- URLhaus API: https://urlhaus.abuse.ch/api/ — Abgerufen 2026-05-06
- OTX AlienVault API: https://otx.alienvault.com/api — Abgerufen 2026-05-06
- VirusTotal Public API v3: https://docs.virustotal.com/reference/overview — Abgerufen 2026-05-06
- Censys Search API (deferred): https://search.censys.io/api — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/packages.py:15`, `scan-worker/scanner/phase0a.py:130-141`, `scan-worker/scanner/passive/`-Verzeichnis

**DNS/Mail-Security Phase 0a (F-P0A-002):**
- TLS-RPT RFC 8460: https://www.rfc-editor.org/rfc/rfc8460.html — Abgerufen 2026-05-06
- BIMI Draft (IETF): https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/ — Abgerufen 2026-05-06
- DMARC RFC 7489: https://datatracker.ietf.org/doc/html/rfc7489 — Abgerufen 2026-05-06
- NSEC3 RFC 9276 (Iterations-Best-Practice): https://www.rfc-editor.org/rfc/rfc9276.html — Abgerufen 2026-05-06
- BSI TR-03108-1 (Mail-Sicherheits-Mindest-Standards) — Verwiesen
- Code-Analyse: `scan-worker/scanner/passive/dns_security.py:24-71, 159-175`, `scan-worker/scanner/phase0.py:720-727`

**Cloud-Provider-Detection (F-PRE-003):**
- AWS ip-ranges: https://ip-ranges.amazonaws.com/ip-ranges.json — Abgerufen 2026-05-06
- Cloudflare ips-v4: https://www.cloudflare.com/ips-v4 — Abgerufen 2026-05-06
- Fastly public IPs: https://api.fastly.com/public-ip-list — Abgerufen 2026-05-06
- GCP cloud.json: https://www.gstatic.com/ipranges/cloud.json — Abgerufen 2026-05-06
- DigitalOcean google.csv: https://digitalocean.com/geo/google.csv — Abgerufen 2026-05-06
- RIPEstat RIS-Prefixes API: https://stat.ripe.net/docs/02.data-api/ris-prefixes.html — Abgerufen 2026-05-06
- Code-Analyse: `scan-worker/scanner/precheck/saas_heuristic.py:15-46`

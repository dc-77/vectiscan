# S6c: Neue Rohdatenfelder des scan-workers (Übergabe an die Berichtsseiten-Session)

Stand: S6c. Diese Datei erfüllt Auflage (e) aus dem Startprompt: je neuem Rohfeld eine Zeile mit
Werkzeug, Feldname, Struktur, Fixture und dem zugehörigen spec/11-Punkt. Der report-worker liest diese
Felder **noch nicht** (S6c ist nur scanner-seitiger Export, „report-worker unverändert grün"); die
Umstellung des Lesens ist die Berichtsseiten-Session nach spec/12.

Grundregel (Auflage c/d): die Felder, die der report-worker heute liest, sind unverändert. Neue
Erkenntnisse stehen in **zusätzlichen** Feldern oder Einträgen. Wo ein Bestandsfeld heute einen
falschen Wert trägt (redirect_probe erste statt Endantwort), bleibt es und die Endantwort kommt in ein
neues Feld.

| Werkzeug / Zeile | Neues Feld / Eintrag | Struktur | Fixture (Scan-Runde 23.09.) | spec-Punkt |
|---|---|---|---|---|
| `header_check` (`result`) | `redirect_eval` | `{reachable, first{status,headers}, final{status,location,url,content_length,response_length,headers}, hops[], not_testable, not_testable_reason}` | JW .28 302→/owa/, CA ubb-wiki 302→/login/, CA Nextcloud 400, HL online 429, BS ftp 403, BS Apex 301, CA x-powered-by-Dublette | Q8, R1 |
| `redirect_probe` (`tech_profile.redirect_data[vhost]`) | `final_response_headers`, `first_response_headers`, `first_status`, `final_status`, `response_chain[]` | Header-Dicts + `[{url,status}]`; `response_headers` bleibt die erste Antwort | HL ose (Redirector→login.seam), HL online (Vercel→www), CA mail/mail2 302→/owa/ | N3 |
| `testssl_<port>` (Zeile + `testssl_<port>.json`) | Per-Port-Läufe mit `--starttls` | testssl-JSON je Port; `testssl.json`/`testssl` (443) unverändert | DB 8 TLS-Dienste (21,110,143,465,587,993,995,10000); Port 25 skipped (E5) | Q17, R3 |
| `testssl_sni_<slug>` (Zeile + Datei) | Per-VHost-SNI-Cert | testssl-JSON (fast, Cert) je Zusatz-VHost | BS ftp (eigenes Zertifikat auf demselben IP:443) | Q17 |
| `smtp_ehlo_<port>` (Zeile + `smtp_ehlo_<port>.json`) | EHLO vor STARTTLS | `{capabilities[], starttls, vrfy, auth_before_starttls, auth_mechanisms[], evidence}` | DB 587 (AUTH vor STARTTLS); Port 25 skipped (E5) | (5) |
| `wordpress_xmlrpc` (Zeile + `xmlrpc_probe.json`) | XML-RPC-Sonde | `{fqdn,url,status,xmlrpc_enabled,fault,evidence}` | DB (aktiv), CA (wpscan meldet es nicht) | 7a, T1 |
| `zap` (Zeile `top_alerts`) | Konfidenz/Risiko/Status je Meldung, unkürzt | `top_alerts:[{name,risk,confidence,url,status,cweid,param,sourceid}]`, `confidence_distribution`, `truncated` | CA „CSP: Wildcard Directive", HL online 429-Alert | Q14, N2 |
| `zap_alerts.json` (Tar) | `status` je Alert (aus `messageId`) | Alert-Dicts mit ergänztem `status` | HL online 429, Nebenpfade (robots.txt) | N2, 7b |
| `abuseipdb` (`abuseipdb.json`) | `maxAgeInDays` | Ganzzahl (90) je IP | alle sieben | 7b |
| `rdap` (Zeile + `rdap.json`) | Netzbetreiber je IP aus der RIR-Registry | `{netblock_owner, netname, handle, country, cidr, rir, source, source_url}` je IP | alle sieben (Hetzner, A100/Amazon, Vodafone-Anschluss) | T2, E17 |
| `phase0/zone_transfer_<domain>.txt` | Rohausgabe je Domain, auch bei „kein Lauf" | Text `=== NS: … ===` bzw. Grund | junkerwerk.hu (kein Lauf → Grund im Text) | 7b |
| `provider_block_probe` (Zeile) + `tech_profile.provider_block` | Sperrerkennung nach dem Portscan | `{ip, blocked, reachable, time_to_reachable_s, checked_ports[], checked_at}` | LW/JW/HL (Hetzner sperrt nach dem Portscan) | Q17 |
| `nmap_versionall.xml` (Tar) + Zeile | `-sV --version-all` für Ports ohne Kennung | nmap-XML je nachgeprobtem Port | HE 1000-1002, CA 8001, HL 8443 | T1 |
| `host_inventory.discovery_health` | `found_not_in_inventory[]` | Liste aufgelöster, nicht ins Inventar gelangter Namen | LW eset/ftp, HE ftp, BS 24 Namen, HL as2/control, JW archiv | Q1, R5 |
| Host-Inventar | Hosts der Zusatzdomain | zusätzliche Hosts aus crtsh/subfinder/gobuster/dnsx je Zieldomain | junkerwerk.hu (eigene Hosts statt nur DNS/Mail) | Q16, 7b |

## Verhaltensänderungen an Bestandszeilen (kein neues Feld, aber neuer Status/Wert für neue Scans)

- `whois`, `securitytrails`, `urlhaus`: ein fehlgeschlagener Abruf ist jetzt `failed` statt `ok`/`no_data` (#35, R6).
- `header_check` bindet an die Inventar-IP (`--resolve`), `testssl` an `--ip <inventar>` (Q16/T7); die
  gemessene Adresse steht in der testssl-`-->>`-Zeile bzw. httpx `host` (Bestandsfelder).
- nmap: `hosts up=0` ohne Hostblock → `failed`/`nmap_no_response` („keine Antwort" statt „kein offener Port", Q17).
- Phase 2 gegen eine IPv6-Adresse ohne Route → alle Werkzeuge `failed`/`no_ipv6_route` (Q16/T7).
- Phase 2 gegen einen nach dem Portscan gesperrten Host → alle Werkzeuge `failed` mit
  „Zielnetz sperrt die Prüfadresse nach dem Portscan" (Q17).
- `waf_body_marker`: schwache Markennamen zählen nur mit Block-Statuscode (403/429/503); starke
  Challenge-Formulierungen weiter allein (Q17, BS 198.202.211.1).
- ffuf/feroxbuster zielen auf die `final_url` des Inhalts-VHosts; `ffuf_sensitive` nutzt gegen Exchange
  die Exchange-Pfadliste (Q17).
- `tech_profiles`: Seiten-Signale einer Weiterleitung fallen nicht mehr dem Ausgangshost zu, der
  Exchange-Build kommt nur aus Spider-URLs des eigenen Hosts (N4).

# Katalog-Simulation über alle 36 Scans: Verhalten, Restmenge, Pflegeprozess

Stand 17.09.2026. Intern. Beantwortet drei Fragen von DC: Wie verhält sich ein Regelkatalog über alle vorhandenen Rohdaten? Was passiert mit Sachverhalten, die nicht im Katalog stehen? Wie kommen neue Einträge hinein?

Werkzeug: `build/catalog_sim.py` (Fakten aus `results.json` und `order.json` je Order, 42 Entwurfsregeln, Vergleich mit den KI-Befunden aus `findings.json`). Daten: `scripts/fetch-all-orders.sh` lädt alle Orders mit Report nach `input/_all/` (gitignored). Ergebnis in `out/catalog-sim.json`.

## 1. Datenbasis

39 Orders mit Report in der Produktions-DB, davon 36 ausgewertet (3 Demo-Orders ohne Rohdaten ausgeschlossen). 17 verschiedene Kunden-Domains, Mai bis September 2026, 34 Perimeter, 2 Webcheck. Wiederholungsläufe: securess.de 8, heuel.com 6, castenow.de 3, dortmund-beach.com 3, rankingcoach.com 2, huendgen-entsorgung.de 2, junkerwerk 3.

Einschränkungen der Simulation: Der API-Endpunkt `/results` liefert von ZAP nur `top_alerts` (gekappt), nicht die vollständige Alert-Liste aus dem Tar; wpscan-Details und der OWA-Build (cms_fingerprinter) fehlen ebenfalls. Rohdaten der Läufe vor Juli haben kein `status`-Feld je Tool-Run, deshalb sind Coverage-Zahlen nur für die 10 jüngeren Läufe belastbar. Die Simulation unterschätzt damit die Regelabdeckung leicht; die KI hatte mehr Eingabe als die Regeln.

## 2. Wie sich der Katalog verhält

### 2.1 Größe und Sättigung

42 Entwurfsregeln erzeugen 41 Befundfamilien. Die KI hat in denselben 36 Läufen 46 Familien erzeugt (363 Befunde, 103 davon SP-FALLBACK, 28 %).

Kumulativ neue Familien je Lauf, chronologisch:

```
Regeln: 12 15 17 17 20 21 21 21 21 22 24 26 26 30 31 31 31 31 31 31 32 32 32 32 34 34 35 39 40 40 40 40 40 40 40 41
KI:      8 11 14 15 16 17 18 18 18 19 20 21 21 25 28 29 30 31 31 31 34 36 36 37 39 40 40 42 44 44 44 44 44 44 46 46
```

Nach 15 Läufen sind 31 von 41 Familien gesehen, die letzten 10 Läufe bringen zusammen 1 neue Familie. Der Sprung bei Lauf 28 (35 → 39) ist castenow.de, die erste Infrastruktur mit Exchange, Nextcloud, Bitwarden und Icecast in einem Scan. Das ist das erwartete Muster: Neue Kundentypen bringen ein bis vier Familien, Wiederholungen bringen nichts.

### 2.2 Vergleich Regeln gegen KI, familienweise (Anzahl Orders mit Befund)

| Familie | Regeln | KI | Bemerkung |
|---|---|---|---|
| csp_missing | 35 | 28 | KI lässt 7 aus |
| banner_version_disclosure | 36 | 27 | |
| security_headers_incomplete | 35 | 13 | KI berichtet Header uneinheitlich (mal XFO, mal „Header fehlen", mal gar nicht) |
| hsts_missing | 33 | 9 | KI übersieht HSTS in 24 Läufen |
| dnssec_missing | 36 | 11 | KI berichtet in 25 Läufen nicht |
| caa_missing | 33 | 0 | KI nie; im Katalog Hygiene niedrig |
| mta_sts_missing | 35 | 6 | |
| spf_softfail | 27 | 16 | |
| ftp_exposed | 23 | 29 | KI zählt FTP mit TLS-Zwang als Befund (10 Fälle), Regeln nicht |
| admin_service_exposed | 30 | 18 | Plesk, Webmin, Portainer, Proxmox, rpcbind, SIP, Mgmt-Ports |
| login_portal_exposed | 17 | 3 | OWA, Roundcube, Nextcloud, OpenOTP, Bitwarden; im Prototyp ein Gelb-Befund |
| software_eol | 10 | 14 | KI: 11 davon falsch oder unbelegt (Abschnitt 3) |
| db_exposed | 8 | 8 | einzig vollständig deckungsgleiche Familie mit Gewicht |
| tls_legacy_protocols | 8 | 7 | |
| csrf_token_missing | 6 | 17 | ZAP-Alert in der API gekappt, Regel sieht ihn nicht immer |
| user_enumeration | 3 | 7 | wpscan-Details in API unvollständig |
| cert_hostname_mismatch | 4 | 1 | |
| cert_chain_incomplete | 6 | 3 | |
| dns_dangling | 3 | 0 | steht in `dns_findings.dangling_cnames`, KI nutzt es nicht |
| ssh_no_bruteforce | 0 | 2 | von außen nicht feststellbar; darf kein Befund sein |

Familien je Order: 242 in beiden, 79 nur KI, 284 nur Regeln. „Nur Regeln" sind überwiegend Hygiene-Familien, die die KI je nach Laune weglässt (HSTS, CAA, MTA-STS, DNSSEC, Header). „Nur KI" sind zur Hälfte Falschbefunde (Abschnitt 3), zur anderen Hälfte ZAP/wpscan-Details, die der API-Auszug nicht enthält.

### 2.3 Drift bei Wiederholungsläufen

Jaccard-Ähnlichkeit der Befundfamilien zwischen je zwei Läufen derselben Domain (1,0 = identisch):

| Domain | Läufe | KI: Familien gesamt / in allen / Ähnlichkeit | Regeln: gesamt / in allen / Ähnlichkeit |
|---|---|---|---|
| securess.de | 8 | 19 / 1 / 0,40 | 20 / 9 / 0,72 |
| heuel.com | 6 | 19 / 1 / 0,38 | 14 / 12 / 0,91 |
| dortmund-beach.com | 3 | 16 / 2 / 0,35 | 18 / 12 / 0,78 |
| castenow.de | 3 | 20 / 6 / 0,47 | 22 / 21 / 0,97 |
| rankingcoach.com | 2 | 9 / 4 / 0,44 | 11 / 10 / 0,91 |
| huendgen-entsorgung.de | 2 | 14 / 7 / 0,50 | 18 / 17 / 0,94 |

Bei securess.de (8 Läufe über zehn Wochen) ist genau eine KI-Familie in allen Läufen enthalten (CSP fehlt). Die Regeln liefern 9 stabile Familien; die restlichen Unterschiede sind reale Infrastrukturänderungen und Abdeckungsunterschiede (testssl und ZAP liefen nicht in jedem Lauf). Genau diese Unterschiede gehören in Kapitel 2 des Reports, nicht in die Befundliste.

Ausschnitt securess.de (K = KI, R = Regel, Spalten chronologisch):

```
Familie                      05-09 05-09 05-09 05-09 05-12 05-21 05-22 07-19
csp_missing                   KR    KR    KR    KR    KR    KR    KR    KR
hsts_missing                   R     R     R     R    KR     R     R    KR
dnssec_missing                 R     R     R     R    KR    KR     R     R
ftp_exposed                   K     K      .    K     K     K     K     K     (TLS erzwungen, Regel: Inventarnotiz)
software_eol                   .     .    KR     .    KR    KR    KR    K
admin_service_exposed          R    KR    KR    KR     .    K      .    KR
login_portal_exposed          KR     R     R    KR     R     R     R    KR
```

Die Regeln sind nicht getunt. Ein Katalog mit Fixtures je Regel würde die verbleibenden Regel-Unterschiede weiter auf Coverage-Ursachen reduzieren.

## 3. Falschbefunde in ausgelieferten Reports

Beim Abgleich der KI-Befunde mit den Rohdaten fallen systematische Fehler auf, die mit Regeln über Fakten nicht entstehen können. 36 von 390 Befunden (9 %) sind belegbar falsch oder defekt, verteilt über 12 Kunden (Zahl nach Fixture-Bau in S0c; zuvor 35):

| Muster | Befunde | Kunden | Ursache |
|---|---|---|---|
| „SPF-Record fehlt", SPF vorhanden | 7 | 7 | Titel-Template SP-DNS-004 über DKIM-Inhalt; `dns_findings.spf` wird nicht geprüft |
| „MySQL/MariaDB 5.5", real MariaDB 10.x, HIGH | 6 | 5 | Banner „5.5.5-10.11.x-MariaDB" ohne Präfix-Strip. Korrektur S0c: Der Befundtext ist in diesen Läufen korrekt, der Fehler sitzt in der Versionsableitung (Tech-Tabelle, EOL). Das Negativ-Fixture verbietet die Ableitung, nicht den Befund; sechs Einträge, weil der hu-Lauf dasselbe Banner trägt. trunk-immobilien.de hat echtes MariaDB 5.5.68 und ist deshalb kein Falschbefund |
| Policy „URLhaus-Kompromittierung" auf FTP/RDP/Plesk/Kubernetes, CRITICAL | 6 | 4 | Type-Mapper-Fehltreffer, Severity aus falscher Policy |
| POP3/IMAP „Klartext", STARTTLS vorhanden | 4 | 4 | Capabilities nicht ausgewertet |
| FTP „Klartext", TLS erzwungen, einmal CRITICAL | 2 | 1 | „requires SSL" ignoriert |
| „Nginx 1.24 EOL" (einmal CRITICAL), „Apache 2.4.41 EOL" | 3 | 3 | EOL-Behauptung ohne Herstellerbasis |
| Exchange 2016, real Exchange SE | 1 | 1 | Build 15.2.x nicht geprüft |
| Platzhalter `{host}` oder `[Hinweis: …]` im Titel | 5 | 3 | Template-Variable leer, Prompt-Hinweis durchgereicht |
| „WordPress-Plugin 27" (27 = Theme-Version) | 2 | 1 | Smart-Var-Fallback greift falsche Zahl |

Die Zahl ist eine Untergrenze: Geprüft wurden nur Muster, die sich aus den API-Rohdaten belegen lassen. Sieben dieser Kunden haben den Report als „delivered" erhalten. Jeder dieser Fehler ist eine Regel im Katalog (SPF-Regel liest `dns.spf`; Versionsnormalisierung strippt MariaDB-Präfix; FTP-Regel liest `tls_required`; Mail-Regel liest STARTTLS-Capability; EOL nur aus Feed mit Produktfamilie).

Dazu Befunde, die die KI erzeugt, obwohl der Sachverhalt von außen nicht feststellbar ist („SSH ohne Brute-Force-Schutz", 2 Fälle). Ein Katalog kann solche Befunde nicht erzeugen, weil es keinen Fakt gibt, auf den eine Regel passen könnte.

## 4. Was passiert mit Sachverhalten, die nicht im Katalog stehen

Nichts wird stillschweigend verworfen. Drei Stufen:

**Stufe 1, Ignorierliste (explizit, versioniert).** ZAP-Informationsalerts ohne Sicherheitsaussage („Modern Web Application", „Session Management Response Identified", „Retrieved from Cache", „Authentication Request Identified") stehen in einer Ignorierliste mit Begründung. In der Simulation betrifft das 92 Alert-Vorkommen. Die Liste ist Teil des Katalogs und wird wie eine Regel gepflegt.

**Stufe 2, generische Auffangregeln.** Sie erzeugen keinen bewerteten Befund, sondern einen Inventareintrag mit Prüfschritt:

- Offener Port außerhalb der bekannten Listen → Zeile in Kapitel 3 „Dienste", Spalte Bewertung „nicht bewertet, Prüfschritt: Zweck klären". Simulation: 12 verschiedene Ports (222/30000/987 als alternativer SSH, 8800 Icecast, 8001/8002/5000 unbekannt, 4443 IIS, 8088/8081 nginx, 26 SMTP), 24 Vorkommen. Daraus werden zwei Regeln (SSH auf Nicht-Standardport; HTTP-Dienst auf Alternativport) und der Rest bleibt generisch.
- ZAP-Alert ohne Zuordnung → Anhang „Werkzeugbefunde ohne Bewertung" mit ZAP-Text als Nachweis, ohne Einstufung. Simulation nach Ignorierliste: 3 Vorkommen („Cross-Domain Misconfiguration").
- Passivquelle (Shodan) mit Port, den nmap nicht bestätigt → Inventarzeile „laut Passivquelle, nicht verifiziert".

**Stufe 3, Sichtbarkeit.** Jede Beobachtung aus Stufe 2 landet zusätzlich in `facts.json` unter `unprocessed` und im Admin-Review als Liste „Beobachtungen ohne Regel". Das Gate zählt sie: mehr als N unverarbeitete Beobachtungen je Report (Vorschlag N = 5) ergibt eine Warnung, damit ein Kunde mit ungewöhnlicher Infrastruktur nicht mit einem dünnen Report abgespeist wird. Die Liste über alle Scans ist eine DB-Abfrage und die Arbeitsvorlage für die Katalogpflege.

Der Unterschied zum heutigen System: Heute erzeugt die KI für Unbekanntes irgendetwas (SP-FALLBACK, 28 % der Befunde), mit Titel, Severity und CVSS. Im Katalogmodell erzeugt Unbekanntes eine ehrliche Inventarzeile und eine Aufgabe für den Betreiber. Lieber ein unbewerteter Dienst, den der Kunde sieht, als ein erfundener Befund.

Restmenge in der Simulation nach Ignorierliste und Auffangregeln: 27 Vorkommen in 36 Scans, weniger als eines je Scan.

## 5. Wie neue Einträge in den Katalog kommen

Der Katalog ist ein Verzeichnis im Repo (`report-worker/reporter/catalog/`): eine YAML-Datei je Regel (Muster, Einstufung, Konsolidierung, Textbausteine, Referenzen), eine Ignorierliste, ein Fixture je Regel unter `tests/golden/`. Version über `CATALOG_VERSION` analog zu `POLICY_VERSION`, jede Änderung bumpt die Version und steht im Report-Impressum.

Vier Wege hinein:

1. **Aus dem Admin-Review (Regelfall).** Liste „Beobachtungen ohne Regel" → Admin markiert eine Beobachtung → KI (Sonnet) erzeugt aus Beobachtung und ähnlichen bestehenden Regeln einen Vorschlag: YAML-Regel, Textbausteine, Fixture aus dem aktuellen Scan → Admin prüft und bestätigt → Pull Request mit Regel und Fixture → Golden-Test läuft → Merge → Version-Bump. Der Report, der die Beobachtung enthielt, kann regeneriert werden. Aufwand je Regel etwa eine Stunde, davon Minuten für den Menschen.
2. **Aus Feeds (automatisch, ohne Katalogänderung).** EOL-Daten (endoflife.date), CVE/EPSS/KEV (NVD, FIRST, CISA), Known-Vuln-Builds. Diese Daten sind Parameter der Regeln R-EOL und R-CVE, keine neuen Regeln. Ein neues Exchange-EOL-Datum erzeugt keinen Katalog-Commit.
3. **Aus Werkzeug-Katalogen (einmalig, dann Pflege).** ZAP hat rund 150 Alert-Typen mit festen IDs (pluginId), nmap eine feste Service-Namensliste, testssl feste Prüf-IDs. Jede dieser Listen wird einmal vollständig durchgesehen und jeder Eintrag einer Regel, der Ignorierliste oder der Auffangregel zugeordnet. Danach kann ein Werkzeug-Update neue IDs bringen; die Auffangregel fängt sie, Weg 1 ordnet sie zu.
4. **Aus Kundenrückmeldungen.** Ein Kunde widerspricht einem Befund → der Fall wird Fixture („dieser Fakt darf diesen Befund nicht erzeugen"), die Regel wird enger, Golden-Test schützt vor Rückfall. Das ist der Weg, auf dem die 35 Falschbefunde aus Abschnitt 3 heute schon Fixtures werden sollten, bevor der Katalog produktiv geht.

Pflegerhythmus: wöchentlich die Liste „Beobachtungen ohne Regel" über alle Scans (eine Abfrage), monatlich Feeds prüfen. Erwartung aus der Sättigungskurve: in den ersten zehn Kunden ein bis vier neue Regeln je Kunde, danach unter einer je Kunde.

## 6. Konsequenzen für spec/05

- M2 Regelkatalog: Startgröße 42 Regeln plus Ignorierliste plus 3 Auffangregeln, belegt durch diese Simulation. `build/catalog_sim.py` ist die Vorlage für Regelmuster und Familien.
- M1 facts.json: die drei Faktenquellen, die die KI heute ignoriert, müssen rein: `dns_findings` (SPF, DKIM, Dangling), `x-feserver`/OWA-Build, nmap-Capabilities (STARTTLS, „requires SSL").
- M7 Golden-Files: die 35 Falschbefunde aus Abschnitt 3 werden Negativ-Fixtures, die Wiederholungsläufe von securess.de und heuel.com werden Drift-Fixtures.
- M5 Coverage: in den 10 jüngeren Läufen `zap_active_failed` 30-mal, `ffuf` 82-mal übersprungen (Wordlist fehlt), `vhost_unreachable` 18-mal. Das steht heute in keinem Report.
- M6 Gate: zusätzlicher Check „unverarbeitete Beobachtungen > N".

## 7. Werkzeugabdeckung über alle 36 Scans

Status je Tool-Run aus `results.json` (Läufe vor Juli ohne `status`-Feld, dort aus dem Rohtext abgeleitet). Spalte „Katalog" sagt, ob der Entwurfskatalog die Ausgabe heute liest, und welche Prüfungen sonst daraus entstünden.

| Phase | Tool | ok | leer | übersprungen | fehlgeschlagen | Häufigster Grund | Katalog |
|---|---|---|---|---|---|---|---|
| 0 | dns_records, dnsx, web_probe, certspotter | 36 | 0 | 0 | 0 | | ja (DNS/Mail, Scope) |
| 0 | subfinder, crtsh | 35 | 1 | 0 | 0 | | Scope; CT-Logs als Prüfung „Zertifikate für unbekannte Hosts" |
| 0 | gobuster_dns | 28 | 0 | 0 | 0 | | Scope |
| 0 | shodan, abuseipdb, dns_security | 14 | 0 | 0 | 0 | erst seit Juli | ja (Passivports, DNSSEC/CAA/MTA-STS); IP-Reputation als Prüfung |
| 0 | greynoise, otx, securitytrails, whois, urlhaus | 7 | 0 | 7 | 0 | not_in_package | urlhaus ja; whois als Prüfung „Domain-Ablauf"; Rest Reputation |
| 0 | virustotal | 0 | 0 | 14 | 0 | no_api_key | nie gelaufen |
| 0 | ai_host_strategy | 36 | | | | | Protokoll |
| 1 | nmap | 133 | 0 | 1 | 0 | host_unreachable | ja (Dienste, Ports, TLS-Zwang, Capabilities) |
| 1 | wafw00f | 255 | 0 | 1 | 0 | | Prüfung „WAF vorhanden" (positiv) und Coverage |
| 1 | webtech | 123 | 0 | 1 | 10 | no_tech_signals | Inventar, EOL-Eingang |
| 1 | ai_phase2_config | 133 | | | | | Protokoll |
| 2 | header_check | 252 | 0 | 1 | 0 | | ja (Header, X-FEServer, PHP-Version) |
| 2 | httpx | 237 | 15 | 1 | 0 | | ja (Titel, Tech, Zertifikat) |
| 2 | testssl | 55 | 0 | 10 | 5 | no_ssl, connect | ja (Protokolle, Cipher, Zertifikat, Schwachstellen) |
| 2 | zap (passiv), zap_spider | 70 | 0 | 11 | 2 | no_zap_context | ja (Alerts); Spider als URL-Inventar |
| 2 | zap_active | 0 | 0 | 12 | 30 | ZAP API 400 does_not_exist | nie erfolgreich gelaufen |
| 2 | feroxbuster | 56 | 0 | 17 | 0 | ai_skip | Prüfung „sensible Pfade erreichbar" (.git, .env, Backups, Admin) |
| 2 | ffuf_param | 10 | 0 | 40 | 0 | no_api_urls | dito |
| 2 | ffuf_sensitive | 0 | 0 | 42 | 0 | wordlist_missing | nie gelaufen |
| 2 | wpscan | 11 | 0 | 40 | 0 | cms_not_wordpress | ja (Plugins, Core, Nutzer) |
| 3 | phase3_correlation | 36 | 0 | 0 | 0 | | CVE-Anreicherung als Prüfung „bekannte CVE in erkannter Version" |

Drei Werkzeuge haben in keinem der 36 Scans ein Ergebnis geliefert: `zap_active` (30 Fehlschläge, 12 Skips), `ffuf_sensitive` (Wordlist fehlt im Image), `virustotal` (kein Key). Die Methodik-Seite jedes ausgelieferten Reports nennt „Schwachstellen-Scan (ZAP Active Scan)" und „Directory-Enumeration (ffuf)". Im Prüfkatalog-Modell erschienen diese als „nicht prüfbar" mit Grund in jedem Report, was der schnellste Weg ist, sie zu reparieren.

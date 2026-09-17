# Rohdaten-Analyse Junkerwerk (drei Perimeter-Läufe vom 31.08.2026)

Intern. Grundlage für den kuratierten Report. Quellen: `input/{multi,de,hu}/results.json`
(131 / 134 / 65 Tool-Läufe), `order.json` (Passive Intel), `findings.json` (Pipeline-Output),
`correlation.json`. Alle Aussagen unten sind gegen den Roh-Output geprüft; wo nur eine
Passivquelle (Shodan) vorliegt, ist das markiert.

## Kunde und Infrastruktur

- Junkerwerk Linder GmbH & Co. KG, Schaumstoffverarbeitung, Solingen (Website-Titel
  „Home - Junkerwerk - Schaumstoffverarbeitung"; AbuseIPDB-ISP-Feld „Junkerwerk Linder GmbH & Co."
  für 217.243.248.27 bis .30; SMTP-Banner „junkerwerk-solingen.de").
- Domains im Scope: junkerwerk.de, junkerwerk.hu. Beide: NS united-domains (ns.udag.de/.net/.org),
  MX Hornetsecurity (mx01 bis mx04), identischer SPF-Record, DKIM-Selektoren hse1/hse2, kein DMARC,
  kein DNSSEC, kein CAA, kein MTA-STS, kein TLS-RPT, kein DANE.
- Außerhalb des Scope, aber sichtbar: www.junkerwerk.com (Redirect-Ziel von Port 80 auf 188.40.3.130),
  junkerwerk-solingen.de (SMTP-Banner .28, historischer MX), erbbauverein.de (weitere Domain auf dem
  Hetzner-Server laut Shodan, also Shared Hosting).

| Host | rDNS / Betreiber | FQDNs | Rolle (belegt) |
|---|---|---|---|
| 188.40.3.130 | dedi2230.your-server.de, Hetzner Managed Server | junkerwerk.de, www.junkerwerk.de, nachhaltigkeit.junkerwerk.de, junkerwerk.hu, www.junkerwerk.hu | Webserver + Mail-Relay des Hosters, MariaDB, PostgreSQL |
| 2a01:4f8:d0a:3124::2 | Hetzner (gleicher Server, IPv6) | nachhaltigkeit.junkerwerk.de (AAAA) | wie oben, nicht gescannt |
| 217.243.248.28 | Telekom-Festverbindung Junkerwerk | mail., outlook., autodiscover.junkerwerk.de | Exchange Server SE (OWA), SonicWall (Shodan) |
| 217.243.248.29 | Junkerwerk | cloud., team., rdgw., rdgw-2016.junkerwerk.de | Windows/IIS 10, Standardseite auf 443 und 8443; Name deutet auf RD-Gateway |
| 217.243.248.30 | Junkerwerk | openotp.junkerwerk.de, openotp.junkerwerk.hu (CNAME auf .de) | RCDevs WebADM/OpenOTP-Portal (Apache); Exim 4.96 auf 25 (Shodan, archiv.junkerwerk.de) |
| 217.243.248.27 | Junkerwerk | ticket.junkerwerk.de | keine erreichbaren Ports |

## Verifizierte Fakten pro Host

### 188.40.3.130 (nmap 7.93, 31.08. 14:16, alle drei Läufe identisch)
- 21 ProFTPD „requires SSL" (AUTH TLS erzwungen, Shodan-Banner: „550 SSL/TLS required on the control channel").
- 22 ProFTPD mod_sftp; 222 OpenSSH 9.2p1 (Debian 12, gepflegtes Distributionspaket).
- 80/443 Apache, Direktaufruf per IP: 404 bzw. 403; Port 80 leitet laut Shodan auf https://www.junkerwerk.com/.
- 110 Courier POP3 mit STLS; 143 Dovecot IMAP mit STARTTLS und LOGINDISABLED vor TLS; 993/995 TLS.
- 465 Exim SMTPS (AUTH LOGIN PLAIN nur im TLS-Kanal); 587 Submission, AUTH erst nach STARTTLS.
- 3306 MariaDB 10.11.18-0+deb12u1 (Handshake beantwortet, mysql_native_password). Versions-String
  „5.5.5-10.11.18-MariaDB": der Präfix 5.5.5 ist der MariaDB-Kompatibilitätsstring. 10.11 ist LTS
  (Support bis Februar 2028). Kein EOL.
- 5432 PostgreSQL „9.6.0 or later": Version nicht bestimmbar. Shodan-Banner zeigt „no pg_hba.conf entry
  for host …": Verbindungen fremder Quellen werden auf DB-Ebene abgewiesen, der Port ist aber offen.
- Zertifikat auf allen Diensten: *.your-server.de (Hetzner), gültig bis 02.11.2026.
- Phase 2 (Web-Tests ab 14:29) gegen diesen Host komplett fehlgeschlagen: testssl „Can't connect",
  header_check „reachable: false" für www/junkerwerk.de/nachhaltigkeit, httpx null. Der Host oder
  Hetzner hat die Scanner-IP nach dem Portscan blockiert. Gilt für alle drei Läufe (hu-Lauf: has_web=false).
  Folge: Website www.junkerwerk.de und www.junkerwerk.hu auf Applikationsebene NICHT geprüft.

### 217.243.248.28 (Exchange)
- nmap: nur 443 offen, 999 Ports closed (RST). Shodan (30.08.): 25 (Banner junkerwerk-solingen.de, STARTTLS)
  und 4433 (SonicWall-Webinterface). Beides vom Scanner aus nicht erreichbar, also vermutlich
  quell-IP-abhängige Firewall-Regeln.
- httpx: Outlook Web App 15.2.2562, IIS 10.0, ASP.NET 4.0.30319. header_check: `x-feserver: EXCHANGE-SE`.
  Build 15.2.2562 ist die RTM-Linie von Exchange Server Subscription Edition (Juli 2025).
  Damit ist VS-2026-001 aus dem Multi-Lauf („Exchange 2016 EOL", 9.1) ein Falschbefund.
  SU-/CU-Stand ist von außen nicht feststellbar.
- testssl: TLS 1.2 + 1.3, keine Altprotokolle, FS, CBC-Suiten vorhanden, kein HSTS. Sectigo-Wildcard
  *.junkerwerk.de RSA 4096, gültig bis 11.12.2026, Chain OK, OCSP Stapling.
- Security-Header 0/7 auf mail/outlook/autodiscover. Kein WAF erkannt.

### 217.243.248.29 (cloud/team/rdgw/rdgw-2016)
- nmap: 443 und 8443 IIS 10.0, Titel „IIS Windows Server" (Standardseite), TRACE erlaubt. Alle vier
  FQDNs liefern denselben Body-Hash. feroxbuster: nur / und /aspnet_client.
- testssl: TLS 1.0 und 1.1 angeboten, CBC-Suiten, TLS_FALLBACK_SCSV fehlt, kein HSTS, Grade B.
- Security-Header 0/7, X-Powered-By: ASP.NET.
- RD-Gateway-Funktion (/RDWeb, /rpc) wurde nicht geprüft; Aussage nur aus der Namensgebung.

### 217.243.248.30 (openotp)
- nmap: 443 Apache, Titel „Junkerwerk Linder GmbH & Co.KG Web Applications Portal" (RCDevs WebADM,
  Pfade /openid/, /selfdesk/). Port 25 vom Scanner aus gefiltert; Shodan: Exim 4.96, Banner archiv.junkerwerk.de.
- testssl: nur TLS 1.2 (kein 1.3), 3DES-Suiten (SWEET32), HSTS max-age 86400, gzip aktiv (BREACH potenziell).
- Header: CSP mit 'unsafe-inline' 'unsafe-eval', X-Frame-Options doppelt, Cache-Control doppelt.
  ZAP passiv: Absence of Anti-CSRF Tokens (Login-Formular /openid/login_uid.php).
- openotp.junkerwerk.hu: CNAME auf openotp.junkerwerk.de, ausgeliefertes Zertifikat *.junkerwerk.de,
  httpx `mismatched: true`. Echter Befund (Zertifikatswarnung im Browser).

### 217.243.248.27 und IPv6
- .27: keine offenen Ports, kein Web. IPv6-Host: nmap-Output leer, httpx leer; nicht geprüft.

## Falschbefunde und Übertreibungen im Pipeline-Output

| Pipeline-Befund | Lauf | Bewertung | Beleg |
|---|---|---|---|
| Exchange 2016 EOL (9.1) | multi | falsch | OWA 15.2.2562, x-feserver EXCHANGE-SE |
| MySQL 5.5 EOL 2018 (Tech-Tabelle) | alle | falsch | MariaDB 10.11.18, LTS |
| PostgreSQL 9.6 EOL 2021 | alle | unbelegt | nmap „9.6.0 or later" |
| SPF-Record fehlt (4.7) | multi, de | falsch | SPF vorhanden, ~all; de-Lauf hat gleichzeitig Positivbefund „SPF korrekt" |
| FTP Klartext (5.3) | multi, de | falsch | ProFTPD requires SSL |
| IMAP/POP3 Klartext (3.7) | de | falsch | STARTTLS/STLS, LOGINDISABLED |
| TLS unter TR-03116 als HIGH 9.1 | multi | überzogen | gleiche Evidenz im de-Lauf MEDIUM 5.9 |
| OpenSSH 9.2p1 CVE (8.1) | hu | unbelegt | Debian-Paket mit Backports, CVE-Guard hat die CVE entfernt, Befund blieb |
| SSH ohne Brute-Force-Schutz (4.8) | multi | unbelegt | von außen nicht prüfbar |
| Anti-CSRF doppelt (012/014, 010/011) | multi, hu | Dublette | ValidationGate-Error, Report trotzdem erzeugt |
| Empfehlung „188.40.3.130-Ableger cloud.junkerwerk.de" | multi | falsch | cloud ist 217.243.248.29 |
| INFO-Befunde mit CVSS 4.3 | alle | inkonsistent | Severity und Score entkoppelt |

## Methodische Einschränkungen (gehören transparent in den Report)

1. Hauptwebsite (www.junkerwerk.de, www.junkerwerk.hu, nachhaltigkeit) nach dem Portscan nicht mehr
   erreichbar für den Scanner: keine Header-, TLS-, Spider- oder Schwachstellenprüfung der Website.
2. IPv6-Adresse nicht geprüft.
3. Aktive Web-Schwachstellentests (ZAP active) in diesem Lauf nicht ausgeführt (API-Fehler); nur passive Analyse.
4. Datei-/Parameter-Fuzzing (ffuf) nicht ausgeführt (Wordlist fehlte). Directory-Enumeration (feroxbuster) lief.
5. VirusTotal ohne API-Key, crt.sh nicht erreichbar (404), gobuster_dns Timeout nach 180 s.
6. Ports außerhalb der nmap-Top-1000 (z. B. 4433) nur über Shodan; Port 25 auf .28/.30 nur über Shodan.
7. Keine authentifizierten Prüfungen, keine Innenperspektive, kein Social Engineering.

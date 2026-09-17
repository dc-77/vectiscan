# Scan-Drift: drei Perimeter-Läufe auf dieselbe Infrastruktur (31.08.2026)

Intern, Vorlage für die Claude-Code-Session. Vergleich der Pipeline-Ergebnisse
(`findings.json`, `policy_version 2026-06-01.1`, Report-Modell claude-opus-4-7) für

| Label | Order | Ziel | Hosts | Findings (C/H/M/L/I) | overall | business_impact |
|---|---|---|---|---|---|---|
| multi | 0bf16342 | junkerwerk.de + .hu | 6 | 14 (0/3/4/3/4) | HIGH | 5.0 |
| de | 2572eebc | junkerwerk.de | 6 | 11 (0/1/3/4/3) | HIGH | 5.0 |
| hu | a6df9d9d | junkerwerk.hu | 2 | 12 (0/3/3/3/3) | HIGH | 6.5 |

Die Rohdaten (nmap, testssl, header_check, DNS) sind über alle drei Läufe praktisch identisch.
Die Unterschiede entstehen in der Reporter-Stufe (KI-Befundgenerierung, Type-Mapping, Severity-Policy).

## 1. Befund-Matrix

| Sachverhalt (Rohdaten) | multi | de | hu | Korrekt wäre |
|---|---|---|---|---|
| MariaDB 3306 exponiert | HIGH 8.1 | HIGH 8.1 | fehlt | HIGH, ein Befund für 3306 + 5432 |
| PostgreSQL 5432 exponiert | nur in Recommendation | fehlt | HIGH 8.1 | s. o. |
| Exchange-Version | „2016 EOL" HIGH 9.1 | kein Befund | n/a | kein Befund (Exchange SE) |
| SPF junkerwerk.de/.hu | „fehlt" MEDIUM 4.7 | „fehlt" MEDIUM 4.7 + Positivbefund „SPF korrekt" | „softfail" LOW 5.3 | DMARC fehlt (MEDIUM), SPF ~all als Hinweis |
| FTP Port 21 | „Klartext" MEDIUM 5.3 | „Klartext" MEDIUM 5.3 | fehlt | kein Befund (TLS erzwungen) |
| IMAP/POP3 110/143 | fehlt | „Klartext" LOW 3.7 | fehlt | kein Befund (STARTTLS, LOGINDISABLED) |
| TLS cloud.junkerwerk.de (1.0/1.1) | „unter TR-03116" HIGH 9.1 | Banner-Befund LOW 3.1 | n/a | MEDIUM/Hygiene |
| 3DES openotp | MEDIUM 5.9 | MEDIUM 5.9 | MEDIUM 5.9 (als software_eol getypt) | MEDIUM, konsistent |
| Cert-Mismatch openotp.junkerwerk.hu | n/a | n/a | HIGH 7.4 | MEDIUM/Hygiene hoch, echter Befund |
| Exim 4.96 (Shodan) | fehlt | fehlt | MEDIUM 5.3 | MEDIUM mit Passiv-Kennzeichnung |
| OpenSSH 9.2p1 | „ohne Brute-Force-Schutz" LOW 4.8 | fehlt | „CVE" HIGH 8.1 (CVE per Guard entfernt) | kein Befund |
| DNSSEC | fehlt | fehlt | LOW 3.7 | LOW/Hygiene, beide Domains |
| CSP unsafe-inline openotp | MEDIUM 4.3 | fehlt | MEDIUM 6.1 | MEDIUM, konsistent |
| HSTS max-age openotp | INFO 4.2 | INFO 3.1 | INFO 4.3 | Hygiene niedrig |
| Anti-CSRF openotp | INFO 4.3 + INFO 3.1 (Dublette) | INFO 3.1 | INFO 5.3 + INFO 4.3 (Dublette) | ein Hygiene-Befund |
| X-Frame-Options doppelt | LOW 3.1 | LOW 3.1 (mit Cache-Control) | LOW 3.1 | Hygiene niedrig |
| Server-Banner | LOW 3.1 (mail) | LOW 5.3 (mail) + LOW 3.1 (cloud) | fehlt | ein Hygiene-Befund |
| CSP fehlt cloud | INFO 4.3 | INFO 4.3 | n/a | Teil Header-Befund |
| SonicWall 4433 (Shodan) | fehlt (nur in KI-Strategie erwähnt) | fehlt | n/a | GELB-Befund, passiv gekennzeichnet |
| RD-Gateway-Hinweis (rdgw, rdgw-2016) | fehlt | fehlt | n/a | GELB-Befund |
| IIS-Standardseite 443/8443 | fehlt | fehlt | n/a | Teil RD-Gateway-Befund |

Nur 4 von 22 Sachverhalten werden in allen zutreffenden Läufen gleich bewertet.
Drei Sachverhalte mit realer Relevanz (SonicWall, RD-Gateway, PostgreSQL im de-Lauf) fehlen ganz.

## 2. Beobachtete Ursachen (mit Anknüpfpunkten im Code)

1. **EOL-Detector** parst „5.5.5-10.11.18-MariaDB" als MySQL 5.5 und „9.6.0 or later" als 9.6.0.
   Fix: MariaDB-Kompatibilitätspräfix strippen, „or later"/Ranges als unbekannt führen (`eol_detector.py`,
   `tech_table_builder.py`).
2. **CMS-Fingerprint „Exchange 2016"** (Konfidenz 0.95) gegen OWA-Build 15.2.x ohne Plausibilitätscheck.
   Fix: Build-Tabelle 15.1.x = 2016, 15.2.x = 2019/SE; `x-feserver`-Header auswerten; Tech-Zeile
   und Finding aus derselben Quelle ableiten (`title_policy.py`, `severity_policy.py` SP-EOL-001).
3. **SPF-Erkennung** liest offenbar `dns_security` (dort kein spf-Key) statt `dns_records.spf`.
   Gleichzeitig Positivbefund aus der KI: Widerspruch im selben Report (ValidationGate prüft das nicht).
4. **Protokoll-Befunde ignorieren TLS-Zwang**: nmap „requires SSL", POP3 STLS, IMAP LOGINDISABLED.
   Fix: Klartext-Befunde nur, wenn AUTH ohne TLS tatsächlich angeboten wird.
5. **Severity-Drift bei gleicher Evidenz** (TLS 1.0/1.1: 9.1 vs. 3.1). SP-TLS-001 liefert 9.1 für
   TR-03116-Abweichung; das ist Hygiene, kein 9.1. Policy-Regel prüfen.
6. **SP-FALLBACK** in 3 bis 6 Befunden je Lauf: Type-Mapper erkennt FTP, XFO-Dubletten, Cert-Mismatch,
   Exim-Version nicht. Fallback-Befunde bekommen KI-Titel mit variabler Qualität.
7. **Dubletten passieren das Gate**: `titles`-Check meldet Error, Level `warn`, PDF wird trotzdem
   ausgeliefert (Order-Status pending_review). Bei Error sollte der Report nicht generiert werden
   oder die Dublette gemerged werden.
8. **CVE-Guard entfernt CVE, Befund bleibt** (hu VS-001 OpenSSH): Guard muss den Befund auf
   „unbelegt" herabstufen oder entfernen, nicht nur den Text säubern.
9. **KI-Titel mit internen Hinweisen** („[Hinweis: exchange wird laut Scan-Inventar …]") gelangen ins PDF.
10. **Shodan-Daten** landen ungekennzeichnet in der Tech-Tabelle (Dubletten, „Port 110 | unbekannt")
    und fehlen zugleich als Befund (SonicWall 4433). Passivquellen brauchen ein eigenes Feld `verified: false`.
11. **Scanner-Blockade nach nmap** (Hetzner) wird nicht erkannt: alle Phase-2-Tools melden „ok" mit leerem
    Ergebnis, der Report behauptet implizit vollständige Prüfung. Fix: reachable=false pro VHost als
    Coverage-Lücke in Kapitel „Umfang" ausweisen (C3-Abdeckungskapitel existiert, erfasst das aber nicht).
12. **IPv6-Hosts**: nmap liefert leeren Output ohne Fehlerstatus.
13. **Toolausfälle** (zap_active API 400, ffuf Wordlist, VirusTotal-Key, crt.sh 404) sind im Report unsichtbar.
14. **Severity vs. CVSS** entkoppelt (INFO mit 4.3, LOW mit 4.8/5.3): P1-01/P1-02 aus der Fehleranalyse weiterhin offen.
15. **Recommendation-Zeitraster** („Sofort / Tag 1-3 / Woche 1 / Monat 1") weicht von der Spec
    (Unverzüglich / In Kürze / Mittelfristig / Strategisch) ab.
16. **Multi-Target-Cover** nennt nur junkerwerk.de; die zweite Domain fehlt auf Cover und in der Ampel.

## 3. Was der Prototyp anders macht

- Ein Befund pro Sachverhalt, hostübergreifend konsolidiert, mit Quelle (aktiv/passiv) am Befund.
- Triage: Status (Rot/Gelb/Grün/Blau) plus Dringlichkeit statt reiner CVSS-Sortierung; CVSS nur bei
  ausnutzbaren Schwachstellen, Hygiene-Skala für Best-Practice-Abweichungen.
- Abdeckungslücken stehen im Kapitel „Umfang" mit Klartext, nicht im Anhang.
- Passivquellen (Shodan) werden als solche gekennzeichnet und mit Verifikationsschritt versehen.

## 4. Nachträge 17.09.2026 (weitere Erkenntnisse aus der Prototyp-Arbeit)

17. **„PTES-konform" ist nicht haltbar** und steht an acht Stellen: `catalog/packages.catalog.json:41`
    (+ generierte `catalog.generated.ts` in api und frontend), `frontend/src/app/page.tsx:255/283/443`,
    `frontend/src/app/subscribe/page.tsx:29`, `report-worker/reporter/prompts.py:231`,
    `claude_client.py:61`, `pdf/v2/layers/strategy.py:159`, `report_mapper.py:522/1041`,
    `generate_report.py:832/1142/1939`, `CLAUDE.md:158`. Ein automatisierter Außenscan deckt von sieben
    PTES-Phasen drei ab (Aufklärung, Schwachstellenanalyse, Bericht). Ersatzformulierung im Prototyp,
    Kapitel 2.3.
18. **„KI-gestützt"** noch in `prompts.py`, `report_mapper.py`, `v2_data.py`, Homepage und Datenschutzseite.
19. **Gate-Level in Produktion ist `warn`** (`docker-compose.yml:550`, Default). Damit blockiert kein
    Check; die Dubletten-Errors der Junkerwerk-Läufe wurden nur in `reports.validation_warnings` abgelegt.
20. **KI-Kosten je Report:** `report_cost` Multi-Lauf 1,94 USD (claude-opus-4-7, 6.810 Input, 18.158 Output,
    25.418 Cache-Creation). Die KI schreibt den kompletten Befundsatz; das ist zugleich die Quelle der Drift.
21. **Website-Status:** www.junkerwerk.hu und nachhaltigkeit.junkerwerk.de antworten mit 403 Forbidden
    (Scan 31.08. und Nachaufnahme 17.09.). Kein Sicherheitsbefund, aber ein Hinweis für den Kunden.
22. **Screenshots:** Die Pipeline liefert nur Aufnahmen erreichbarer vHosts (5 Stück, OWA dreifach
    identisch). Für den Prototyp wurden www.de, www.hu, nachhaltigkeit am 17.09. per Playwright
    nachgeholt (`scripts/take-screenshots.py`). In der App braucht es einen zweiten Aufnahme-Pass nach
    dem Scan für vHosts mit `reachable=false`.
23. **Zertifikatswarnung nicht fotografierbar:** Chrome-Erweiterung und Container-Proxy liefern für
    Cert-Mismatch-Seiten keine Aufnahme (Fehlerseite). Nachweis bleibt httpx/testssl.
24. **Prototyp-Entscheidungen DC:** kein Eigen-CVSS (nur Fremdreferenz mit Quelle), Werkzeuge ohne
    Versionsnummer, Screenshots ohne Aufnahmedatum, Impressum am Seitenfuß, Berichtsdatum für den
    Prototyp 01.09.2026.

Konsolidierter Plan: `04-umsetzungsplan-report-v3.md`.

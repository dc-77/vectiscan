# Erstsichtung Order multi (junkerwerk.de + junkerwerk.hu), 2026-09-17

Quelle: `/api/orders/0bf16342…/findings` (findings_data, policy 2026-06-01.1),
Paket perimeter, overall HIGH, Counts H3 M4 L3 I4, 2 positive Befunde,
6 Hosts (188.40.3.130 Hetzner; 217.243.248.27/.28/.29/.30 Telekom; 2a01:4f8:d0a:3124::2).

## Auffälligkeiten im aktuellen Pipeline-Output (zu prüfen gegen Rohdaten)

EOL / Tech-Tabelle
- `MySQL 5.5.5-10.11.18-MariaDB-0+deb12u1` → als MySQL 5.5 EOL 2018-12-31 geführt.
  Der Präfix 5.5.5 ist der MariaDB-Kompatibilitätsstring, reale Version ist
  MariaDB 10.11.18 (Debian 12, LTS bis 2028). Falsch-EOL. Zusätzlich Dublette
  `MariaDB 10.11.18` aus Shodan mit Status unbekannt.
- `PostgreSQL DB 9.6.0 or later` → EOL 2021-11-11. nmap kann Version nicht
  bestimmen ("or later"), EOL-Aussage nicht belegbar.
- `Exchange 2016 (cms_fingerprint 0.95)` Status "aktuell" in der Tabelle, aber
  VS-2026-001 sagt "Exchange 2016 End-of-Life", CVSS 9.1. Widerspruch. OWA-Build
  15.2.2562 ist Exchange Server SE (RTM 15.2.2562.17, Juli 2025), nicht 2016
  (15.1.x). Verdacht: VS-2026-001 ist Falschbefund. Gegen httpx/OWA-Rohdaten prüfen.
- Viele Shodan-Zeilen ohne Aussage ("Port 110 | unbekannt", "Apache httpd" doppelt).

Findings
- VS-2026-001 Titel enthält internen Hinweis "[Hinweis: exchange wird laut Scan-Inventar als …".
- VS-2026-012 und VS-2026-014 identischer Titel (Anti-CSRF-Token fehlt …); die
  Empfehlung zu 014 spricht von BREACH, Titel passt nicht zum Inhalt.
- VS-2026-002 TLS unter TR-03116 als HIGH 9.1 bewertet; das ist Hygiene, kein 9.1.
- INFO-Befunde mit CVSS 4.2/4.3 (011, 012, 013), LOW mit 4.8 (008): Severity und Score laufen auseinander.
- Reihenfolge 010 vor 009.
- Recommendation zu VS-2026-002 nennt "188.40.3.130-Ableger cloud.junkerwerk.de";
  cloud.junkerwerk.de ist 217.243.248.29, anderes Netz. Falschaussage.
- VS-2026-003 Titel nur Port 3306, Recommendation nennt zusätzlich 5432.
- Zeitraster der Maßnahmen "Sofort / Tag 1-3 / Woche 1 / Monat 1" statt der
  Spec-Stufen Unverzüglich / In Kürze / Mittelfristig / Strategisch.
- SP-FALLBACK bei 005, 007, 010 (kein Policy-Match).

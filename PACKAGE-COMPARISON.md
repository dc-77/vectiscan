# VectiScan — Paketvergleich

## Übersicht

| Feature | Basic | Professional | NIS2 Compliance |
|---------|-------|-------------|-----------------|
| **Scan-Dauer** | ~10 Min | ~45 Min | ~45 Min |
| **Max. Hosts** | 3 | 10 | 10 |
| **DNS-Reconnaissance** | crt.sh, subfinder | crt.sh, subfinder, amass, gobuster, axfr, dnsx | Wie Professional |
| **Port-Scan** | Top 100 | Top 1000 | Top 1000 |
| **Phase-1-Tools** | nmap, webtech, wafw00f | nmap, webtech, wafw00f | Wie Professional |
| **Phase-2-Tools** | testssl, headers, gowitness | testssl, nikto, nuclei, gobuster_dir, gowitness, headers | Wie Professional |
| **CVSS-Vektoren** | Nein | Ja (CVSS v3.1) | Ja (CVSS v3.1) |
| **CWE-Referenz** | Nein | Ja | Ja |
| **Evidence-Blöcke** | Nein | Ja | Ja |
| **Appendix CVSS** | Nein | Ja | Ja |
| **Appendix Tools** | Nein | Ja | Ja |
| **NIS2-Compliance** | Nein | Nein | Ja (§30 BSIG) |
| **Audit-Trail** | Nein | Nein | Ja |
| **Lieferketten-1-Seiter** | Nein | Nein | Ja |
| **Max. Empfehlungen** | 3 | Unbegrenzt | Unbegrenzt |
| **Claude max_tokens** | 2.048 | 4.096 | 6.144 |

## Report-Umfang (geschätzt)

| Paket | Seitenanzahl | PDF-Größe |
|-------|-------------|-----------|
| Basic | 5–8 Seiten | ~50–150 KB |
| Professional | 15–25 Seiten | ~200–500 KB |
| NIS2 Compliance | 20–30 Seiten | ~300–700 KB |

## Report-Aufbau nach Paket

### Basic
1. Cover (mit "Basic"-Badge)
2. Zusammenfassung (Gesamtbewertung + Befundübersicht)
3. Umfang & Methodik (vereinfacht: Port-Scan, Header, SSL, Screenshot)
4. Befunde (ohne CVSS, ohne Evidence)
5. Empfehlungen (max. 3, nur Maßnahme + Zeitrahmen)

### Professional
1. Cover (mit "Professional"-Badge)
2. Inhaltsverzeichnis (mit Finding-Untereinträgen)
3. Zusammenfassung
4. Umfang & Methodik (PTES, drei Phasen)
5. Befunde (mit CVSS-Vektor, CWE, Evidence, Impact)
6. Maßnahmenplan (mit Befund-Ref. + Aufwand)
7. Anhang A: CVSS-Referenz
8. Anhang B: Eingesetzte Tools

### NIS2 Compliance
1. Cover (mit "NIS2 Compliance"-Badge in Gold)
2. Inhaltsverzeichnis (inkl. NIS2-Sections)
3. Zusammenfassung
4. Umfang & Methodik
5. Befunde (mit §30 BSIG Referenz-Badge)
6. Maßnahmenplan
7. NIS2-Compliance-Übersicht (§30 BSIG Tabelle, 6 Zeilen)
8. Audit-Trail (Scan-Metadaten, Tool-Versionen)
9. Lieferketten-Bewertung (1-Seiter zum Ausdrucken)
10. Anhang A: CVSS-Referenz
11. Anhang B: Eingesetzte Tools

## Beispiel-PDFs

Beispiel-Reports finden sich unter `docs/examples/`:
- `example-basic.pdf`
- `example-professional.pdf`
- `example-nis2.pdf`

Diese wurden aus synthetischen Testdaten generiert und zeigen die Struktur
jedes Report-Typs.

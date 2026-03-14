# VectiScan — Bekannte Probleme

## Paket-Integration

### ~~P1: Audit-Trail Tool-Versionen leer~~ (BEHOBEN)
- **Status:** Behoben — Tool-Versionen werden beim Scan-Start erfasst
  (`_collect_tool_versions()` in `worker.py`), in `meta.json` geschrieben
  und vom Report-Worker in den NIS2-Audit-Trail übernommen.

### P2: Lieferketten-Seite Layout bei vielen Findings
- **Betrifft:** NIS2-Paket
- **Beschreibung:** Bei mehr als 8 Findings kann die Lieferketten-
  Zusammenfassung auf eine zweite Seite umbrechen, was den 1-Seiter-
  Charakter verletzt.
- **Workaround:** Keine — Claude sollte max. 8 Findings generieren.
- **Priorität:** Niedrig

### P3: Basic-Paket zeigt "Phase 0" Tools im Scope
- **Betrifft:** Basic-Paket
- **Beschreibung:** Der Scope-Abschnitt erwähnt nur die vereinfachten
  Tools (Port-Scan, Header, SSL, Screenshot), aber die Phase-0-Tools
  (crt.sh, subfinder) werden nicht explizit gelistet.
- **Workaround:** Keine nötig — Phase-0-Tools sind korrekt konfiguriert.
- **Priorität:** Info

### P4: Keine E-Mail-Benachrichtigung bei Scan-Abschluss
- **Betrifft:** Alle Pakete
- **Beschreibung:** Es gibt keine E-Mail-Benachrichtigung, wenn ein Scan
  abgeschlossen ist.
- **Workaround:** Browser-Tab offen lassen — Updates kommen jetzt via
  WebSocket in Echtzeit (Fallback: HTTP-Polling alle 15s).
- **Priorität:** Prototyp-Scope — kein E-Mail-Versand vorgesehen.

### ~~P5: CVSS-Score-Validierung nur prompt-basiert~~ (BEHOBEN)
- **Status:** Behoben — `validate_cvss_scores()` in `claude_client.py`
  prüft jetzt: Vektor-Syntax (8 Pflichtmetriken, gültige Werte),
  Score-Berechnung nach CVSS 3.1-Spec (Toleranz 0.1 statt 0.5),
  und Severity ↔ Score-Konsistenz.

### ~~P6: Scan-Timeout unterschiedlich pro Paket, aber Frontend zeigt generisches Timeout~~ (BEHOBEN)
- **Status:** Behoben — Timeout-Meldung enthält jetzt Paketnamen und
  Zeitlimit (z.B. "Das Basic (~10 Min.)-Paket hat das Zeitlimit von
  10 Minuten überschritten"). Frontend zeigt bei Timeouts einen
  eigenen Hinweis mit Handlungsempfehlung.

## Allgemein (vor Paket-Integration)

### A1: amass Timeout bei großen Domains
- **Betrifft:** Professional, NIS2
- **Beschreibung:** amass kann bei Domains mit vielen Subdomains das
  Phase-0-Timeout (10 Min) überschreiten und wird dann abgebrochen.
- **Workaround:** amass-Output wird trotzdem gespeichert (partial).
- **Priorität:** Niedrig (by design)

### A2: gowitness Screenshots nur für HTTP/HTTPS
- **Betrifft:** Alle Pakete
- **Beschreibung:** gowitness erfasst nur Screenshots für HTTP(S)-Dienste.
  Andere Dienste (FTP, SSH, SMTP) werden nicht visuell dokumentiert.
- **Workaround:** Keine nötig — expected behavior.
- **Priorität:** Info

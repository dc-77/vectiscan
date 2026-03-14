# VectiScan — Bekannte Probleme

## Paket-Integration

### P1: Audit-Trail Tool-Versionen leer
- **Betrifft:** NIS2-Paket
- **Beschreibung:** Die Audit-Trail-Seite zeigt keine Tool-Versionen an.
  Der `tools`-Array im Audit-Trail ist immer leer, da die tatsächlichen
  Tool-Versionen zur Laufzeit noch nicht erfasst werden.
- **Workaround:** Tool-Versionen können nachträglich aus den Docker-Images
  gelesen werden.
- **Priorität:** Niedrig (kosmetisch)

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
  abgeschlossen ist. Der Benutzer muss die Status-Seite manuell
  refreshen.
- **Workaround:** Browser-Tab offen lassen (Polling alle 3 Sekunden).
- **Priorität:** Prototyp-Scope — kein E-Mail-Versand vorgesehen.

### P5: CVSS-Score-Validierung nur prompt-basiert
- **Betrifft:** Professional, NIS2
- **Beschreibung:** Die CVSS-Scores werden von Claude generiert und nicht
  programmatisch validiert. Es gibt keine Prüfung, ob der numerische
  Score zum CVSS-Vektor passt.
- **Workaround:** Der Prompt enthält strenge Scoring-Regeln mit
  Referenzwerten.
- **Priorität:** Mittel

### P6: Scan-Timeout unterschiedlich pro Paket, aber Frontend zeigt generisches Timeout
- **Betrifft:** Basic-Paket
- **Beschreibung:** Basic hat 10 Minuten Timeout, Professional/NIS2
  haben 120 Minuten. Das Frontend zeigt bei Timeout eine generische
  Fehlermeldung ohne Paket-spezifische Information.
- **Workaround:** Keine — tritt selten auf.
- **Priorität:** Niedrig

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

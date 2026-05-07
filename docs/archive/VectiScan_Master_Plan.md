# VectiScan — Master-Planungsdokument

> **Produkt:** scan.vectigal.tech  
> **Zielgruppe:** Geschäftsführer / C-Level (nicht-technisch)  
> **Benchmark:** iPhone-Level UX — wertig, seriös, sicher, selbsterklärend  
> **Audit-Datum:** 19.–20. April 2026  
> **Zweck:** Einziges Referenzdokument für die Umsetzung via Claude Code  
> **Umfang:** UX-Audit + Implementierungs-Spec + Produkt-Strategie

---

## 1. Executive Summary

### Was VectiScan gut macht
- Starke Scan-Engine mit KI-gestützter Korrelation und Report-Erstellung
- Der priorisierte Maßnahmenplan (Empfehlungen-Tab) ist hervorragend — Tag 1-3 / Woche 1 / Monat 1
- Scan-Detail mit CVSS-Scores, erweiterbaren Befunden und „False Positive"-Button ist solide
- Dark-Theme passt zur Security-Branche, Farbsystem (Teal/Severity-Badges) funktioniert
- Abo-Wizard mit 5-Schritte-Stepper ist strukturell gut

### Was kritisch ist (52 Befunde)
1. **Post-Login → Landing statt Dashboard** (Critical)
2. **Impressum + Datenschutz = 404** (Legal Critical)
3. **Dashboard = endlose Flat-List** mit 92 Scans ohne Suche/Pagination
4. **Debug-Tab zeigt Kunden AI-Kosten, System-Prompts und Raw-Claude-Responses** (IP-Exposure!)
5. **Mobile Navigation komplett broken** (kein Hamburger-Menü)
6. **Technischer Jargon** (Nmap, Nuclei, ffuf) schreckt CEO-Zielgruppe ab
7. **8+ Umlaut-Fehler** im Abo-Wizard und Dashboard
8. **Kein Onboarding, kein Aha-Moment** für neue User

### Strategische Vision
VectiScan muss sich vom **Report-Generator** zum **Security-Cockpit** entwickeln. Der CEO soll auf einen Blick wissen „Wie sicher bin ich?" und mit einem Klick handeln können. Der PDF-Report ist das Produkt, das der CEO weitergibt — alles im UI muss darauf optimiert sein, diesen Report maximal wirksam zu machen.

---

## 2. Produkt-Vision: Vom Report-Generator zum Security-Cockpit

### 2.1 Die drei Wertversprechen für den CEO

**Heute (MVP):**
„Wir scannen Ihre IT und geben Ihnen einen Report."

**Ziel (Premium-SaaS):**
1. **Sichtbarkeit** — „Auf einen Blick: Wie verwundbar bin ich?" (Risk-Gauge, Ampel, Trend)
2. **Handlungsfähigkeit** — „Was muss ich tun und in welcher Reihenfolge?" (Priorisierter Maßnahmenplan mit Tracking)
3. **Nachweisbarkeit** — „Dokumentierter Beweis für Versicherer, Aufsicht, Vorstand" (Compliance-Mapping, Trend-Reports)

### 2.2 Der ideale First-Time-User-Flow

```
Registrierung (E-Mail + Firma + AGB)
  → Welcome-Screen: „In 3 Schritten zu Ihrem ersten Sicherheits-Report"
    → Domain eingeben (kein Verifizierungs-Blocker für WebCheck!)
      → WebCheck startet sofort (15 Min, kein Abo nötig)
        → Live-Fortschritt mit Radar-Animation
          → Ergebnis: „3 Befunde gefunden — 2 Medium, 1 Low"
            → Aha-Moment: „So verwundbar bin ich?!"
              → CTA: „Vollständigen Perimeter-Scan starten" oder „Abo abschließen"
```

**Kern-Idee:** Der WebCheck als kostenloser/günstiger Appetizer, der den CEO überzeugt, bevor er nach dem Preis fragt. Der Aha-Moment muss in unter 20 Minuten eintreten.

### 2.3 Design-Prinzipien für alle Sprints

1. **CEO-First:** Jeder Screen fragt sich „Versteht ein nicht-technischer Geschäftsführer das in 3 Sekunden?"
2. **Progressive Disclosure:** Technische Details nur auf Nachfrage. CEO-Layer als Standard, Tech-Layer bei Expand/Klick.
3. **Security-Cockpit > Scan-Liste:** Dashboard = Sicherheitsstatus auf einen Blick, nicht Datenbank-Tabelle.
4. **Der Report ist das Produkt:** Alles im UI dient dazu, den Report schnell, verständlich und weitergebbar zu machen.
5. **Destructive Actions = 2 Klicks:** Löschen immer mit Bestätigungsdialog.
6. **Feedback für jede Aktion:** Toast-Notifications bei Scan-Start, Löschen, Speichern, Fehler.
7. **Mobile First:** Navigation, Cards, Touch-Targets für 390px.
8. **Sprache = Deutsch:** Kein Denglisch, Umlaute korrekt, keine technischen IDs prominent.
9. **Trust Signals überall:** BSI-Logo, „Daten in Deutschland", Verschlüsselungs-Hinweise — nicht nur auf der Landing Page, auch im eingeloggten Bereich.

---

## 3. Alle Befunde nach Seite

### 3.1 Landing Page (`/`)

| # | Problem | Severity | Fix |
|---|---------|----------|-----|
| L1 | Große leere dunkle Flächen — Content fehlt oder zu geringer Kontrast | HIGH | Sektionen mit hellerem Hintergrund oder Subtle-Patterns aufbrechen |
| L2 | „4 Schritte"-Sektion kaum lesbar (grau-auf-dunkel) | MEDIUM | Kontrast erhöhen, Icons größer, als Timeline mit Illustrationen |
| L3 | Eingeloggter User sieht Landing Page + App-Nav gleichzeitig | CRITICAL | Eingeloggte User → Redirect zu `/dashboard` |
| L4 | „Preis auf Anfrage" = Conversion-Killer für Self-Service | HIGH | Preisindikation „ab X €/Monat" oder kostenloser WebCheck als Lead-Magnet |
| L5 | „Direkt Abo starten" im Footer kaum sichtbar | MEDIUM | Self-Service-CTA prominent in Pricing-Sektion |
| L6 | Keine Social Proof / Kundenlogos / Testimonials | MEDIUM | Referenz-Sektion mit anonymisierten Case Studies oder Logos |
| L7 | **Strategisch:** Kein kostenloser Erst-Scan als Conversion-Treiber | HIGH | WebCheck als Lead-Magnet ohne Abo-Pflicht anbieten |

### 3.2 Login/Register (`/login`)

| # | Problem | Severity | Fix |
|---|---------|----------|-----|
| A1 | Post-Login → Redirect auf `/` statt `/dashboard` | CRITICAL | Auth-Callback auf `/dashboard` redirecten |
| A2 | Register nur E-Mail + Passwort — kein Firmenname, keine AGB-Checkbox | HIGH | Firmenname + AGB/Datenschutz-Checkbox |
| A3 | Kein CAPTCHA oder Rate-Limiting sichtbar | MEDIUM | hCaptcha oder Turnstile |
| A4 | Passwort-Anforderungen nicht angezeigt | MEDIUM | Live-Validierung mit Stärke-Indikator |
| A5 | `/register` gibt 404, Tab auf `/login` funktioniert aber | LOW | Route-Redirect |

### 3.3 Forgot Password (`/forgot-password`)

| # | Problem | Severity | Fix |
|---|---------|----------|-----|
| F1 | Kein Card-Container — Elemente schweben lose | MEDIUM | Konsistenten Card-Style wie bei Login |
| F2 | „Reset-Link senden" grau statt teal — inkonsistent | LOW | Brand-Farbe für Primary-Button |
| F3 | Kein E-Mail-Feld-Label, nur Placeholder | LOW | Label hinzufügen (Accessibility) |

### 3.4 Dashboard (`/dashboard`)

| # | Problem | Severity | Fix |
|---|---------|----------|-----|
| D1 | Endlose Flat-List (92 Scans!) ohne Pagination/Suche | CRITICAL | Pagination 20/Seite, Suchfeld, Domain-Gruppierung |
| D2 | E-Mail-Adresse auf jeder Scan-Card — redundant / Privacy | HIGH | Nur in Admin-Ansicht zeigen |
| D3 | „delivered" Status ist Englisch | MEDIUM | Einheitlich „Zugestellt" |
| D4 | Keine KPI-Summary-Cards | HIGH | Risk-Gauge + KPI-Leiste (→ siehe Strategie: Security-Cockpit) |
| D5 | „Löschen" direkt neben „Details" und „PDF" | HIGH | In Overflow-Menü (⋯) + Bestätigungsdialog |
| D6 | Abo-Card „3/3 Re-Scans" ohne Erklärung | MEDIUM | Tooltip mit Klartext |
| D7 | „1395 Min" nicht menschenlesbar | LOW | Formatierung: „23 Std 15 Min" |
| D8 | Kein Empty State für neue User | MEDIUM | Onboarding-Card → siehe Strategie |
| D9 | „Aktualisiert: 21:00:47" kryptisch | LOW | „Zuletzt aktualisiert: vor 2 Min" oder weglassen |
| D10 | **Strategisch:** Dashboard ist Scan-Liste statt Security-Cockpit | HIGH | Risk-Gauge oben, 3 dringendste Befunde, dann Historie |
| D11 | **Strategisch:** Kein Trend / Vergleich zwischen Scans | MEDIUM | Trend-Pfeil: „Risiko: abnehmend ↓" |

### 3.5 Neuer Scan (`/scan`)

| # | Problem | Severity | Fix |
|---|---------|----------|-----|
| S1 | Domain-Eingabe ohne Label — nur Placeholder | HIGH | Label: „Welche Domain möchten Sie scannen?" + Hilfetext |
| S2 | Technischer Jargon: Nmap, Nuclei, Nikto, ffuf, XSS-Scanner | HIGH | Verständliche Sprache (→ Mapping in Impl-Spec) |
| S3 | „FULL PERIMETER SCAN" ist englisch | MEDIUM | „VOLLSTÄNDIGER PERIMETER-SCAN" |
| S4 | Kein Hinweis was nach „Scan starten" passiert | HIGH | Micro-Copy: „Dauer ca. 60–90 Min. Report per E-Mail." |
| S5 | Kein Fortschrittsindikator nach Scan-Start | MEDIUM | → Strategisch: Live-Fortschritt mit Phasen-Visualisierung |
| S6 | Domain-Ownership-Verifikation nicht erklärt | MEDIUM | Hinweis + Link zur Verifizierung |
| S7 | ⚡-Icons ohne Erklärung | LOW | Tooltip: „Schnell-Scan" |
| S8 | **Strategisch:** „Neuer Scan" vs „Neues Abo" verwirrend | HIGH | Einheitlicher Flow: Scan → Ergebnis → Abo-Upgrade-CTA |

### 3.6 Scan-Detail (`/scan/<id>`)

| # | Problem | Severity | Fix |
|---|---------|----------|-----|
| SD1 | Debug-Tab zeigt AI-Kosten, System-Prompts, Raw Claude Responses | CRITICAL | Nur für Admins! |
| SD2 | CVSS-Scores ohne Erklärung | HIGH | Klartext: „Mittel — innerhalb von 30 Tagen beheben" |
| SD3 | Befund-IDs (VS-2025-002) technisch, nicht CEO-relevant | LOW | Deemphasizen |
| SD4 | Kein „Was bedeutet das?"-Button pro Befund | MEDIUM | Expandierbare CEO-gerechte Erklärung |
| SD5 | Kein „An IT-Team weiterleiten"-Button | MEDIUM | → Strategisch: Share-Funktion |
| SD6 | Kein Inline-Preview des PDF-Reports | LOW | Optional: PDF-Preview oder Inline-Ansicht |
| SD7 | Doppelter Prefix „VS-VS-2025-001" in Empfehlungen | MEDIUM | Bug fixen: `VS-VS-` → `VS-` |
| SD8 | **Strategisch:** Empfehlungen nicht trackbar | HIGH | Checkboxen + Fortschrittsbalken + Auto-Abgleich bei Re-Scan |
| SD9 | **Strategisch:** Kein Scan-Vergleich (Diff) | MEDIUM | Neue/behobene/unveränderte Befunde visualisieren |

### 3.7 Abo-Wizard (`/subscribe`)

| # | Problem | Severity | Fix |
|---|---------|----------|-----|
| W1 | 8+ Umlaut-Fehler: Wahlen, Zuruck, Vollstandige, Empfanger, hinzufugen, Wochentlich, gepruft, Lauft | HIGH | Alle korrigieren |
| W2 | „Weiter" disabled ohne Validation-Feedback | MEDIUM | Inline-Fehlermeldung |
| W3 | „+ Ziel hinzufügen" ist Textlink statt Button | LOW | Als Button stylen |
| W4 | Kein Preis in der Zusammenfassung | HIGH | Preis oder „wird nach Prüfung mitgeteilt" |
| W5 | **Strategisch:** Abo-Wizard als separater Flow vom Scan | MEDIUM | Zusammenführen: Scan → Ergebnis → „Regelmäßig überwachen?" |

### 3.8 Zeitpläne (`/schedules`)

| # | Problem | Severity | Fix |
|---|---------|----------|-----|
| Z1 | Empty State zu karg | MEDIUM | Illustration + Erklärung + CTA |
| Z2 | Beziehung Zeitpläne ↔ Abos unklar | MEDIUM | Kontextueller Hinweis |
| Z3 | Domain-Feld im Dialog ist Freitext statt Dropdown | MEDIUM | Dropdown mit verifizierten Domains |
| Z4 | „Abbrechen"-Button sieht aus wie Primary-Action | LOW | Ghost-Button-Style |
| Z5 | TLS-Compliance fehlt im Paket-Dropdown | LOW | Hinzufügen |

### 3.9 Profil (`/profile`)

| # | Problem | Severity | Fix |
|---|---------|----------|-----|
| P1 | Keine Firmendaten | HIGH | Firmenprofil-Sektion |
| P2 | „Manuell" + „60 Tage" kryptisch | HIGH | Erklärung + Verlängern-CTA |
| P3 | Kein Domain-hinzufügen-Workflow | HIGH | „+ Domain hinzufügen" + Verifizierungs-Wizard |
| P4 | Kein Notification-Settings | MEDIUM | Toggle für E-Mail-Benachrichtigungen |
| P5 | „Abmelden"-Button-Duplikat auf der Seite | LOW | Entfernen (ist schon in Nav) |
| P6 | **Strategisch:** Domain-Verifizierung zu technisch für CEO | HIGH | Alternative Methoden: E-Mail an IT-Admin, HTML-File-Upload |

### 3.10 Admin (`/admin`)

| # | Problem | Severity | Fix |
|---|---------|----------|-----|
| AD1 | AI-Kosten in USD statt EUR | HIGH | EUR anzeigen |
| AD2 | „Zu Admin" / „Zu Customer" unklar | MEDIUM | „Rolle ändern → Admin/Kunde" |
| AD3 | „0 Aufträge" für alle User (Bug?) | MEDIUM | Tatsächliche Scan-Anzahl zeigen |
| AD4 | „Löschen" neben „Zu Admin" ohne Bestätigung | HIGH | Bestätigungsdialog |
| AD5 | Admin-Link für alle User sichtbar | HIGH | Rollenbasiert anzeigen |
| AD6 | Keine Domain-Verifizierungs-Queue | MEDIUM | Pending-Domains mit Approve/Reject |

### 3.11 Fehlende Seiten

| # | Problem | Severity | Fix |
|---|---------|----------|-----|
| 404-1 | `/impressum` → 404 | LEGAL CRITICAL | Seite erstellen (§5 TMG) |
| 404-2 | `/datenschutz` → 404 | LEGAL CRITICAL | Seite erstellen (DSGVO Art. 13/14) |
| 404-3 | `/register` → 404 | LOW | Redirect auf `/login?tab=register` |

### 3.12 Mobile UX

| # | Problem | Severity | Fix |
|---|---------|----------|-----|
| M1 | Kein Hamburger-Menü — 7+ Nav-Items horizontal | CRITICAL | Hamburger für < 768px |
| M2 | Dashboard-Cards gequetscht, Domains abgeschnitten | HIGH | Card-Layout optimieren |
| M3 | Touch-Targets „Details/PDF/Löschen" zu klein | HIGH | 44px Minimum, Löschen in Swipe/Menü |
| M4 | Scan-Typ-Karten stapeln nicht responsive | MEDIUM | Stacked Cards auf Mobile |

---

## 4. Strategische Optimierungen (Detail)

### 4.1 Dashboard → Security-Cockpit

**IST:** Flat-List mit Scan-Einträgen.  
**SOLL:** Drei-Zonen-Layout:

**Zone 1 — Risk-Gauge (ganz oben):**
- Großes visuelles Element: Ampel oder Gauge mit Gesamtrisiko (NIEDRIG / MITTEL / HOCH / KRITISCH)
- Berechnung: höchster offener Severity-Wert über alle aktiven Domains
- Trend-Indikator: „↓ Verbessert seit letztem Scan" / „↑ Verschlechtert" / „→ Unverändert"
- Einzeiler: „5 aktive Domains · 32 offene Befunde · 1 kritisch"

**Zone 2 — Top-3-Handlungsbedarf (Mitte):**
- Die 3 dringendsten offenen Befunde als Cards
- Pro Card: Domain, Befund-Titel, Severity-Badge, „Details →"
- Wenn alle behoben: „Keine kritischen Befunde — gut gemacht!" mit grünem Checkmark

**Zone 3 — Scan-Historie (unten):**
- Die bisherige Liste, aber mit Pagination (20/Seite), Suche, Filter
- Optional: Domain-Gruppierung als Toggle

**Implementierungs-Hinweis für Claude Code:**
- Zone 1+2 brauchen einen API-Endpoint der aggregierte Daten liefert (offene Befunde, höchster Severity, Trend)
- Falls Backend-Änderung zu aufwändig: Client-seitige Aggregation aus den Scan-Daten
- Zone 3 ist primär Frontend-Arbeit (Pagination, Filter-State)

### 4.2 Live-Scan-Fortschritt

**IST:** Scan startet → User wartet 60–90 Min → irgendwann E-Mail.  
**SOLL:** Nach Scan-Start → Redirect auf Detail-Seite mit Live-Progress:

```
Phase 0: DNS-Analyse       ████████████░░░░ 75%  (12 Subdomains gefunden)
Phase 1: Port-Scan          ░░░░░░░░░░░░░░░░ wartend
Phase 2: Schwachstellen     ░░░░░░░░░░░░░░░░ wartend
Phase 3: KI-Korrelation     ░░░░░░░░░░░░░░░░ wartend
Phase 4: Report             ░░░░░░░░░░░░░░░░ wartend
```

- Radar-Ping-Animation oder Wellenform als visuelles Element
- Phasen-Updates via WebSocket oder Polling (Backend liefert Phase + Progress bereits)
- Micro-Facts während des Wartens: „Wussten Sie? 73% aller Cyberangriffe beginnen über exponierte Dienste."

**Implementierungs-Hinweis:** Das Backend trackt bereits Phasen und Tool-Zeiten (sichtbar im Debug-Tab). Diese Daten müssen nur an den Customer-View durchgereicht werden — ohne die Debug-Details.

### 4.3 Report als Produkt

**IST:** „PDF herunterladen" → User muss Datei manuell öffnen und weiterleiten.  
**SOLL:** Drei Aktionen auf der Detail-Seite:

1. **„Report ansehen"** → Inline-Preview im Browser (PDF.js oder HTML-Rendering)
2. **„An IT-Team senden"** → Modal:
   - E-Mail-Adresse eingeben
   - Vorgefertigter Text: „Anbei der Sicherheitsreport für [domain]. Bitte bearbeiten Sie die priorisierten Maßnahmen bis [Datum]."
   - Anpassbar durch den CEO
   - Zeitlich begrenzter Deeplink (7 Tage), kein Login nötig
3. **„PDF herunterladen"** → bleibt wie bisher

### 4.4 Empfehlungen mit Fortschrittsverfolgung

**IST:** Statische Liste von Maßnahmen.  
**SOLL:** Interaktiver Maßnahmenplan:

- Checkbox pro Empfehlung: ☐ → ☑ (mit Timestamp: „Erledigt am 15.04.2026")
- Fortschrittsbalken oben: „5/8 Maßnahmen umgesetzt" mit Prozent-Anzeige
- Bei nächstem Scan: automatischer Abgleich — wurde der Befund tatsächlich behoben?
  - ✅ „VS-2025-002: jQuery aktualisiert — im letzten Scan nicht mehr gefunden"
  - ⚠️ „VS-2025-004: Security-Header — immer noch fehlend"
- Export als CSV für Ticket-System-Import (Jira, Asana)

### 4.5 Scan-Vergleich (Diff-View)

**IST:** Kein Vergleich möglich.  
**SOLL:** Button „Mit vorherigem Scan vergleichen" auf Detail-Seite:

- **Neu** (rot): 2 neue Befunde seit letztem Scan
- **Behoben** (grün): 3 Befunde sind verschwunden
- **Unverändert** (grau): 7 Befunde bestehen weiter
- Kompakte Zusammenfassung: „Seit dem letzten Scan am 15.03. hat sich Ihr Risiko verbessert: 3 Befunde behoben, 2 neue entdeckt."

### 4.6 Onboarding-Flow

**IST:** Neuer User → leeres Dashboard.  
**SOLL:** Dreistufiger Welcome-Flow:

**Schritt 1 — Welcome-Screen** (Modal oder Full-Page):
„Willkommen bei VectiScan. In wenigen Minuten wissen Sie, wie angreifbar Ihre IT-Infrastruktur ist."
→ CTA: „Ersten Scan starten"

**Schritt 2 — Domain eingeben:**
- Einfaches Input-Feld: „Ihre Unternehmens-Domain (z.B. meinefirma.de)"
- WebCheck starten (kein Verifizierungs-Blocker, kein Abo nötig)
- Live-Fortschritt zeigen

**Schritt 3 — Ergebnis + Upgrade:**
- WebCheck-Ergebnis anzeigen
- CTA: „Für eine vollständige Analyse starten Sie einen Perimeter-Scan →"

**Dashboard-Checkliste** (solange nicht alles erledigt):
☐ Ersten Scan abgeschlossen  
☐ Report angesehen  
☐ Domain verifiziert  
☐ Abo abgeschlossen (optional)

### 4.7 Pricing & Conversion

**IST:** „Jahresabo — Preis auf Anfrage" + „Angebot anfordern" (= Sackgasse für Self-Service).  
**SOLL:** Gestuftes Modell:

1. **WebCheck gratis** (oder einmalig 49 €): Schnell-Scan als Appetizer
2. **Perimeter-Scan einmalig** (z.B. ab 299 €): Für CEOs die erstmal testen wollen
3. **Abo** (ab X €/Monat): Für regelmäßige Überwachung

Mindestens Preisindikation auf der Pricing-Seite: „ab 199 €/Monat" oder interaktiver Rechner.

### 4.8 Domain-Verifizierung vereinfachen

**IST:** Nur DNS-TXT-Eintrag (technisch, CEO-feindlich).  
**SOLL:** Drei Methoden zur Auswahl:

1. **DNS-TXT** (für IT-Admins) — bleibt
2. **HTML-File-Upload** — `vectigal-verify.html` in Root hochladen
3. **E-Mail an Domain-Admin** — VectiScan sendet E-Mail an `admin@domain.de` oder `webmaster@domain.de` mit Bestätigungslink

Bonus: **„IT-Admin einladen"**-Button — CEO gibt Admin-E-Mail ein, Admin erhält Einladung mit Anleitung zur Verifizierung. CEO muss nichts Technisches tun.

### 4.9 Trust-Signale im App-Bereich

**IST:** BSI, PTES, DSGVO nur auf der Landing Page.  
**SOLL:** Trust-Signale auch im eingeloggten Bereich:

- Footer (alle Seiten): „🔒 Daten AES-256 verschlüsselt · Hosting in Deutschland · DSGVO-konform"
- Profil-Seite: Sicherheits-Badge mit Details
- Scan-Detail: „Dieser Report wurde auf Servern in Deutschland erstellt. Keine Daten verlassen die EU."
- Login-Seite: Kleines Trust-Label unter dem Formular

### 4.10 Notification-Center

**IST:** Keine In-App-Benachrichtigungen.  
**SOLL:** Glocke in der Navigation:

- Badge mit Anzahl ungelesener Events
- Dropdown-Liste:
  - „Scan für securess.de abgeschlossen — MEDIUM (6 Befunde)"
  - „Neuer kritischer Befund auf rankingcoach.com"
  - „Abo läuft in 30 Tagen ab"
  - „3 Maßnahmen als erledigt markiert"
- Link zu Notification-Settings (Profil)

---

## 5. Sprint-Plan mit Implementierungs-Details

### SPRINT 1 — Rechtlich & Showstopper (Tag 1)

#### TICKET-001: Post-Login Redirect
**Problem:** Login → `/` statt `/dashboard`  
**Wo:** Auth-Callback / Login-Handler (`app/login/page.tsx` oder Auth-Middleware)  
**Lösung:** `router.push('/dashboard')` + `if (session) redirect('/dashboard')` auf Landing Page  
**Strategischer Kontext:** Dieser Fix ist Voraussetzung für das Security-Cockpit-Dashboard (Sprint 4)

#### TICKET-002: Impressum erstellen
**Wo:** Neue Seite `app/impressum/page.tsx`  
**Inhalt:** Vectigal GmbH, Adresse, GF, HRB, USt-IdNr, Kontakt, Verantwortlicher (§18 MStV)  
**Design:** Dark-Theme, einfacher Text, im Footer verlinkt

#### TICKET-003: Datenschutz erstellen
**Wo:** Neue Seite `app/datenschutz/page.tsx`  
**Inhalt:** Verantwortlicher, Rechtsgrundlagen, Datenverarbeitung, Cookies, Drittanbieter (Anthropic, Stripe), Betroffenenrechte  
**Strategischer Kontext:** Wird in Register-Formular verlinkt (Sprint 2, TICKET-035)

#### TICKET-004: Mobile Hamburger-Navigation
**Wo:** Nav-Komponente  
**Lösung:** `< 768px` → Hamburger (☰), Slide-in Panel, 48px Touch-Targets  
**Strategischer Kontext:** Hamburger-Menü wird später auch Notification-Glocke aufnehmen (Sprint 5)

#### TICKET-005: Umlaut-Korrektur
**Methode:** Grep nach `Wahlen|Zuruck|Vollstandig|Empfanger|hinzufugen|Wochentlich|gepruft|Massnahme|Lauft|offentlich|Angriffsoberflache`  
**Betroffene Dateien:** Abo-Wizard-Steps, Dashboard Abo-Card, Zeitplan-Dialog

---

### SPRINT 2 — Core UX-Fixes (Tag 2–3)

#### TICKET-010: Dashboard Pagination + Suche
**Lösung:** Max 20/Seite, Suchfeld (Domain/Status/Datum), Sortierung  
**Strategischer Kontext:** Vorbereitung für Security-Cockpit — die Liste wird Zone 3 des neuen Dashboards. Baue die Pagination so, dass sie später unter den KPI-Cards sitzen kann.

#### TICKET-011: Löschen absichern
**Lösung:** Overflow-Menü (⋯) + Bestätigungsdialog mit rotem Warnhinweis

#### TICKET-012: Debug-Tab nur für Admins
**Lösung:** `if (user.role !== 'admin') return null` für Debug-Tab  
**Wichtig:** Die Phasen-Daten (Phase 0–4 mit Timing) können für den Live-Fortschritt (Sprint 4) wiederverwendet werden — nur ohne AI-Kosten, Prompts und Raw-Responses.

#### TICKET-013: Admin-Link rollenbasiert
**Lösung:** `{user.role === 'admin' && <Link>Admin</Link>}`

#### TICKET-014: Jargon vereinfachen
**Mapping:**
- „Nmap Top-1000" → „Port-Analyse"
- „Passive Intel" → „Passive Aufklärung"
- „Nuclei" → „Schwachstellen-Prüfung"
- „Nikto" → „Webserver-Analyse"
- „ffuf" → „Verzeichnis-Scan"
- „XSS-Scanner" → „Skript-Injection-Test"
- „Threat-Intel" → „Bedrohungsanalyse"
- „Korrelation" → „KI-Korrelation"
- „FULL PERIMETER SCAN" → „VOLLSTÄNDIGER PERIMETER-SCAN"

#### TICKET-015: Domain-Eingabe mit Label
**Lösung:** Label + Hilfetext + Post-Scan Micro-Copy  
**Strategischer Kontext:** Dieses Input-Feld wird auch im Onboarding-Flow (Sprint 5) wiederverwendet.

#### TICKET-016: Status-Labels Deutsch
**Mapping:** `delivered→Zugestellt`, `running→Läuft`, `failed→Fehlgeschlagen`, `cancelled→Abgebrochen`, `completed→Fertig`, `pending→Wartend`

#### TICKET-017: CVSS mit Klartext
**Mapping:**
- 9.0–10.0: „Kritisch — sofort handeln" (rot)
- 7.0–8.9: „Hoch — innerhalb einer Woche" (orange)
- 4.0–6.9: „Mittel — innerhalb von 30 Tagen" (gelb)
- 0.1–3.9: „Niedrig — bei Gelegenheit" (blau)
- 0.0: „Information" (grau)

#### TICKET-018: E-Mail aus Dashboard-Cards entfernen
**Lösung:** E-Mail nur wenn Admin + anderer User. Eigene Scans: weglassen.

#### TICKET-019: VS-VS Doppel-Prefix
**Lösung:** String-Replace `VS-VS-` → `VS-` in Report-Rendering

#### TICKET-020: AI-Kosten EUR statt USD
**Wo:** Admin-Seite  
**Lösung:** EUR-Umrechnung oder „Kosten in USD (Anthropic API)" als Clarifier

---

### SPRINT 3 — UX Polish (Tag 4–5)

#### TICKET-030: Dashboard KPI-Summary-Cards
**Design:** 4 Cards in einer Reihe über der Scan-Liste  
**Strategischer Kontext:** Vorstufe zum Security-Cockpit. Später wird Card 1 durch das Risk-Gauge ersetzt.

#### TICKET-031: Empty State mit Onboarding-CTA
**Strategischer Kontext:** Vorstufe zum vollständigen Onboarding-Flow. Der Empty State zeigt „Willkommen" + „Ersten Scan starten →".

#### TICKET-032: Domain-Verifizierung erklären + verlängern
**Lösung:** Tooltips + „+ Domain hinzufügen" Button  
**Strategischer Kontext:** Wird später zum Multi-Methoden-Verifizierungs-Wizard (Sprint 5)

#### TICKET-033: Zeitplan-Dialog — Domain als Dropdown
**Lösung:** Dropdown mit verifizierten Domains + Ghost-Style für Abbrechen

#### TICKET-034: Forgot-Password Card-Container

#### TICKET-035: Register-Formular erweitern
**Hinzufügen:** Firmenname, Passwort-Stärke, AGB-Checkbox mit Link zu Datenschutz  
**Strategischer Kontext:** Firmenname wird für personalisierte Dashboard-Begrüßung genutzt.

#### TICKET-036: Scan-Dauer menschenlesbar
```js
function formatDuration(minutes) {
  if (minutes < 60) return `${minutes} Min`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  if (h >= 24) return `~${Math.floor(h/24)} Tag${Math.floor(h/24)>1?'e':''}`;
  return m > 0 ? `${h} Std ${m} Min` : `${h} Std`;
}
```

#### TICKET-037: Lösch-Bestätigung für User im Admin

#### TICKET-038: Toast-Notifications
**Implementierung:** shadcn/ui Toast oder eigene Komponente  
**Events:** Scan gestartet, Scan gelöscht, Zeitplan erstellt, Fehler  
**Strategischer Kontext:** Toast-System wird auch für Notification-Center-Events (Sprint 5) verwendet.

---

### SPRINT 4 — Security-Cockpit & Fortschritt (Woche 2)

#### TICKET-040: Dashboard Security-Cockpit (Zone 1 + 2)
**Beschreibung:** Risk-Gauge + Top-3-Handlungsbedarf über der Scan-Liste  
**Abhängigkeit:** Backend-Endpoint für aggregierte Befund-Daten oder Client-seitige Aggregation  
**Details:** Siehe Abschnitt 4.1

#### TICKET-041: Live-Scan-Fortschritt
**Beschreibung:** Phasen-Fortschrittsleiste auf Scan-Detail nach Start  
**Datenquelle:** Phase-/Tool-Timing aus Debug-Daten (ohne AI-Kosten/Prompts)  
**Details:** Siehe Abschnitt 4.2

#### TICKET-042: Report-Sharing per E-Mail
**Beschreibung:** „An IT-Team senden" mit Deeplink (7 Tage gültig)  
**Details:** Siehe Abschnitt 4.3

#### TICKET-043: Empfehlungen mit Fortschrittsverfolgung
**Beschreibung:** Checkboxen + Fortschrittsbalken + Auto-Abgleich bei Re-Scan  
**Details:** Siehe Abschnitt 4.4

#### TICKET-044: Scan-Vergleich (Diff-View)
**Beschreibung:** Neue/behobene/unveränderte Befunde zwischen zwei Scans  
**Details:** Siehe Abschnitt 4.5

#### TICKET-045: Trust-Signale im App-Bereich
**Beschreibung:** Footer-Trust-Leiste + Profil-Badge + Scan-Detail-Hinweis  
**Details:** Siehe Abschnitt 4.9

---

### SPRINT 5 — Onboarding, Conversion & Premium (Woche 3+)

#### TICKET-050: Onboarding-Flow für Neukunden
**Details:** Siehe Abschnitt 4.6

#### TICKET-051: Pricing-Überarbeitung
**Details:** Siehe Abschnitt 4.7  
**Entscheidung nötig:** Ist ein kostenloser WebCheck wirtschaftlich tragbar? (~$0.05 pro Scan)

#### TICKET-052: Domain-Verifizierung Multi-Methode
**Details:** Siehe Abschnitt 4.8

#### TICKET-053: Notification-Center
**Details:** Siehe Abschnitt 4.10

#### TICKET-054: „Neuer Scan" und „Neues Abo" zusammenführen
**Beschreibung:** Einheitlicher Flow: Domain scannen → Ergebnis → „Regelmäßig überwachen?"  
**Details:** Siehe Abschnitt 4.7 (strategisch verknüpft)

---

## 6. Qualitäts-Checkliste für jede Änderung

- [ ] Funktioniert auf 1440px Desktop
- [ ] Funktioniert auf 390px Mobile (iPhone 14)
- [ ] Funktioniert im Dark Mode (ist default)
- [ ] Keine Umlaut-Fehler in neuen Texten
- [ ] Keine englischen Labels in der deutschen UI
- [ ] Destructive Actions haben Bestätigungsdialog
- [ ] Touch-Targets ≥ 44×44px auf Mobile
- [ ] Kein technischer Jargon in Kunden-sichtbaren Bereichen
- [ ] Admin-only Features sind rollenbasiert geschützt
- [ ] CEO-Test: „Versteht ein nicht-technischer Geschäftsführer das in 3 Sekunden?"
- [ ] Trust-Signal-Check: Fühlt sich die Seite sicher und professionell an?
- [ ] Strategische Kompatibilität: Blockiert die Änderung einen späteren Sprint?

---

## 7. Architektur-Hinweise für Claude Code

### Komponentenstruktur (empfohlen)
```
components/
  dashboard/
    RiskGauge.tsx          # Sprint 4 — Security-Cockpit Zone 1
    TopFindings.tsx         # Sprint 4 — Security-Cockpit Zone 2
    ScanList.tsx            # Sprint 2 — mit Pagination/Suche
    ScanCard.tsx            # Sprint 2 — ohne E-Mail, mit Overflow-Menü
    AboStatusCard.tsx       # Sprint 3 — mit Tooltips
    EmptyState.tsx          # Sprint 3 — Onboarding-CTA
  scan/
    ScanTypeSelector.tsx    # Sprint 2 — ohne Jargon
    DomainInput.tsx         # Sprint 2 — mit Label, wiederverwendbar für Onboarding
    LiveProgress.tsx        # Sprint 4 — Phasen-Fortschritt
  scan-detail/
    FindingCard.tsx         # Sprint 2 — mit CVSS-Klartext
    RecommendationCard.tsx  # Sprint 4 — mit Checkbox
    DiffView.tsx            # Sprint 4 — Scan-Vergleich
    ShareModal.tsx          # Sprint 4 — Report senden
  layout/
    Nav.tsx                 # Sprint 1 — Hamburger, Sprint 5 — Notification-Glocke
    Footer.tsx              # Sprint 1 — Impressum/Datenschutz-Links, Sprint 4 — Trust-Signale
    Toast.tsx               # Sprint 3 — Feedback-System
  onboarding/
    WelcomeScreen.tsx       # Sprint 5
    DomainSetup.tsx         # Sprint 5
    FirstScanResult.tsx     # Sprint 5
```

### Wiederverwendbare Utilities
```
utils/
  formatDuration.ts       # „1395 Min" → „23 Std 15 Min"
  cvssLabel.ts            # 6.1 → „Mittel — innerhalb von 30 Tagen"
  statusLabel.ts          # „delivered" → „Zugestellt"
  riskLevel.ts            # Aggregation für Risk-Gauge
```

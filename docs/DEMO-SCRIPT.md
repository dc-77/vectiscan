# Demo-Skript & Talktrack — VectiScan-Live-Demo (VEC-118 / PA-6)

**Zweck:** Eine dritte Person **ohne Vorwissen** kann diese VectiScan-Demo
verlässlich durchspielen — vom Login bis zum PDF-Download — und dabei pro Paket
die richtige Vertriebs-Story erzählen.

**Grundlage:** `docs/DEMO-SEED.md` (synthetischer Mandant + 3 fertige Reports +
reproduzierbarer Login). Alle Daten sind **synthetisch** (`.test`-TLD, keine PII).

**Dauer:** ~7–10 Min für alle drei Pakete, ~3 Min für eine Kurz-Demo (nur Perimeter).

---

## 0. Vorbereitung (1× vor der Demo, nicht vor Kunden)

1. **Seed ausführen** (legt Mandant + 3 Reports + PDFs an, idempotent):
   ```bash
   cd api && npm run seed:demo          # lokal
   # oder im laufenden Stack:
   docker compose exec api npm run seed:demo
   ```
   Voraussetzung: Postgres + MinIO laufen (`docker-compose.dev.yml`).
2. **Frontend erreichbar** prüfen: `scan.vectigal.tech` (intern) bzw. lokal `http://localhost:3000`.
3. **Browser vorbereiten:** Inkognito-Fenster (kein fremder Login-State), Zoom 100 %,
   Fenster groß genug, dass Risk-Gauge + Top-Findings ohne Scrollen sichtbar sind.
4. **Einmal selbst durchklicken** (Smoke-Test), damit kein Überraschungsmoment vor dem Kunden entsteht.

**Zugangsdaten (synthetisch):**

| Feld | Wert |
|---|---|
| URL | `scan.vectigal.tech` bzw. lokal `http://localhost:3000` |
| E-Mail | `demo@vectiscan.tech` |
| Passwort | `VectiScanDemo2026!` |

---

## 1. Demo-Daten-Überblick

| Paket | Ziel (synthetisch) | Mandant | Risiko | Befunde | Demo-Story |
|---|---|---|---|---|---|
| **WebCheck** | `demo-shop.vectiscan-demo.test` | Demo-Shop GmbH | **MEDIUM** | 6 (0C/0H/4M/2L) | „Sauberes Schnell-Audit" |
| **Perimeter** | `demo-corp.vectiscan-demo.test` | Demo-Corp AG | **HIGH** | 10 (1C/3H/4M/2L) | „Aha-Effekt" (SQLi + RDP + .git) |
| **Compliance** | `demo-stadtwerke.vectiscan-demo.test` | Demo-Stadtwerke AöR | **CRITICAL** | 11 (1C/4H/5M/1L) | NIS2/§30-BSIG-Story |

**Deep-Links zur Scan-Detailseite** (zuverlässiger Fallback, falls man sich
über das Dashboard „verklickt" — direkt nach Login aufrufbar):

| Paket | Direkt-URL (Scan-Detail) |
|---|---|
| WebCheck | `/scan/d0000000-0000-4000-a000-000000000101` |
| Perimeter | `/scan/d0000000-0000-4000-a000-000000000102` |
| Compliance | `/scan/d0000000-0000-4000-a000-000000000103` |

---

## 2. Schritt-für-Schritt-Klickpfad (mit erwartetem Bildschirm + Talktrack)

> Empfohlene Reihenfolge für den „Spannungsbogen": **Perimeter zuerst** (Aha-Effekt),
> dann **Compliance** (Eskalation auf NIS2), zum Schluss **WebCheck** (Kontrast „sauber").
> Für eine 3-Min-Kurzdemo nur **Schritt 1–5 mit Perimeter**.

### Schritt 1 — Login
- **Klick:** URL öffnen → landet auf **`/login`**.
  - Tab **„Anmelden"** ist aktiv.
  - Feld **„E-Mail-Adresse"** → `demo@vectiscan.tech`
  - Feld **„Passwort (min. 8 Zeichen)"** → `VectiScanDemo2026!`
  - Button **„Anmelden"** klicken.
- **Erwarteter Bildschirm:** Redirect auf **`/dashboard`**. *(Screenshot-Platzhalter: `login.png`)*
- **Talktrack:**
  > „Ihre Mitarbeiter melden sich an einem internen, abgesicherten Portal an —
  > kein öffentliches Internet, kein zusätzliches Tool zu installieren.
  > Ich bin jetzt als Kunde eingeloggt und sehe ausschließlich meine eigenen Scans."

### Schritt 2 — Dashboard (Überblick)
- **Erwarteter Bildschirm:** Vier KPI-Karten oben:
  **„Domains"**, **„Scans gesamt"**, **„Aktive Scans"**, **„Gesamtrisiko"**
  (Gesamtrisiko zeigt **CRITICAL** — das höchste Einzelrisiko der drei Pakete).
  Darunter pro Scan eine Karte mit **Risk-Badge** (CRITICAL/HIGH/MEDIUM, farbcodiert),
  **Status-Badge** („Fertig") und **Severity-Verteilung** (farbige Punkte C·H·M·L).
  *(Screenshot-Platzhalter: `dashboard.png`)*
- **Talktrack:**
  > „Das ist die Vogelperspektive für die Geschäftsführung: Auf einen Blick sehen
  > Sie, wie viele Domains geprüft wurden und wo Sie aktuell stehen. Dieses rote
  > **CRITICAL** oben ist genau das, was ein Vorstand oder Auditor zuerst sehen will —
  > keine 80-seitige PDF, sondern eine Ampel."

### Schritt 3 — Paket öffnen
- **Klick:** Auf die gewünschte Scan-Karte klicken (bzw. Button **„Öffnen"**).
  - *Hinweis:* Die Karte führt zunächst zur **Gruppen-Übersicht** (`/scans/<key>`);
    von dort den Einzel-Scan öffnen → **`/scan/<orderId>`**.
  - **Zuverlässiger Weg für die Demo:** Den Deep-Link aus Abschnitt 1 direkt
    aufrufen (z. B. Perimeter `/scan/d0000000-0000-4000-a000-000000000102`).
- **Erwarteter Bildschirm:** **Scan-Detailseite** mit Kopfzeile (Domain + Paket-Label
  + Status **„Fertig"**), KPI-Leiste (**Findings**, **Determinismus**, **Hosts**, **Paket**)
  und dem **Befunde-Bereich** mit **Risk-Badge** + Befundzahl. *(Screenshot-Platzhalter: `scan-detail.png`)*

### Schritt 4 — Risk-Gauge + Top-Findings
- **Erwarteter Bildschirm:** Risk-Badge (z. B. **HIGH** bei Perimeter), darunter die
  Befundliste, sortier-/filterbar über Severity-Pills (**„Alle"** + Schweregrade mit Zähler).
  Tabs: **„Befunde"**, **„Empfehlungen"**, **„Vergleich"**.
- **Talktrack (allgemein):**
  > „Jeder Befund hat einen Schweregrad, eine CVSS-Bewertung, das Tool, das ihn
  > gefunden hat, und einen Nachweis. Das ist nicht KI-Raterei — die Schweregrade
  > laufen durch eine feste Richtlinie (Policy), d. h. zwei Scans desselben Ziels
  > liefern dasselbe Ergebnis. Reproduzierbar, auditierbar."
- **Paket-spezifischer Talktrack:** siehe Abschnitt 3.

### Schritt 5 — PDF herunterladen
- **Klick:** Button **„PDF herunterladen"** (oben rechts in der Kopfzeile,
  nur sichtbar bei Status „Fertig"/Report vorhanden).
- **Erwarteter Bildschirm:** Das **gebrandete PDF** öffnet sich/lädt herunter —
  Cover, Executive Summary (Risk-Box + Severity-Verteilung + Empfehlungen),
  detaillierte Befunde, positive Feststellungen, Haftungsausschluss.
  *(Screenshot-Platzhalter: `pdf.png`)*
- **Talktrack:**
  > „Und das hier ist das, was Ihr IT-Team oder Ihr Auditor am Montag auf dem
  > Tisch hat: ein fertiger, gebrandeter Report — kein Rohdaten-Dump. Mit einem
  > Klick auch direkt **„An IT-Team senden"**."

---

## 3. Talktrack pro Paket (die drei Stories)

### 3a. WebCheck — `demo-shop.vectiscan-demo.test` — **MEDIUM** — „sauberes Schnell-Audit"
- **Top-Befunde (real im Seed):**
  - MEDIUM — Veraltete TLS-Protokolle (TLS 1.0 / 1.1) aktiv
  - MEDIUM — Fehlende Security-Header (HSTS, CSP, X-Content-Type-Options)
  - MEDIUM — Kein DMARC-Record vorhanden
- **Story:**
  > „WebCheck ist unser Schnellscan — in ~15–20 Minuten. Hier sehen Sie einen
  > **gepflegten** Webauftritt: kein kritisches Loch, nur Härtungs-Themen wie
  > altes TLS und fehlende E-Mail-Absicherung (DMARC). So sieht es aus, wenn die
  > Hausaufgaben weitgehend gemacht sind — und genau das wollen Sie schwarz auf
  > weiß für Ihre Kunden und Partner belegen können."

### 3b. Perimeter — `demo-corp.vectiscan-demo.test` — **HIGH** — der „Aha-Effekt"
- **Top-Befunde (real im Seed):**
  - **CRITICAL — SQL-Injection im Kundenportal (Login-Parameter)**
  - **HIGH — RDP (3389/tcp) aus dem Internet erreichbar**
  - **HIGH — Exponiertes .git-Verzeichnis mit Quellcode**
  - HIGH — Veraltete OpenSSH-Version mit bekannten CVEs
- **Story:**
  > „Perimeter ist der Vollscan. Und hier passiert der Aha-Moment: Eine
  > **SQL-Injection direkt im Login des Kundenportals** — damit kann ein Angreifer
  > potenziell Kundendaten abgreifen. Dazu **offenes RDP aus dem Internet** — das
  > ist das Einfallstor Nr. 1 für Ransomware — und ein **offenes .git-Verzeichnis**,
  > über das jeder Ihren Quellcode herunterladen kann. Drei Funde, jeder einzelne
  > reicht für einen ernsten Vorfall. Das findet kein Standard-Virenscanner."

### 3c. Compliance — `demo-stadtwerke.vectiscan-demo.test` — **CRITICAL** — NIS2/§30-BSIG
- **Top-Befunde (real im Seed):**
  - **CRITICAL — Ungepatchte kritische Schwachstelle im VPN-Gateway (RCE)**
  - **HIGH — Keine Multi-Faktor-Authentifizierung für administrative Zugänge**
  - **HIGH — Unzureichendes zentrales Logging und Monitoring**
  - HIGH — Exponierte SMB-Freigabe (445/tcp) am Perimeter
- **NIS2/§30-BSIG-Summary (im Report, Tab/PDF):**
  - §30 Abs. 2 Nr. 1 (Risikomanagement) — *teilweise erfüllt*
  - §30 Abs. 2 Nr. 3 (Vorfallsbewältigung) — *nicht erfüllt: kein zentrales Logging, kein IR-Prozess*
  - §30 Abs. 2 Nr. 4 (Zugriffskontrolle / MFA) — *nicht erfüllt: keine MFA*
  - §30 Abs. 2 Nr. 8 (Kryptografie) — *teilweise erfüllt: veraltetes TLS*
  - §32 (Meldepflichten) — *Risiko*
- **Story:**
  > „Für Betreiber kritischer Infrastruktur — wie Stadtwerke — reicht ‚wir haben
  > gescannt' nicht mehr. **NIS2 und §30 BSIG** verlangen nachweisbares
  > Risikomanagement, MFA und Vorfallsbehandlung. Unser Compliance-Paket übersetzt
  > die technischen Funde direkt in die Gesetzesparagrafen: Hier sehen Sie schwarz
  > auf weiß, dass **MFA fehlt** und **kein zentrales Logging** existiert — beides
  > ‚nicht erfüllt'. Das ist genau die Lücke, für die Geschäftsführer heute
  > **persönlich haften**. Wir liefern Ihnen die Beweislage und die Roadmap dazu."

---

## 4. Stolperfallen & Reset (Troubleshooting)

| Symptom | Ursache / Lösung |
|---|---|
| Login schlägt fehl | Falsches Passwort-ENV? Default `VectiScanDemo2026!`, überschreibbar via `DEMO_PASSWORD`. Seed erneut laufen lassen. |
| Dashboard leer / keine Karten | Seed nicht ausgeführt oder andere DB. `npm run seed:demo` (idempotent) ausführen. |
| Karte führt nicht direkt zum Scan | Dashboard-Karte öffnet zuerst die **Gruppen-Übersicht**. Deep-Link aus Abschnitt 1 nutzen. |
| „PDF herunterladen" fehlt | Nur bei Status „Fertig"/Report vorhanden sichtbar. Korrekten Demo-Scan geöffnet? |
| PDF lädt nicht | MinIO-Container läuft nicht / Objekt fehlt. Seed neu laufen lassen (legt PDFs in `scan-reports/demo/…` an). |
| Fremder Login-State | Inkognito-Fenster nutzen. |
| Daten „verändert" nach Test | Seed ist idempotent → einfach erneut ausführen, stellt deterministisch denselben Zustand her. |

---

## 5. Objektiv prüfbare Akzeptanzkriterien (für QA-Gegenlauf, Sven)

Eine Person ohne Vorwissen führt das Skript einmal durch. **Bestanden**, wenn alle Punkte ✅:

- [ ] **AC1 — Login:** Mit `demo@vectiscan.tech` / `VectiScanDemo2026!` gelingt der Login und landet auf `/dashboard`.
- [ ] **AC2 — Dashboard:** Vier KPI-Karten sichtbar (**Domains, Scans gesamt, Aktive Scans, Gesamtrisiko**); „Gesamtrisiko" zeigt **CRITICAL**; drei Scan-Karten mit Risk-Badge + Severity-Verteilung sichtbar.
- [ ] **AC3 — Paket öffnen:** Jeder der drei Scans ist erreichbar (über Karte/Gruppe **oder** Deep-Link) und zeigt die Scan-Detailseite mit Risk-Badge.
- [ ] **AC4 — Risk + Findings:** Pro Paket stimmen Risiko und Top-Befunde mit Abschnitt 1/3 überein:
  - WebCheck = **MEDIUM**, 6 Befunde, kein C/H.
  - Perimeter = **HIGH**, enthält SQL-Injection (CRITICAL) + RDP + .git.
  - Compliance = **CRITICAL**, enthält VPN-RCE + fehlende MFA + Logging-Lücke + NIS2/§30-Summary.
- [ ] **AC5 — PDF:** Button **„PDF herunterladen"** ist je Paket vorhanden und liefert ein PDF mit Cover + Executive Summary + Befunden.
- [ ] **AC6 — Reproduzierbarkeit:** Nach erneutem `npm run seed:demo` ist der Zustand identisch (gleiche Risiken/Befundzahlen).
- [ ] **AC7 — Durchführbarkeit:** Die Demo war ohne Rückfrage an Entwickler/PM durchspielbar; jede beschriebene Schaltfläche/Bildschirm existiert wie dokumentiert.

> Abweichung melden: UI-/Datenlage → Max (CTO); Skript-/Talktrack-Korrektur → Paul (PM).

---

*Quellen: `docs/DEMO-SEED.md`, Frontend (`/login`, `/dashboard`, `/scan/[orderId]`),
Seed-Fixtures `api/src/scripts/demo-data/{webcheck,perimeter,compliance}.json`.
Synthetische Daten, keine PII.*

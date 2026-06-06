# Support-Pfad & Incident-Eskalation

Stand: VEC-83 (Launch-Ready-Gate). Quelle der Entscheidung: VEC-80 §3, VEC-20 §4/§8.

## Support-Kanal

- **Zentrale Adresse:** `support@vectiscan.de`
- **Geschäftszeiten:** Mo–Fr, 09:00–17:00 Uhr (CET)
- **In-App:** Route `/contact` (Header- und Footer-Link „Support", zusätzlich verlinkt auf `/pricing`).

Outbound-Mail läuft über Resend (`api/src/lib/email.ts`, Absender `noreply@vectiscan.de`).
Inbound für `support@vectiscan.de` ist über UDAG-Standard-MX (`mx00/mx01.udag.de`) als
Forwarding auf das interne Postfach eingerichtet und **verifiziert** (siehe „Empfangs-Nachweis").

> Hinweis zur Domain: Mit dem Brand-Cutover (VEC-268) ist die kanonische Marken-Domain
> `vectiscan.de`. Die frühere Adresse `support@vectigal.tech` wurde durchgängig auf
> `support@vectiscan.de` umgestellt — das ist das einzige verifiziert empfangsbereite Postfach.

## Light-SLA

| Kategorie | Erstreaktion | Fenster |
|---|---|---|
| **Standard-Anfrage** | ≤ 1 Werktag | Mo–Fr, 09–17 CET |
| **P1 — Security-/Datenschutz-Vorfall** | ≤ 4 Std. | innerhalb Geschäftszeiten |

Anfragen außerhalb der Geschäftszeiten werden am nächsten Werktag bearbeitet.
P1-Anfragen werden per Betreff-Präfix `[P1]` markiert.

## Eskalations- & Incident-Pfad

1. **Eingang** — Alle Anfragen laufen über `support@vectiscan.de` und werden werktäglich gesichtet.
2. **Triage (Standard)** — Support-Team antwortet bzw. routet innerhalb von 1 Werktag.
3. **P1-Vorfall** — sofortige Benachrichtigung von:
   - **Security-Verantwortlicher (Sven)** — technische Bewertung & Eindämmung
   - **CEO (Claudia)** — Geschäftsführungs-Entscheidung & Kommunikation

   Erstreaktion ≤ 4 Std. (Geschäftszeiten), laufende Status-Updates bis zur Eindämmung.
4. **Datenschutz-relevanter Vorfall** — Bewertung der Meldepflicht (Art. 33 DSGVO, 72-Std.-Frist)
   gemeinsam mit der Geschäftsführung; ggf. Meldung an die zuständige Aufsichtsbehörde.

## Wer wird wann benachrichtigt

| Auslöser | Benachrichtigt | Frist |
|---|---|---|
| Standard-Anfrage | Support-Team | 1 Werktag |
| P1 (Security/Datenschutz) | Sven (Security) + Claudia (CEO) | sofort, Reaktion ≤ 4 Std. |
| Meldepflichtiger Datenschutzvorfall | Geschäftsführung → Aufsichtsbehörde | ≤ 72 Std. (Art. 33 DSGVO) |

## Empfangs-Nachweis (DoD „Test-Mail kommt an")

Das Postfach `support@vectiscan.de` ist serverseitig empfangsfähig. Verifiziert über:

- **VEC-93** (done) — Postfach provisioniert, Empfang board-bestätigt (Confirmation `ee13b240`).
- **VEC-224** (done) — Test-Mail über realen Prod-Pfad `POST /api/auth/forgot-password`
  → Resend → `support@vectiscan.de` → Forward auf internes Postfach; Zustellung bestätigt.
- **VEC-271** (done) — Root-/Empfangs-MX auf `vectiscan.de` (UDAG `mx00/mx01.udag.de`)
  reaktiviert; SMTP-RCPT `250 Ok`, Send-MX/SPF/DKIM (VEC-268-Cutover) unberührt.

Damit ist das DoD-Kriterium „Test-Mail an Support kommt an" erfüllt.

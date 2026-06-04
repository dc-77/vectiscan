# Off-Site-Backup — Bewertung & Empfehlung

Ticket: VEC-85 (Teil von VEC-52, A5 — Produktions-Infra), Deliverable #4.
Dies ist ein **Entscheidungs-Dokument**, kein produktiver Code. Ergänzt das
Backup-Runbook `BACKUP-RESTORE.md`.

## Ist-Zustand (nach der Backup-Iteration)

- `scripts/backup-prod.sh` erzeugt nächtlich (GitLab-Schedule, `0 3 * * *`) einen
  konsistenten Satz unter `${DEPLOY_PATH}/backups/<TIMESTAMP>/`
  (PostgreSQL-Dump + MinIO-Buckets + SHA256-Manifest), Retention 14 Tage.
- **Alle Backups liegen ausschließlich lokal auf `vectigal-docker02`** — auf
  demselben Host wie die Produktion.

## Risiko

Single-Host-Backup schützt gegen *logische* Fehler (versehentliches Löschen,
fehlerhafte Migration, korrupte Tabelle) — **aber nicht** gegen:

- **Host-/Disk-Verlust** (Hardware-Defekt, gelöschte/zerstörte VM) → Prod **und**
  Backups gleichzeitig weg.
- **Ransomware / Kompromittierung** des Hosts → erreichbare lokale Backups werden
  mitverschlüsselt.
- **Rechenzentrums-/Standortausfall**.

Für eine Multi-Tenant-SaaS mit Kundendaten ist das die größte verbleibende
Infra-Lücke nach A5. Off-Site = **3-2-1-Regel** (≥1 Kopie an anderem Ort).

## Optionen

| # | Ziel | Spend | Aufwand | Bewertung |
|---|------|-------|---------|-----------|
| **A** | **Interner Off-Site-Host/NAS bei Bergersysteme** (anderer Server/Standort), Push via `rsync`/`restic` über SSH | **0 €**, falls Ziel vorhanden | gering | **Bevorzugt** — spend-frei, Daten bleiben im Haus (DSGVO-einfach), volle Kontrolle |
| B | Managed S3-kompatibel: **Hetzner Storage Box** (1 TB ≈ 3,81 €/Mon.) oder **Backblaze B2 / Wasabi** | ~3–6 €/Mon. | gering | Solide, günstig; benötigt Board-Approval (Spend) + AVV/DSGVO-Check (Backblaze = US) |
| C | Hetzner **Object Storage** (S3, EU) | nutzungsabhängig, gering | gering–mittel | EU-Region, S3-API; Spend nutzungsabhängig |
| D | Status quo (nur lokal) | 0 € | — | **Nicht empfohlen** — Risiko oben bleibt offen |

DSGVO-Hinweis: Optionen A und C/Hetzner liegen in der EU. Backblaze B2 (US)
nur mit AVV + Standardvertragsklauseln; Daten sind ohnehin verschlüsselbar
(restic verschlüsselt at-rest), aber Standortwahl bevorzugt EU.

## Empfehlung

1. **Priorität A:** Falls Bergersysteme einen zweiten Host / ein NAS an einem
   anderen Standort bereitstellen kann, dorthin nächtlich pushen — **spend-frei**.
2. **Fallback B:** Sonst **Hetzner Storage Box** (EU, ~3,81 €/Mon. für 1 TB,
   SSH/`restic`-fähig). Minimaler Spend → **Board-Approval** (siehe verknüpfte
   Approval im Ticket).

In **beiden** Fällen identische Umsetzung via `restic` (verschlüsselt,
inkrementell, dedupliziert) — nur das Repo-Backend (SSH-Pfad vs. Storage-Box)
unterscheidet sich. Damit ist die Migration zwischen A und B trivial.

## Umsetzungsskizze (sobald Ziel entschieden)

Additiver Schritt am Ende des bestehenden `backup-prod`-Jobs bzw. ein eigener
`offsite-sync`-Job, der nach erfolgreichem Backup läuft:

```bash
# .env / CI-Variablen (Secrets):
#   RESTIC_REPOSITORY   z.B. sftp:offsite@nas.intern:/backups/vectiscan   (A)
#                       oder sftp:uXXXX@uXXXX.your-storagebox.de:/vectiscan (B)
#   RESTIC_PASSWORD     Repo-Verschlüsselung (einmalig generiert, sicher ablegen!)

restic snapshots >/dev/null 2>&1 || restic init        # einmalig
restic backup "${DEPLOY_PATH}/backups/$(date +%Y%m%d)-*"  # neuesten Satz pushen
restic forget --keep-daily 14 --keep-weekly 8 --prune    # Off-Site-Retention
restic check --read-data-subset=5%                        # Integritäts-Stichprobe
```

Eigenschaften: Transport- + At-Rest-Verschlüsselung (kein Klartext beim
Provider), inkrementell (nur Deltas → wenig Traffic), eingebauter Integritäts-
Check. Restore-Test analog zu `BACKUP-RESTORE.md` ergänzen.

## Offene Entscheidung (Board / CEO)

Welches Off-Site-Ziel?
- **A** — interner Host/NAS verfügbar? (→ Pfad/SSH-Zugang nennen, spend-frei)
- **B** — Hetzner Storage Box freigeben (~3,81 €/Mon., Board-Approval)?

Sobald entschieden, ist die Umsetzung (restic-Job + 2 CI-Variablen + Schedule)
ein kleiner additiver Folge-Schritt — als Child-Ticket von VEC-52 umsetzbar.

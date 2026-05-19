# Sample-PDFs

Drei Real-Reports aus der laufenden API; ein Sample fehlt, weil die heuel-Order auf `failed` steht und kein PDF lieferbar ist.

## Vorhandene Samples

### `7629dd77-260b-4b68-9f26-b4d806fabe09.pdf` — secumetrix.de, perimeter

- **Domain:** secumetrix.de (+ apitest, cloudscanner-api, cloudscanner, app)
- **Paket:** perimeter
- **Order-Status:** `delivered` (PDF endgültig ausgeliefert)
- **Hosts:** 3 IPs (45.157.234.103, 173.249.44.221, …) mit mehreren VHosts; Multi-VHost-Probe wirkt.
- **Größe:** 32 Seiten, ~1.0 MB.

**Struktur-Hinweise:**

- Service-Karte (Layer 2, Seite 7) ist gut besetzt: RDP (3389), MS-SQL 2022, MySQL (3306), FTP (21), Ollama (8000/8080/8502/8503) — viele RED-Ports. Anhang B (Service-Inventar) zeigt für diese Ports die `_SERVICE_RECOMMENDATION_HINT`-Texte aus `appendix.py:186`.
- Tech-Tabelle (Seite 6) hat einen "Microsoft HTTPAPI httpd/2.0" + "WordPress 6.9.4" — interessant für den Kernel-Detection-Blacklist-Pfad (P1-05): `httpapi`/`http.sys` darf nicht als Tech erscheinen (siehe `tech_table_builder.KERNEL_DETECTION_BLACKLIST` und `validation/checks/tech_table.py`).
- Mehrere VHosts mit unterschiedlichen `site_summary.classification` (web_content vs login_only) → der Screenshot-Pipeline-Pfad mit `skip_non_content` ist hier sichtbar.
- ValidationGate-Level: STRICT (Default seit M6.7), die Order hat das Gate passed.

### `12bdbf3a-0691-42e4-933a-dad430f9fa0b.pdf` — heuel.com, perimeter

- **Domain:** heuel.com
- **Paket:** perimeter
- **Order-Status:** `pending_review` (PDF liegt vor, Admin noch nicht freigegeben)
- **Hosts:** 6 IPs (217.72.203.132 IONOS, 20.79.218.75 Azure, 195.225.241.75, 213.133.104.51 Hetzner, 104.16.10.6 Cloudflare, IPv6-Host)
- **Größe:** 23 Seiten, ~580 KB.

**Struktur-Hinweise:**

- Mehrere Hosts, davon einige ohne erreichbare Ports. Anhang B (Service-Inventar) zeigt den "Folgende Hosts haben in der externen Pruefung keine erreichbaren Ports gezeigt: …"-Sammler aus `appendix.py:336-342`.
- Cloudflare-Host (104.16.10.6) demonstriert den CDN-IP-Dedup-Pfad aus `project_multi_vhost.md` (Memory).
- Diese Order ist Beispiel für die `id_renumber`-Lückenlosigkeit nach Selection (siehe Layer 3 Befund-IDs).

## Fehlend: `dbeef8f3-d26d-4ca8-9b1a-d3d2e7608745.pdf` — heuel.com (alt), perimeter

Order-Status ist `failed` (`/api/orders/<id>/report` antwortet 404 mit `{"success":false,"error":"Report not yet available"}`). Die ursprüngliche Aufgabe-Beschreibung erwartete diese Order als M2-clean / ValidationGate STRICT — aktuell ist sie nicht abrufbar. Sobald ein Frischscan auf heuel.com erfolgreich durchläuft, kann dieses Sample nachträglich heruntergeladen werden:

```bash
EMAIL=$(head -1 ~/.claude/secrets/vectiscan-test.creds)
PASS=$(sed -n '2p' ~/.claude/secrets/vectiscan-test.creds)
JWT=$(curl -sS -X POST -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" \
  https://scan-api.vectigal.tech/api/auth/login \
  | python -c "import sys,json;print(json.load(sys.stdin)['data']['token'])")
curl -sS -H "Authorization: Bearer $JWT" \
  "https://scan-api.vectigal.tech/api/orders/dbeef8f3-d26d-4ca8-9b1a-d3d2e7608745/report" \
  -o "docs/report-pipeline/samples/dbeef8f3-d26d-4ca8-9b1a-d3d2e7608745.pdf"
```

## Hinweise zur Verwendung

Die Samples sind **keine** Bewertung der gescannten Befunde — sie illustrieren die Struktur der v2-Renderer-Pipeline (3 Schichten + 6 Anhänge). Zum Vergleich mit der Doku:

- Seite 1 = Cover (Doku in `06_v2_renderer.md` / Section "Cover").
- Seite 2 = Layer 1 (Doku in `07_layer1_aggregators.md`).
- Seite 3-9 = Layer 2 (Doku in `08_layer2_data.md`).
- Seite 10-N = Layer 3 (Doku in `09_layer3_findings.md`).
- Anhänge A-F (Doku in `10_appendices.md`).

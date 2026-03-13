import { test, expect, Page } from '@playwright/test';

const PASSWORD = process.env.VECTISCAN_PASSWORD || '';
const TEST_DOMAIN = 'scanme.nmap.org';
const API_URL = process.env.API_URL || 'https://scan-api.vectigal.tech';

// Timeout für den gesamten Scan-Vorgang (150 Minuten)
const SCAN_TIMEOUT = 150 * 60_000;
// Polling-Intervall für Status-Checks (30 Sekunden)
const POLL_INTERVAL = 30_000;

async function login(page: Page) {
  await page.goto('/');
  await page.locator('input[type="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Anmelden' }).click();
  await expect(page.locator('input[placeholder="beispiel.de"]')).toBeVisible({
    timeout: 10_000,
  });
}

test.describe('Scan-Workflow mit scanme.nmap.org', () => {
  test.beforeEach(() => {
    test.skip(!PASSWORD, 'VECTISCAN_PASSWORD nicht gesetzt');
  });

  test('Domain-Validierung lehnt ungültige Eingaben ab', async ({ page }) => {
    await login(page);

    // Ungültige Domain eingeben
    await page.locator('input[placeholder="beispiel.de"]').fill('http://example.com');
    await page.getByRole('button', { name: 'Scan starten' }).click();

    await expect(page.getByText('Ungültige Domain')).toBeVisible({ timeout: 5_000 });
  });

  test('Domain-Validierung lehnt Domain mit Pfad ab', async ({ page }) => {
    await login(page);

    await page.locator('input[placeholder="beispiel.de"]').fill('example.com/path');
    await page.getByRole('button', { name: 'Scan starten' }).click();

    await expect(page.getByText('Ungültige Domain')).toBeVisible({ timeout: 5_000 });
  });

  test('Scan starten und Fortschritt verfolgen', async ({ page }) => {
    test.setTimeout(SCAN_TIMEOUT);
    await login(page);

    // Domain eingeben und Scan starten
    await page.locator('input[placeholder="beispiel.de"]').fill(TEST_DOMAIN);
    await page.getByRole('button', { name: 'Scan starten' }).click();

    // Button sollte kurz "Startet..." anzeigen
    await expect(page.getByText('Startet...')).toBeVisible({ timeout: 5_000 });

    // Scan-Progress sollte erscheinen (Domain-Name im Header)
    await expect(page.getByText(TEST_DOMAIN)).toBeVisible({ timeout: 30_000 });

    // Phase-Badge sollte sichtbar sein
    await expect(
      page.getByText(
        /DNS-Reconnaissance|Phase 1|Phase 2|Report wird generiert|Erstellt/,
      ),
    ).toBeVisible({ timeout: 30_000 });

    // Abbrechen-Button sollte verfügbar sein
    await expect(page.getByText('Scan abbrechen')).toBeVisible({ timeout: 10_000 });

    // Warten bis Phase 0 (DNS) abgeschlossen ist — Hosts sollten erscheinen
    await expect(page.getByText('Entdeckte Hosts')).toBeVisible({
      timeout: 15 * 60_000, // max 15 Min für DNS-Phase
    });

    // Warten bis Scan + Report komplett oder fehlgeschlagen
    await expect(
      page.getByText(/Report fertig|Scan fehlgeschlagen/),
    ).toBeVisible({ timeout: SCAN_TIMEOUT });

    // Prüfen ob erfolgreich
    const success = await page.getByText('Report fertig').isVisible().catch(() => false);

    if (success) {
      // PDF-Download-Link prüfen
      await expect(page.getByText('PDF herunterladen')).toBeVisible();

      // Download-Link sollte eine gültige URL haben
      const downloadLink = page.locator('a:has-text("PDF herunterladen")');
      const href = await downloadLink.getAttribute('href');
      expect(href).toBeTruthy();

      // "Neuen Scan starten"-Button prüfen
      await expect(page.getByText('Neuen Scan starten')).toBeVisible();
    } else {
      // Fehlgeschlagen — Fehlermeldung dokumentieren
      const errorText = await page.locator('.font-mono.bg-\\[\\#0f172a\\]').textContent();
      console.log(`Scan fehlgeschlagen mit Fehler: ${errorText}`);

      // "Neuen Scan starten"-Button sollte trotzdem da sein
      await expect(page.getByText('Neuen Scan starten')).toBeVisible();
    }
  });

  test('Scan abbrechen funktioniert', async ({ page }) => {
    test.setTimeout(2 * 60_000);
    await login(page);

    // Scan starten
    await page.locator('input[placeholder="beispiel.de"]').fill(TEST_DOMAIN);
    await page.getByRole('button', { name: 'Scan starten' }).click();

    // Warten bis Scan läuft
    await expect(page.getByText('Scan abbrechen')).toBeVisible({ timeout: 30_000 });

    // Scan abbrechen
    await page.getByText('Scan abbrechen').click();

    // Sollte zurück zum Eingabeformular kommen
    await expect(page.locator('input[placeholder="beispiel.de"]')).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByRole('button', { name: 'Scan starten' })).toBeVisible();
  });
});

test.describe('API-Endpunkte (direkt)', () => {
  test('POST /api/scans mit ungültiger Domain wird abgelehnt', async ({ request }) => {
    const response = await request.post(`${API_URL}/api/scans`, {
      data: { domain: '' },
    });

    const body = await response.json();
    expect(body.success).toBe(false);
  });

  test('GET /api/scans/:id mit ungültiger ID gibt Fehler', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/scans/nonexistent-id`);

    expect([400, 404]).toContain(response.status());
  });
});

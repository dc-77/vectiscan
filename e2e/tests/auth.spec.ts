import { test, expect } from '@playwright/test';

const PASSWORD = process.env.VECTISCAN_PASSWORD || '';

test.describe('Authentifizierung', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('Login-Seite wird korrekt angezeigt', async ({ page }) => {
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Anmelden' })).toBeVisible();
    await expect(page.locator('input[type="password"]')).toHaveAttribute(
      'placeholder',
      'Passwort eingeben',
    );
  });

  test('Anmelden-Button ist deaktiviert ohne Eingabe', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Anmelden' })).toBeDisabled();
  });

  test('Falsches Passwort zeigt Fehlermeldung', async ({ page }) => {
    await page.locator('input[type="password"]').fill('falsches-passwort-xyz');
    await page.getByRole('button', { name: 'Anmelden' }).click();

    // Fehlermeldung sollte erscheinen
    await expect(page.getByText(/Falsches Passwort|API nicht erreichbar/)).toBeVisible({
      timeout: 10_000,
    });
  });

  test('Korrektes Passwort führt zur Scan-Seite', async ({ page }) => {
    test.skip(!PASSWORD, 'VECTISCAN_PASSWORD nicht gesetzt');

    await page.locator('input[type="password"]').fill(PASSWORD);
    await page.getByRole('button', { name: 'Anmelden' }).click();

    // Nach Login: Domain-Eingabe sichtbar
    await expect(page.locator('input[placeholder="beispiel.de"]')).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByRole('button', { name: 'Scan starten' })).toBeVisible();
    await expect(page.getByText('Automatisierte Security-Scan-Plattform')).toBeVisible();
  });
});

import { test, expect } from '@playwright/test';

const API_URL = process.env.API_URL || 'https://scan-api.vectigal.tech';

test.describe('Deployment Health Checks', () => {
  test('API /health endpoint antwortet mit 200', async ({ request }) => {
    const response = await request.get(`${API_URL}/health`);
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.success).toBe(true);
  });

  test('Frontend ist erreichbar', async ({ page }) => {
    await page.goto('/');
    // Login-Seite sollte geladen werden
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.getByText('Zugang zum Security-Scanner')).toBeVisible();
  });

  test('Frontend zeigt VectiScan-Logo', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText('Vecti')).toBeVisible();
    await expect(page.getByText('Scan', { exact: false })).toBeVisible();
  });
});

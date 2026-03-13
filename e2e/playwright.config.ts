import { defineConfig } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || 'https://scan.vectigal.tech';
const API_URL = process.env.API_URL || 'https://scan-api.vectigal.tech';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [['html', { open: 'never' }], ['list']],

  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'on-first-retry',
    ignoreHTTPSErrors: true,
    actionTimeout: 15_000,
  },

  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],

  // Scan-Tests können bis zu 150 Minuten dauern (120 Min Scan + 30 Min Report)
  timeout: 180 * 60_000,

  // Globale Umgebungsvariablen für Tests
  metadata: {
    baseUrl: BASE_URL,
    apiUrl: API_URL,
  },
});

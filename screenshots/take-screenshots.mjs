/**
 * Playwright screenshot script for VectiScan.
 * Takes screenshots of Frontend in different states and the mock API.
 */
import { chromium } from 'playwright';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCREENSHOTS_DIR = __dirname;
const FRONTEND_URL = 'http://localhost:3000';
const API_URL = 'http://localhost:4000';

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 900 },
    colorScheme: 'dark',
  });

  // --- 1. Frontend: Landing page (empty form) ---
  console.log('1/6 Frontend — Landing Page...');
  const page = await context.newPage();
  await page.goto(FRONTEND_URL, { waitUntil: 'networkidle' });
  await sleep(1000);
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '01-frontend-landing.png'), fullPage: true });

  // --- 2. Frontend: Type domain and start scan ---
  console.log('2/6 Frontend — Domain eingeben...');
  await page.fill('input[type="text"]', 'scanme.nmap.org');
  await sleep(500);
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '02-frontend-domain-input.png'), fullPage: true });

  // --- 3. Frontend: Scanning in progress (after clicking scan) ---
  console.log('3/6 Frontend — Scan läuft...');
  await page.click('button[type="submit"]');
  // Wait for polling to advance through states
  await sleep(4000);
  // Should be in scan_phase1 or phase2 by now
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '03-frontend-scan-progress.png'), fullPage: true });

  // --- 4. Frontend: Wait for deeper scan state ---
  console.log('4/6 Frontend — Tiefer Scan + Hosts...');
  await sleep(7000);
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '04-frontend-scan-hosts.png'), fullPage: true });

  // --- 5. Frontend: Report complete ---
  console.log('5/6 Frontend — Report fertig...');
  await sleep(8000);
  await page.screenshot({ path: path.join(SCREENSHOTS_DIR, '05-frontend-report-complete.png'), fullPage: true });

  // --- 6. Backend API: Health endpoint ---
  console.log('6/6 Backend API — /health...');
  const apiPage = await context.newPage();
  await apiPage.goto(`${API_URL}/health`, { waitUntil: 'networkidle' });
  await sleep(500);
  await apiPage.screenshot({ path: path.join(SCREENSHOTS_DIR, '06-backend-health.png'), fullPage: true });

  await browser.close();
  console.log('Alle Screenshots gespeichert in:', SCREENSHOTS_DIR);
}

main().catch((err) => {
  console.error('Screenshot-Fehler:', err);
  process.exit(1);
});

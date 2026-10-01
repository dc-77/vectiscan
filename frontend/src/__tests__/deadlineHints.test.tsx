/**
 * S7a Punkt 8 (E27): Fristhinweise zum Freigabetag im Admin-Review.
 *
 * Die Komponente wird gerendert; die Review-Seite selbst wird wie in reportBlocked.test.tsx im
 * Quelltext geprueft, weil das jsdom-Setup die Admin-Seiten nicht rendert.
 */
import * as fs from 'fs';
import * as path from 'path';
import { render, screen } from '@testing-library/react';

jest.mock('@/lib/api', () => ({ requeueReport: jest.fn() }));
jest.mock('@/components/ds', () => ({ ConfirmDialog: () => null }));

import { DeadlineHints } from '@/components/admin/ReportDefectsPanel';

const HEUEL = {
  subjekt: 'online.heuel.com:443',
  gueltigBis: '2026-10-25',
  tageScantag: 31,
  tageFreigabe: 27,
  regelScantag: null,
  regelFreigabe: 'cert_expiring_later',
  freigabetag: '2026-09-27',
};

describe('S7a E27: Fristhinweise zum Freigabetag', () => {
  it('nennt Subjekt, Ablauf, Tage und Regel am Scantag und heute', () => {
    render(<DeadlineHints hints={[HEUEL]} />);
    expect(screen.getByText('Fristen zum Freigabetag 27.09.2026')).toBeInTheDocument();
    expect(screen.getByText('online.heuel.com:443')).toBeInTheDocument();
    const zeile = screen.getByText('online.heuel.com:443').closest('li');
    expect(zeile?.textContent).toContain('gültig bis 25.10.2026');
    expect(zeile?.textContent).toContain('am Scantag 31 Tage, keine Fristregel');
    expect(zeile?.textContent).toContain('heute 27 Tage, Zertifikat läuft in höchstens 30 Tagen ab');
    expect(screen.getByText(/Stufe und\s+Regelauslösung bleiben am Scantag/)).toBeInTheDocument();
  });

  it('zeigt ohne Hinweise nichts', () => {
    const { container } = render(<DeadlineHints hints={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('steht auf der Review-Seite ueber den Reitern', () => {
    const page = fs.readFileSync(
      path.join(process.cwd(), 'src', 'app', 'admin', 'review', '[orderId]', 'page.tsx'), 'utf-8');
    const hinweis = page.indexOf('<DeadlineHints hints={report?.deadlineHints ?? []} />');
    expect(hinweis).toBeGreaterThan(0);
    expect(hinweis).toBeLessThan(page.indexOf('{/* Reiter */}'));
  });

  it('nennt die Pruefungen der Hinweise im Klartext', () => {
    const panel = fs.readFileSync(
      path.join(process.cwd(), 'src', 'components', 'admin', 'ReportDefectsPanel.tsx'), 'utf-8');
    for (const check of ['fristregel_am_berichtsdatum', 'frist_vor_berichtsdatum',
      'messadresse_ausserhalb_inventar', 'firmenname_nicht_bestaetigt', 'werkzeugfehler_im_kundentext']) {
      expect(panel).toContain(`${check}: '`);
    }
  });
});

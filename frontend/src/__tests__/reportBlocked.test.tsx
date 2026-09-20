/**
 * S5 — report_blocked im Frontend.
 *
 * Zwei Teile: der Status muss im kanonischen Mapping stehen (sonst rendert
 * StatusChip "Unbekannt"), und die Admin-Review-Seite muss die drei neuen
 * Reiter tragen. Die Seite selbst wird nicht gerendert, sondern im Quelltext
 * geprueft — dasselbe Vorgehen wie in admin-review-no-hang.test.tsx, weil das
 * jsdom-Setup die Admin-Seiten nicht rendert.
 */

import * as fs from 'fs';
import * as path from 'path';

import { statusMeta, statusLabel } from '@/lib/status';
import { STATUS_LABELS } from '@/lib/utils';

const SRC = path.join(process.cwd(), 'src');
const read = (...parts: string[]) => fs.readFileSync(path.join(SRC, ...parts), 'utf-8');

describe('S5: report_blocked ist ein bekannter Status', () => {
  it('traegt Klartext, Ton und Icon im kanonischen Mapping', () => {
    const meta = statusMeta('report_blocked');
    expect(meta.label).toBe('Bericht angehalten');
    expect(meta.tone).toBe('warn');
    expect(meta.glyph).toBe('alert');
    expect(statusLabel('report_blocked')).toBe('Bericht angehalten');
  });

  it('faellt nicht auf "Unbekannt" zurueck', () => {
    expect(statusMeta('report_blocked').label).not.toBe(statusMeta('gibt-es-nicht').label);
  });

  it('steht auch in der Altkarte, damit die Legacy-Ansichten es kennen', () => {
    expect(STATUS_LABELS.report_blocked).toBe('Bericht angehalten');
  });
});

describe('S5: Admin-Review traegt die neuen Reiter', () => {
  const page = read('app', 'admin', 'review', '[orderId]', 'page.tsx');

  it('kennt alle vier Reiter', () => {
    for (const label of ['Freigabe', 'Defekte', 'Beobachtungen ohne Regel', 'Kunde']) {
      expect(page).toContain(label);
    }
  });

  it('startet bei einem blockierten Bericht im Reiter Defekte', () => {
    expect(page).toContain("report?.status === 'report_blocked' ? 'defekte' : 'freigabe'");
  });

  it('haelt den Ladepfad aus VEC-349 ein', () => {
    expect(page).toMatch(/finally\s*{[\s\S]*?setLoading\(false\)/);
    expect(page).toContain('} catch {');
  });

  it('laedt nach einem Statuswechsel neu', () => {
    // Der Berichtslauf endet mit einem status-Ereignis; ohne Neuladen bliebe
    // die Defektliste veraltet stehen.
    const block = page.slice(page.indexOf('const relevant'), page.indexOf('if (relevant.includes'));
    expect(block).toContain("'status'");
  });
});

describe('S5: Defektliste und Beobachtungen', () => {
  const defects = read('components', 'admin', 'ReportDefectsPanel.tsx');
  const unprocessed = read('components', 'admin', 'UnprocessedPanel.tsx');

  it('zeigt Herkunft, Pruefung, Meldung und Befund', () => {
    for (const spalte of ['Stufe', 'Herkunft', 'Prüfung', 'Meldung', 'Befund']) {
      expect(defects).toContain(spalte);
    }
  });

  it('bietet Regenerieren nach Fix und einen Platzhalter fuer den Regelvorschlag', () => {
    expect(defects).toContain('Regenerieren nach Fix');
    expect(defects).toContain('requeueReport');
    expect(defects).toContain('Regelvorschlag');
    // Der Regelvorschlag kommt spaeter; der Knopf darf nichts ausloesen.
    const knopf = defects.slice(defects.indexOf('Regelvorschlag') - 500, defects.indexOf('Regelvorschlag'));
    expect(knopf).toContain('disabled');
  });

  it('nutzt den Bestaetigungsdialog statt des nativen confirm', () => {
    expect(defects).toContain('ConfirmDialog');
    expect(defects).not.toContain('window.confirm');
  });

  it('sagt im Reiter Beobachtungen, dass nichts davon in den Bericht geht', () => {
    expect(unprocessed).toContain('nicht im Kundenbericht');
  });
});

describe('S5: Kundenkontext', () => {
  const form = read('components', 'admin', 'CustomerContextForm.tsx');
  const wizard = read('app', 'scan', 'new', 'page.tsx');

  it('zeigt je Feld die Herkunft', () => {
    expect(form).toContain('SOURCE_LABELS');
    for (const quelle of ['kunde', 'recherche', 'admin']) {
      expect(form).toContain(quelle);
    }
  });

  it('speichert ueber die Admin-Route', () => {
    expect(form).toContain('updateCustomerContext');
  });

  it('fragt die Felder im Bestellprozess optional ab', () => {
    expect(wizard).toContain('Angaben zum Unternehmen');
    expect(wizard).toContain('(optional)');
    // Ohne Eingabe wird nichts mitgeschickt.
    expect(wizard).toContain('hatKontext ? kontext : undefined');
  });
});

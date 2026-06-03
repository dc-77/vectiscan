/**
 * Abhängigkeitsfreier PDF-Generator für den Demo-Sample-Report (VEC-86 / PA-6).
 *
 * Erzeugt einen gebrandeten, mehrseitigen VectiScan-Report direkt aus einem
 * findings_data-Objekt — ohne den vollen Python-Report-Worker-Stack (reportlab),
 * ohne Claude-API und ohne echten Scan. So bleibt der Demo-Seed in der reinen
 * Node-Umgebung der API reproduzierbar lauffähig.
 *
 * WICHTIG: Das ist bewusst KEIN Ersatz für den echten Report-Worker-PDF — es ist
 * ein deterministischer Demo-Report mit synthetischen Daten. Branding-Farben sind
 * an report-worker/reporter/pdf/branding.py angelehnt.
 */

// ── PDF-Low-Level ────────────────────────────────────────────────────────────
// Ein PDF ist eine Sammlung nummerierter Objekte + xref-Tabelle + Trailer.
// Text-Operatoren laufen in einem Content-Stream. Wir nutzen die Base-14-Fonts
// Helvetica / Helvetica-Bold (keine Einbettung nötig) mit WinAnsi-Encoding,
// damit deutsche Umlaute (ä ö ü ß) korrekt dargestellt werden.

const PAGE_W = 595.28; // A4 in pt
const PAGE_H = 841.89;
const MARGIN = 56;
const CONTENT_W = PAGE_W - 2 * MARGIN;

interface RGB {
  r: number;
  g: number;
  b: number;
}

function hex(c: string): RGB {
  const n = parseInt(c.replace('#', ''), 16);
  return { r: ((n >> 16) & 255) / 255, g: ((n >> 8) & 255) / 255, b: (n & 255) / 255 };
}

const COLORS = {
  navy: hex('#0F172A'),
  accent: hex('#38BDF8'),
  gold: hex('#EAB308'),
  text: hex('#1E293B'),
  muted: hex('#64748B'),
  white: hex('#FFFFFF'),
  line: hex('#CBD5E1'),
};

const SEVERITY_COLORS: Record<string, RGB> = {
  CRITICAL: hex('#DC2626'),
  HIGH: hex('#EA580C'),
  MEDIUM: hex('#CA8A04'),
  LOW: hex('#16A34A'),
  INFO: hex('#2563EB'),
};

// Helvetica-Zeichenbreiten (AFM, /1000 em) — gekürzt auf WinAnsi-Bereich.
// Für unbekannte Zeichen nehmen wir 500 als Default (gute Näherung).
const HELV_WIDTHS: Record<number, number> = {
  32: 278, 33: 278, 34: 355, 35: 556, 36: 556, 37: 889, 38: 667, 39: 191,
  40: 333, 41: 333, 42: 389, 43: 584, 44: 278, 45: 333, 46: 278, 47: 278,
  48: 556, 49: 556, 50: 556, 51: 556, 52: 556, 53: 556, 54: 556, 55: 556,
  56: 556, 57: 556, 58: 278, 59: 278, 60: 584, 61: 584, 62: 584, 63: 556,
  64: 1015, 65: 667, 66: 667, 67: 722, 68: 722, 69: 667, 70: 611, 71: 778,
  72: 722, 73: 278, 74: 500, 75: 667, 76: 556, 77: 833, 78: 722, 79: 778,
  80: 667, 81: 778, 82: 722, 83: 667, 84: 611, 85: 722, 86: 667, 87: 944,
  88: 667, 89: 667, 90: 611, 91: 278, 92: 278, 93: 278, 94: 469, 95: 556,
  96: 333, 97: 556, 98: 556, 99: 500, 100: 556, 101: 556, 102: 278, 103: 556,
  104: 556, 105: 222, 106: 222, 107: 500, 108: 222, 109: 833, 110: 556,
  111: 556, 112: 556, 113: 556, 114: 333, 115: 500, 116: 278, 117: 556,
  118: 500, 119: 722, 120: 500, 121: 500, 122: 500, 123: 334, 124: 260,
  125: 334, 126: 584,
  // WinAnsi-Umlaute
  196: 667, 214: 778, 220: 722, 223: 556, 228: 556, 246: 556, 252: 556, 8364: 556,
};

function charWidth(code: number, fontSize: number): number {
  const w = HELV_WIDTHS[code] ?? 556;
  return (w / 1000) * fontSize;
}

function textWidth(s: string, fontSize: number): number {
  let w = 0;
  for (const ch of s) w += charWidth(ch.codePointAt(0)!, fontSize);
  return w;
}

/** Bricht Text auf maxWidth um (Wort-Wrapping, mit Hard-Break für lange Tokens). */
function wrap(s: string, fontSize: number, maxWidth: number): string[] {
  const out: string[] = [];
  for (const rawLine of s.split('\n')) {
    const words = rawLine.split(/\s+/).filter(Boolean);
    let line = '';
    for (const word of words) {
      const candidate = line ? `${line} ${word}` : word;
      if (textWidth(candidate, fontSize) <= maxWidth) {
        line = candidate;
      } else {
        if (line) out.push(line);
        if (textWidth(word, fontSize) > maxWidth) {
          // Hard-Break für überlange Tokens (z. B. URLs, Vektoren)
          let chunk = '';
          for (const ch of word) {
            if (textWidth(chunk + ch, fontSize) > maxWidth) {
              out.push(chunk);
              chunk = ch;
            } else {
              chunk += ch;
            }
          }
          line = chunk;
        } else {
          line = word;
        }
      }
    }
    out.push(line);
  }
  return out;
}

// PDF-String-Escaping
function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

// ── Layout-Engine ────────────────────────────────────────────────────────────

interface PageOps {
  ops: string[];
}

class PdfBuilder {
  private pages: PageOps[] = [];
  private cur!: PageOps;
  private y = 0;
  private readonly footerText: string;

  constructor(footerText: string) {
    this.footerText = footerText;
    this.newPage();
  }

  private rg(c: RGB): void {
    this.cur.ops.push(`${c.r.toFixed(3)} ${c.g.toFixed(3)} ${c.b.toFixed(3)} rg`);
  }

  newPage(): void {
    this.cur = { ops: [] };
    this.pages.push(this.cur);
    this.y = PAGE_H - MARGIN;
  }

  private ensure(space: number): void {
    if (this.y - space < MARGIN + 24) this.newPage();
  }

  rect(x: number, yTop: number, w: number, h: number, color: RGB): void {
    this.rg(color);
    this.cur.ops.push(`${x.toFixed(2)} ${(yTop - h).toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re f`);
  }

  private drawText(x: number, y: number, s: string, size: number, bold: boolean, color: RGB): void {
    const font = bold ? '/F2' : '/F1';
    this.rg(color);
    this.cur.ops.push(`BT ${font} ${size} Tf ${x.toFixed(2)} ${y.toFixed(2)} Td (${esc(s)}) Tj ET`);
  }

  /** Mehrzeiliger, umgebrochener Absatz. Gibt Restkonsum zurück. */
  paragraph(
    s: string,
    opts: { size?: number; bold?: boolean; color?: RGB; indent?: number; gap?: number; leading?: number } = {},
  ): void {
    const size = opts.size ?? 10;
    const color = opts.color ?? COLORS.text;
    const indent = opts.indent ?? 0;
    const leading = opts.leading ?? size * 1.45;
    const x = MARGIN + indent;
    const lines = wrap(s, size, CONTENT_W - indent);
    for (const ln of lines) {
      this.ensure(leading);
      this.drawText(x, this.y, ln, size, opts.bold ?? false, color);
      this.y -= leading;
    }
    if (opts.gap) this.y -= opts.gap;
  }

  spacer(h: number): void {
    this.y -= h;
  }

  rule(color: RGB = COLORS.accent, weight = 1.4): void {
    this.ensure(weight + 6);
    this.rect(MARGIN, this.y, CONTENT_W, weight, color);
    this.y -= weight + 8;
  }

  sectionTitle(title: string): void {
    this.ensure(34);
    this.drawText(MARGIN, this.y, title, 15, true, COLORS.navy);
    this.y -= 19;
    this.rule(COLORS.accent, 1.4);
    this.y -= 2;
  }

  /** Gefülltes Banner mit Text (z. B. Risk-Box). */
  banner(label: string, value: string, fill: RGB): void {
    const h = 46;
    this.ensure(h + 10);
    const top = this.y;
    this.rect(MARGIN, top, CONTENT_W, h, fill);
    this.drawText(MARGIN + 14, top - 18, label, 9, true, COLORS.white);
    this.drawText(MARGIN + 14, top - 36, value, 16, true, COLORS.white);
    this.y = top - h - 12;
  }

  /** Kleines Severity-Tag + Titelzeile für ein Finding. */
  findingHeader(idLabel: string, title: string, severity: string): void {
    this.ensure(40);
    const sev = severity.toUpperCase();
    const fill = SEVERITY_COLORS[sev] ?? COLORS.muted;
    const tagW = textWidth(sev, 8) + 16;
    const top = this.y;
    this.rect(MARGIN, top, tagW, 15, fill);
    this.drawText(MARGIN + 8, top - 11, sev, 8, true, COLORS.white);
    this.drawText(MARGIN + tagW + 10, top - 11, idLabel, 9, true, COLORS.muted);
    this.y = top - 22;
    this.paragraph(title, { size: 12, bold: true, color: COLORS.navy, gap: 2 });
  }

  keyValue(key: string, value: string): void {
    this.ensure(14);
    this.drawText(MARGIN, this.y, key, 9, true, COLORS.muted);
    const keyW = textWidth(key, 9) + 10;
    const lines = wrap(value, 9, CONTENT_W - keyW);
    this.drawText(MARGIN + keyW, this.y, lines[0] ?? '', 9, false, COLORS.text);
    this.y -= 13;
    for (let i = 1; i < lines.length; i++) {
      this.ensure(12);
      this.drawText(MARGIN + keyW, this.y, lines[i], 9, false, COLORS.text);
      this.y -= 12;
    }
  }

  /** Farb-Swatch + Text auf einer Zeile (z. B. Severity-Verteilung). */
  swatch(color: RGB, text: string): void {
    this.ensure(16);
    const top = this.y;
    this.rect(MARGIN, top, 12, 11, color);
    this.drawText(MARGIN + 20, top - 9, text, 10, false, COLORS.text);
    this.y = top - 16;
  }

  labelledBlock(label: string, body: string): void {
    this.ensure(16);
    this.drawText(MARGIN, this.y, label, 8.5, true, COLORS.accent);
    this.y -= 12;
    this.paragraph(body, { size: 9.5, color: COLORS.text, gap: 4 });
  }

  // ── Render zu PDF-Bytes ──────────────────────────────────────────────────
  build(): Buffer {
    const objects: Buffer[] = [];
    const addObj = (body: string | Buffer): number => {
      objects.push(typeof body === 'string' ? Buffer.from(body, 'latin1') : body);
      return objects.length; // 1-basierte Objektnummer
    };

    // Reservierte Nummern: 1=Catalog, 2=Pages, 3=F1, 4=F2.
    // Seiten + Content-Streams folgen danach.
    const fontF1 = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>';
    const fontF2 = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>';

    const total = this.pages.length;
    const pageObjNums: number[] = [];
    const contentObjNums: number[] = [];

    // Platzhalter für Catalog(1) + Pages(2)
    addObj(''); // 1
    addObj(''); // 2
    const f1 = addObj(fontF1); // 3
    const f2 = addObj(fontF2); // 4

    this.pages.forEach((pg, idx) => {
      // Footer auf jede Seite
      const footY = MARGIN - 18;
      pg.ops.push(`${COLORS.line.r.toFixed(3)} ${COLORS.line.g.toFixed(3)} ${COLORS.line.b.toFixed(3)} rg`);
      pg.ops.push(`${MARGIN} ${(footY + 12).toFixed(2)} ${CONTENT_W} 0.6 re f`);
      pg.ops.push(
        `BT /F1 7.5 Tf ${COLORS.muted.r.toFixed(3)} ${COLORS.muted.g.toFixed(3)} ${COLORS.muted.b.toFixed(3)} rg ${MARGIN} ${footY} Td (${esc(this.footerText)}) Tj ET`,
      );
      const pageLabel = `Seite ${idx + 1} / ${total}`;
      const plW = textWidth(pageLabel, 7.5);
      pg.ops.push(
        `BT /F1 7.5 Tf ${COLORS.muted.r.toFixed(3)} ${COLORS.muted.g.toFixed(3)} ${COLORS.muted.b.toFixed(3)} rg ${(PAGE_W - MARGIN - plW).toFixed(2)} ${footY} Td (${esc(pageLabel)}) Tj ET`,
      );

      const stream = pg.ops.join('\n');
      const contentBuf = Buffer.from(`<< /Length ${Buffer.byteLength(stream, 'latin1')} >>\nstream\n${stream}\nendstream`, 'latin1');
      const cNum = addObj(contentBuf);
      contentObjNums.push(cNum);

      const pageDict = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W.toFixed(2)} ${PAGE_H.toFixed(2)}] /Resources << /Font << /F1 ${f1} 0 R /F2 ${f2} 0 R >> >> /Contents ${cNum} 0 R >>`;
      const pNum = addObj(pageDict);
      pageObjNums.push(pNum);
    });

    // Catalog + Pages jetzt befüllen
    objects[0] = Buffer.from('<< /Type /Catalog /Pages 2 0 R >>', 'latin1');
    const kids = pageObjNums.map((n) => `${n} 0 R`).join(' ');
    objects[1] = Buffer.from(`<< /Type /Pages /Kids [${kids}] /Count ${total} >>`, 'latin1');

    // Datei zusammenbauen + xref
    const header = Buffer.from('%PDF-1.5\n%\xE2\xE3\xCF\xD3\n', 'latin1');
    const chunks: Buffer[] = [header];
    const offsets: number[] = [];
    let pos = header.length;
    objects.forEach((obj, i) => {
      offsets[i] = pos;
      const objHeader = Buffer.from(`${i + 1} 0 obj\n`, 'latin1');
      const objFooter = Buffer.from('\nendobj\n', 'latin1');
      chunks.push(objHeader, obj, objFooter);
      pos += objHeader.length + obj.length + objFooter.length;
    });

    const xrefStart = pos;
    let xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
    for (let i = 0; i < objects.length; i++) {
      xref += `${offsets[i].toString().padStart(10, '0')} 00000 n \n`;
    }
    xref += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;
    chunks.push(Buffer.from(xref, 'latin1'));

    return Buffer.concat(chunks);
  }
}

// ── Öffentliche API ──────────────────────────────────────────────────────────

export interface DemoFinding {
  id?: string;
  title: string;
  severity: string;
  cvss_score?: string | number;
  cvss_vector?: string;
  cwe?: string;
  affected?: string;
  description?: string;
  evidence?: string;
  impact?: string;
  recommendation?: string;
}

export interface DemoFindingsData {
  overall_risk: string;
  overall_description?: string;
  severity_counts: Record<string, number>;
  findings: DemoFinding[];
  positive_findings?: Array<{ title: string; description: string }>;
  recommendations?: Array<{ timeframe?: string; action: string; effort?: string }>;
  package: string;
}

const PACKAGE_LABELS: Record<string, string> = {
  webcheck: 'WebCheck — Website- & Mail-Security-Schnellscan',
  perimeter: 'Perimeter — Vollständiger Infrastruktur-Pentest',
  compliance: 'Compliance — Perimeter + §30 BSIG / BSI-Grundschutz',
  supplychain: 'SupplyChain — Perimeter + ISO 27001 Annex A',
  insurance: 'Insurance — Perimeter + Cyber-Versicherungs-Fragebogen',
};

/**
 * Erzeugt die PDF-Bytes für einen Demo-Report.
 * @param data    findings_data-Objekt (synthetisch)
 * @param target  Ziel-Domain (synthetisch)
 * @param dateIso ISO-Datum des "Scans" (deterministisch übergeben)
 */
export function generateDemoReportPdf(data: DemoFindingsData, target: string, dateIso: string): Buffer {
  const pkg = data.package.toLowerCase();
  const pkgLabel = PACKAGE_LABELS[pkg] ?? data.package.toUpperCase();
  const dateStr = new Date(dateIso).toLocaleDateString('de-DE', { day: '2-digit', month: 'long', year: 'numeric' });
  const b = new PdfBuilder('VectiScan Demo · Synthetische Daten — kein echter Scan · Vectigal GmbH (vertraulich)');

  // ── Cover ──
  b.spacer(40);
  b.paragraph('VECTISCAN', { size: 30, bold: true, color: COLORS.accent, gap: 2 });
  b.paragraph('Security Assessment Report', { size: 18, bold: true, color: COLORS.navy, gap: 18 });
  b.rule(COLORS.gold, 2);
  b.spacer(8);
  b.keyValue('Paket:', pkgLabel);
  b.keyValue('Ziel:', target);
  b.keyValue('Berichtsdatum:', dateStr);
  b.keyValue('Klassifizierung:', 'VERTRAULICH — nur für autorisierte Empfänger');
  b.spacer(20);
  b.banner('DEMO-REPORT — SYNTHETISCHE DATEN', 'Kein echter Scan · keine realen Kundendaten / PII', COLORS.muted);
  b.spacer(10);
  b.paragraph(
    'Dieser Bericht dient ausschließlich Demonstrationszwecken. Alle Ziel-Hosts, Befunde und ' +
      'Kennzahlen sind synthetisch erzeugt und bilden ein realistisches, aber fiktives Szenario ab.',
    { size: 9, color: COLORS.muted },
  );

  // ── Executive Summary ──
  b.newPage();
  b.sectionTitle('1  Executive Summary');
  const risk = data.overall_risk.toUpperCase();
  b.banner('GESAMTRISIKO', risk, SEVERITY_COLORS[risk] ?? COLORS.muted);
  if (data.overall_description) {
    b.paragraph(data.overall_description, { size: 10.5, gap: 10 });
  }

  // Severity-Verteilung
  b.paragraph('Befundverteilung nach Schweregrad', { size: 11, bold: true, color: COLORS.navy, gap: 4 });
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  for (const sev of order) {
    const count = data.severity_counts[sev] ?? data.severity_counts[sev.toLowerCase()] ?? 0;
    if (count === 0) continue;
    b.swatch(SEVERITY_COLORS[sev] ?? COLORS.muted, `${sev}: ${count} Befund${count === 1 ? '' : 'e'}`);
  }
  b.spacer(8);

  if (data.recommendations && data.recommendations.length) {
    b.paragraph('Priorisierte Empfehlungen', { size: 11, bold: true, color: COLORS.navy, gap: 4 });
    data.recommendations.forEach((r, i) => {
      const tf = r.timeframe ? `[${r.timeframe}] ` : '';
      const ef = r.effort ? `  (Aufwand: ${r.effort})` : '';
      b.paragraph(`${i + 1}. ${tf}${r.action}${ef}`, { size: 9.5, indent: 4, gap: 3 });
    });
  }

  // ── Findings ──
  b.newPage();
  b.sectionTitle('2  Detaillierte Befunde');
  data.findings.forEach((f, i) => {
    const id = f.id || `F-${String(i + 1).padStart(2, '0')}`;
    b.findingHeader(id, f.title, f.severity);
    const cvss = f.cvss_score != null ? String(f.cvss_score) : '—';
    b.keyValue('CVSS:', `${cvss}${f.cvss_vector ? `  ${f.cvss_vector}` : ''}`);
    if (f.cwe) b.keyValue('CWE:', f.cwe);
    if (f.affected) b.keyValue('Betroffen:', f.affected);
    if (f.description) b.labelledBlock('BESCHREIBUNG', f.description);
    if (f.evidence) b.labelledBlock('NACHWEIS', f.evidence);
    if (f.impact) b.labelledBlock('AUSWIRKUNG', f.impact);
    if (f.recommendation) b.labelledBlock('EMPFEHLUNG', f.recommendation);
    b.rule(COLORS.line, 0.6);
  });

  // ── Positive Findings ──
  if (data.positive_findings && data.positive_findings.length) {
    b.sectionTitle('3  Positive Feststellungen');
    data.positive_findings.forEach((p) => {
      b.paragraph(`✓ ${p.title}`, { size: 10.5, bold: true, color: COLORS.navy, gap: 1 });
      if (p.description) b.paragraph(p.description, { size: 9.5, indent: 12, gap: 6 });
    });
  }

  // ── Disclaimer ──
  b.newPage();
  b.sectionTitle('Haftungsausschluss');
  b.paragraph(
    'Dieser Demo-Report wurde von der VectiScan-Plattform mit synthetischen Daten erzeugt und ' +
      'enthält keine Ergebnisse eines realen Sicherheits-Scans. Er dient ausschließlich der ' +
      'Produktdemonstration. Eine echte Sicherheitsbewertung erfordert eine schriftliche ' +
      'Auftragserteilung und einen vollständigen, autorisierten Scan der jeweiligen Zielsysteme. ' +
      'Vectigal GmbH übernimmt keine Gewähr für die Übertragbarkeit dieser Demo-Befunde auf reale Systeme.',
    { size: 10, color: COLORS.text, gap: 12 },
  );
  b.paragraph('© Vectigal GmbH · VectiScan · Vertraulich', { size: 9, color: COLORS.muted });

  return b.build();
}

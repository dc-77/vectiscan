/**
 * S7a Punkt 8 (Entscheidung E27, spec/11 Teil 6): Fristregeln am Freigabetag.
 *
 * Stufe und Regelausloesung eines Berichts bleiben am Scantag. Das Berichtsdatum ist aber der
 * Tag der Freigabe (E15); faellt eine Fristregel an diesem Tag anders aus als am Scantag
 * (heuel online.heuel.com: 31 Tage am Scantag, Schwelle 30), braucht der Admin vor der Freigabe
 * einen Hinweis. Der report-worker legt dafuer die Fristen nahe einer Schwelle mit den Schwellen
 * des Katalogs in `orders.report_defects` ab (`fristen`, `fristen_schwellen`, `fristen_scantag`,
 * report-worker/reporter/gate/fristen.py); hier wird dieselbe Einordnung fuer den heutigen Tag
 * in Europe/Berlin nachgerechnet.
 */

export interface Frist {
  art: 'tls' | 'service_cert' | 'domain';
  subjekt: string;
  gueltig_bis: string;
  tage_scantag: number;
}

export interface Schwellen {
  sofort: number;
  bald: number;
  spaeter: number;
  domain: number;
}

export interface FristHinweis {
  subjekt: string;
  gueltigBis: string;
  tageScantag: number;
  tageFreigabe: number;
  regelScantag: string | null;
  regelFreigabe: string | null;
  freigabetag: string;
}

/** Welche Fristregel bei `tage` Restlaufzeit ausloest (gleiche Tabelle wie reporter/gate/fristen.py). */
export function fristKlasse(art: Frist['art'], tage: number, s: Schwellen): string | null {
  if (art === 'domain') return tage <= s.domain ? 'domain_expiring' : null;
  if (tage < 0) return art === 'service_cert' ? 'service_cert_expired' : 'cert_expired';
  if (art === 'service_cert') return null;
  if (tage <= s.sofort) return 'cert_expiring_sofort';
  if (tage <= s.bald) return 'cert_expiring';
  if (tage <= s.spaeter) return 'cert_expiring_later';
  return null;
}

/** Kalendertag in Europe/Berlin als JJJJ-MM-TT. */
export function berlinDatum(jetzt: Date): string {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Berlin', year: 'numeric', month: '2-digit', day: '2-digit',
  }).format(jetzt);
}

function tageZwischen(von: string, bis: string): number {
  const a = Date.UTC(+von.slice(0, 4), +von.slice(5, 7) - 1, +von.slice(8, 10));
  const b = Date.UTC(+bis.slice(0, 4), +bis.slice(5, 7) - 1, +bis.slice(8, 10));
  return Math.round((b - a) / 86_400_000);
}

const ISO_TAG = /^\d{4}-\d{2}-\d{2}$/;

function istSchwellen(wert: unknown): wert is Schwellen {
  if (!wert || typeof wert !== 'object') return false;
  const s = wert as Record<string, unknown>;
  return ['sofort', 'bald', 'spaeter', 'domain'].every(k => typeof s[k] === 'number');
}

/**
 * Hinweise fuer eine Freigabe am Tag von `jetzt`: jede Frist, deren Regel an diesem Tag anders
 * ausfiele als am Scantag. Ohne Fristen in der Nutzlast (aeltere Laeufe) eine leere Liste.
 */
export function fristHinweise(payload: Record<string, unknown> | null | undefined,
                              jetzt: Date = new Date()): FristHinweis[] {
  if (!payload) return [];
  const scantag = payload.fristen_scantag;
  const schwellen = payload.fristen_schwellen;
  const fristen = Array.isArray(payload.fristen) ? (payload.fristen as Frist[]) : [];
  if (typeof scantag !== 'string' || !ISO_TAG.test(scantag) || !istSchwellen(schwellen)) return [];
  const freigabetag = berlinDatum(jetzt);
  const verschiebung = tageZwischen(scantag, freigabetag);
  if (verschiebung <= 0) return [];
  const out: FristHinweis[] = [];
  for (const f of fristen) {
    if (!f || typeof f.tage_scantag !== 'number' || typeof f.subjekt !== 'string') continue;
    const tageFreigabe = f.tage_scantag - verschiebung;
    const vorher = fristKlasse(f.art, f.tage_scantag, schwellen);
    const nachher = fristKlasse(f.art, tageFreigabe, schwellen);
    if (vorher !== nachher) {
      out.push({
        subjekt: f.subjekt, gueltigBis: f.gueltig_bis, tageScantag: f.tage_scantag, tageFreigabe,
        regelScantag: vorher, regelFreigabe: nachher, freigabetag,
      });
    }
  }
  return out;
}

/**
 * Kundenkontext einer Order (S5, Migration 045).
 *
 * Flache Felder plus eine Herkunft je Feld. Die Herkunft entscheidet, wer ein
 * Feld noch anfassen darf: was der Kunde angegeben hat und was ein Admin
 * korrigiert hat, ueberschreibt die Recherche-KI nie.
 *
 * Geschrieben wird der Kontext an zwei Stellen: beim Anlegen der Order
 * (Quelle `kunde`) und im Admin-Review (Quelle `admin`). Die dritte Quelle
 * `recherche` setzt der report-worker.
 */

export type ContextSource = 'kunde' | 'recherche' | 'admin';

export interface CustomerContext {
  firmenname?: string;
  kuerzel?: string;
  branche?: string;
  mitarbeiter?: string;
  systeme?: Array<{ fqdn: string; zweck: string }>;
  sources?: Record<string, { source: ContextSource; url?: string }>;
}

// Felder, die von aussen gesetzt werden duerfen. Alles andere wird verworfen;
// `sources` verwaltet der Server selbst.
export const CUSTOMER_CONTEXT_TEXT_FIELDS = [
  'firmenname', 'kuerzel', 'branche', 'mitarbeiter',
] as const;
export const CUSTOMER_CONTEXT_FIELD_LIMIT = 200;
export const CUSTOMER_CONTEXT_MAX_SYSTEME = 50;

/**
 * Whitelist und Herkunft fuer den Kundenkontext.
 *
 * Jedes gesetzte Feld bekommt die angegebene Quelle. Ein leer uebergebenes Feld
 * loescht den Wert samt Herkunft und gibt ihn damit fuer die Recherche wieder
 * frei. Felder, die der Aufrufer gar nicht nennt, bleiben unveraendert.
 */
export function sanitizeCustomerContext(
  raw: unknown,
  source: ContextSource,
  previous: CustomerContext | null = null,
): CustomerContext {
  const input = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const result: CustomerContext = {};
  const sources: Record<string, { source: ContextSource; url?: string }> = {
    ...(previous?.sources ?? {}),
  };

  for (const field of CUSTOMER_CONTEXT_TEXT_FIELDS) {
    if (!(field in input)) {
      const kept = previous?.[field];
      if (kept) result[field] = kept;
      continue;
    }
    const value = typeof input[field] === 'string'
      ? (input[field] as string).replace(/\s+/g, ' ').trim().slice(0, CUSTOMER_CONTEXT_FIELD_LIMIT)
      : '';
    if (value) {
      result[field] = value;
      sources[field] = { source };
    } else {
      delete sources[field];
    }
  }

  if ('systeme' in input) {
    const systeme = Array.isArray(input.systeme) ? input.systeme : [];
    const cleaned = systeme
      .filter((s): s is Record<string, unknown> => !!s && typeof s === 'object')
      .map(s => ({
        fqdn: String(s.fqdn ?? '').trim().toLowerCase().slice(0, CUSTOMER_CONTEXT_FIELD_LIMIT),
        zweck: String(s.zweck ?? '').replace(/\s+/g, ' ').trim().slice(0, CUSTOMER_CONTEXT_FIELD_LIMIT),
      }))
      .filter(s => s.fqdn && s.zweck)
      .slice(0, CUSTOMER_CONTEXT_MAX_SYSTEME);
    if (cleaned.length > 0) {
      result.systeme = cleaned;
      sources.systeme = { source };
    } else {
      delete sources.systeme;
    }
  } else if (previous?.systeme?.length) {
    result.systeme = previous.systeme;
  }

  // Herkunft nur fuer Felder behalten, die es noch gibt.
  for (const key of Object.keys(sources)) {
    if (!(key in result)) delete sources[key];
  }
  if (Object.keys(sources).length > 0) result.sources = sources;
  return result;
}

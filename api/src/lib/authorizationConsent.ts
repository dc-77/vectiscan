/**
 * Registrierungs-Policy: Firmen-E-Mail-Pflicht + versionierte
 * Scan-Berechtigungs-Bestaetigung (VEC-364, Phase 1b aus VEC-360 §6).
 *
 * Board-Vorgabe: Jeder Check erfordert ein Konto mit Firmen-E-Mail UND eine
 * verpflichtende, versionierte Berechtigungs-Bestaetigung. Dieses Modul ist die
 * SSoT der API-Seite fuer:
 *   - die Freemail-Erkennung (Block von gmail/gmx/… bei der Registrierung),
 *   - den exakten Erklaerungstext + dessen Version (Nachweis am users-Datensatz).
 *
 * RECHTS-GATE: Die juristische Formulierung von AUTHORIZATION_CONSENT_TEXT muss
 * vor Go-live vom Board/Recht freigegeben sein. Eine Wording-Aenderung MUSS die
 * Version bumpen (Format `YYYY-MM-DD.n`), damit der gespeicherte Nachweis je
 * Nutzer eindeutig auf den eingewilligten Text zeigt. Der Server setzt die
 * Version autoritativ — der Client kann sie nicht faelschen.
 *
 * Pure Helfer, ohne DB/IO — unit-testbar.
 */

/** Version des aktuell gueltigen Berechtigungs-Erklaerungstextes. Bei jeder
 *  Wording-Aenderung bumpen (Format `YYYY-MM-DD.n`). */
export const AUTHORIZATION_CONSENT_VERSION = '2026-06-10.1' as const;

/**
 * Erklaerungstext (erweiterte Variante). Board/Recht-Freigabe des Wortlauts:
 * Confirmation 62b445cb accepted 2026-06-10 (Dokument consent-wording, VEC-364).
 * Die Version oben verweist auf GENAU diesen Wortlaut — byte-identisch mit dem
 * im Frontend angezeigten Text (frontend/src/app/login/page.tsx).
 */
export const AUTHORIZATION_CONSENT_TEXT =
  'Ich bestätige, dass ich ausschließlich Domains, IP-Adressen und Systeme zum Scan ' +
  'beauftrage, für die ich selbst Inhaber bin oder über eine nachweisbare, ' +
  'ausdrückliche Genehmigung des Inhabers verfüge. Für die von mir beauftragten Ziele ' +
  'erteile ich VectiScan hiermit die Genehmigung, die im gewählten Paket beschriebenen ' +
  'Sicherheits-Scans durchzuführen. Mir ist bekannt, dass das Scannen fremder Systeme ohne ' +
  'Genehmigung rechtswidrig sein kann (insb. §§ 202a–202c StGB), und ich stelle ' +
  'VectiScan von Ansprüchen Dritter frei, die aus von mir ohne Genehmigung beauftragten ' +
  'Scans entstehen.';

/**
 * Freemail-/Consumer-Provider — keine Firmen-E-Mail. Bewusst deckungsgleich mit
 * der Frontend-Liste in `WebCheckLeadForm.tsx` (getrennte Build-Kontexte, daher
 * dupliziert statt geteilt). Match auf die Domain nach dem letzten '@'.
 */
const FREEMAIL_DOMAINS = [
  'gmail', 'googlemail', 'gmx', 'web', 'yahoo', 'ymail', 'hotmail', 'outlook',
  'live', 'icloud', 'me', 'aol', 't-online', 'freenet', 'mail', 'proton',
  'protonmail', 'mailbox',
];

const FREEMAIL_RE = new RegExp(
  `@(${FREEMAIL_DOMAINS.map((d) => d.replace(/[-]/g, '\\-')).join('|')})\\.[a-z.]+$`,
  'i',
);

/** true = die E-Mail gehoert zu einem Freemail-/Consumer-Provider (keine Firmen-E-Mail). */
export function isFreemailEmail(email: string): boolean {
  return FREEMAIL_RE.test(email.trim().toLowerCase());
}

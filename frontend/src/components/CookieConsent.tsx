'use client';

import { useEffect, useState } from 'react';

const STORAGE_KEY = 'vs_cookie_consent';
const CONSENT_VERSION = '1';

/**
 * Cookie-/Storage-Consent-Banner.
 *
 * VectiScan setzt ausschliesslich technisch notwendige Cookies bzw. Local Storage
 * (JWT-Authentifizierung) und ein cookieloses, anonymes First-Party-Analytics ohne
 * personenbezogene Daten ein. Beides ist nach TDDDG/DSGVO einwilligungsfrei.
 *
 * Es gibt daher derzeit keine zustimmungspflichtigen, nicht-essenziellen Cookies.
 * Das Banner dient der Transparenz (Informationspflicht) und merkt sich die
 * Kenntnisnahme des Nutzers, damit es nicht bei jedem Seitenaufruf erneut erscheint.
 */
export default function CookieConsent() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (!stored || stored !== CONSENT_VERSION) {
        setVisible(true);
      }
    } catch {
      // Local Storage nicht verfuegbar (z. B. Privatmodus) -> Banner anzeigen
      setVisible(true);
    }
  }, []);

  const acknowledge = () => {
    try {
      localStorage.setItem(STORAGE_KEY, CONSENT_VERSION);
    } catch {
      // ignorieren – Banner verschwindet zumindest fuer diese Session
    }
    setVisible(false);
  };

  if (!visible) return null;

  return (
    <div
      role="dialog"
      aria-label="Hinweis zu Cookies und Datenspeicherung"
      aria-live="polite"
      className="fixed bottom-0 inset-x-0 z-50 px-4 pb-4 sm:px-6 sm:pb-6"
    >
      <div
        className="max-w-3xl mx-auto rounded-xl p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-5 shadow-2xl"
        style={{ background: '#1E293B', border: '1px solid rgba(45,212,191,0.25)' }}
      >
        <p className="text-xs sm:text-sm leading-relaxed flex-1" style={{ color: '#CBD5E1' }}>
          🔒 VectiScan verwendet ausschließlich{' '}
          <strong style={{ color: '#F8FAFC' }}>technisch notwendige</strong> Cookies bzw. Local
          Storage (Anmeldung) sowie ein anonymes, cookieloses Analytics ohne personenbezogene Daten.
          Es werden keine Tracking- oder Werbe-Cookies gesetzt. Details in der{' '}
          <a
            href="/datenschutz"
            className="underline hover:no-underline"
            style={{ color: '#2DD4BF' }}
          >
            Datenschutzerklärung
          </a>
          .
        </p>
        <button
          type="button"
          onClick={acknowledge}
          className="shrink-0 rounded-lg px-5 py-2 text-sm font-semibold transition-colors"
          style={{ background: '#2DD4BF', color: '#0C1222' }}
        >
          Verstanden
        </button>
      </div>
    </div>
  );
}

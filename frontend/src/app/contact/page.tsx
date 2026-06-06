import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Support & Kontakt — VectiScan',
  description: 'Support-Kanal, Service-Level (SLA) und Eskalationspfad für VectiScan-Kunden.',
};

const C = {
  slateLight: '#1E293B',
  teal: '#2DD4BF',
  offWhite: '#F8FAFC',
  muted: '#94A3B8',
  mutedLight: '#CBD5E1',
  border: 'rgba(45,212,191,0.12)',
  borderSubtle: 'rgba(30,58,95,0.35)',
};

const SUPPORT_EMAIL = 'support@vectiscan.de';

// Vorausgefüllte mailto-Links (Standard-Anliegen + P1-Sicherheitsvorfall)
const MAILTO_STANDARD =
  `mailto:${SUPPORT_EMAIL}` +
  '?subject=VectiScan%20Support-Anfrage' +
  '&body=Guten%20Tag%2C%0A%0A' +
  'mein%20Anliegen%3A%20%0A%0A' +
  'Betroffenes%20Abo%2FScan%20(falls%20relevant)%3A%20%0A%0A' +
  'Mit%20freundlichen%20Gr%C3%BC%C3%9Fen';

const MAILTO_INCIDENT =
  `mailto:${SUPPORT_EMAIL}` +
  '?subject=%5BP1%5D%20Sicherheits-%2FDatenschutz-Vorfall%20-%20VectiScan' +
  '&body=DRINGEND%20-%20P1-Vorfall%0A%0A' +
  'Kurzbeschreibung%3A%20%0A%0A' +
  'Betroffene%20Systeme%2FDaten%3A%20%0A%0A' +
  'Zeitpunkt%20der%20Entdeckung%3A%20%0A%0A' +
  'Kontakt%20f%C3%BCr%20R%C3%BCckfragen%3A%20%0A';

export default function ContactPage() {
  return (
    <main className="flex-1 py-16 px-6">
      <div className="max-w-2xl mx-auto space-y-10">
        <header className="space-y-3">
          <h1 className="text-2xl font-semibold" style={{ color: C.offWhite }}>Support &amp; Kontakt</h1>
          <p className="text-sm leading-relaxed" style={{ color: C.muted }}>
            Fragen zu einem Scan, Report oder Ihrem Abo? Unser Team hilft Ihnen weiter.
            Schreiben Sie uns an die zentrale Support-Adresse — wir antworten innerhalb der
            unten genannten Reaktionszeiten.
          </p>
        </header>

        {/* Support-Kanal */}
        <section
          className="rounded-2xl p-6 sm:p-8 text-center"
          style={{ backgroundColor: C.slateLight, border: `1px solid ${C.border}` }}
        >
          <p className="text-xs uppercase tracking-wider mb-3 font-medium" style={{ color: C.teal }}>
            Support-Postfach
          </p>
          <a
            href={`mailto:${SUPPORT_EMAIL}`}
            className="text-xl font-semibold hover:underline"
            style={{ color: C.offWhite }}
          >
            {SUPPORT_EMAIL}
          </a>
          <p className="text-sm mt-3 mb-6 max-w-md mx-auto" style={{ color: C.muted }}>
            Mo–Fr, 09:00–17:00 Uhr (CET). Bitte nennen Sie nach Möglichkeit Ihre Abo- oder Scan-Nummer,
            damit wir Ihr Anliegen schneller zuordnen können.
          </p>
          <a
            href={MAILTO_STANDARD}
            className="inline-block px-7 py-3 rounded-lg text-sm font-semibold transition-all"
            style={{ backgroundColor: C.teal, color: '#0F172A' }}
          >
            Support-Anfrage schreiben
          </a>
        </section>

        {/* Light-SLA */}
        <section className="space-y-4">
          <h2 className="text-base font-semibold" style={{ color: C.offWhite }}>Reaktionszeiten (SLA)</h2>

          <div className="rounded-xl p-5" style={{ backgroundColor: C.slateLight, border: `1px solid ${C.borderSubtle}` }}>
            <h3 className="text-sm font-semibold mb-1" style={{ color: C.offWhite }}>Standard-Anfragen</h3>
            <p className="text-sm leading-relaxed" style={{ color: C.muted }}>
              Erstantwort innerhalb von <strong style={{ color: C.mutedLight }}>1 Werktag</strong>{' '}
              (Mo–Fr, 09:00–17:00 Uhr CET). Anfragen außerhalb der Geschäftszeiten werden am
              nächsten Werktag bearbeitet.
            </p>
          </div>

          <div className="rounded-xl p-5" style={{ backgroundColor: C.slateLight, border: `1px solid ${C.border}` }}>
            <h3 className="text-sm font-semibold mb-1" style={{ color: C.teal }}>
              Sicherheits- &amp; Datenschutz-Vorfall (P1)
            </h3>
            <p className="text-sm leading-relaxed mb-4" style={{ color: C.muted }}>
              Erstreaktion innerhalb von <strong style={{ color: C.mutedLight }}>4 Stunden</strong>{' '}
              (innerhalb der Geschäftszeiten). Der Vorfall wird unmittelbar an unser Security-Team
              und die Geschäftsführung eskaliert. Bitte markieren Sie die Betreffzeile mit{' '}
              <code style={{ color: C.mutedLight }}>[P1]</code>.
            </p>
            <a
              href={MAILTO_INCIDENT}
              className="inline-block px-5 py-2.5 rounded-lg text-sm font-medium transition-colors"
              style={{ color: C.teal, border: `1px solid ${C.teal}40` }}
            >
              P1-Vorfall melden
            </a>
          </div>
        </section>

        {/* Eskalations-/Incident-Pfad */}
        <section className="space-y-3">
          <h2 className="text-base font-semibold" style={{ color: C.offWhite }}>Eskalations- &amp; Incident-Pfad</h2>
          <ol className="space-y-2 text-sm leading-relaxed list-decimal pl-5" style={{ color: C.muted }}>
            <li>
              <strong style={{ color: C.mutedLight }}>Eingang:</strong> Alle Anfragen laufen über{' '}
              {SUPPORT_EMAIL} und werden werktäglich gesichtet.
            </li>
            <li>
              <strong style={{ color: C.mutedLight }}>Standard:</strong> Triage und Erstantwort
              innerhalb von 1 Werktag durch das Support-Team.
            </li>
            <li>
              <strong style={{ color: C.mutedLight }}>P1-Vorfall:</strong> Sofortige Benachrichtigung
              des Security-Verantwortlichen sowie der Geschäftsführung; Erstreaktion ≤ 4 Std.
              (Geschäftszeiten), laufende Status-Updates bis zur Eindämmung.
            </li>
            <li>
              <strong style={{ color: C.mutedLight }}>Datenschutz:</strong> Bei meldepflichtigen
              Vorfällen erfolgt die Bewertung der Meldefristen (Art. 33 DSGVO) gemeinsam mit der
              Geschäftsführung.
            </li>
          </ol>
        </section>

        <p className="text-xs" style={{ color: `${C.muted}99` }}>
          Rechtliche Angaben finden Sie im{' '}
          <a href="/impressum" className="hover:underline" style={{ color: C.teal }}>Impressum</a>{' '}
          und in der{' '}
          <a href="/datenschutz" className="hover:underline" style={{ color: C.teal }}>Datenschutzerklärung</a>.
        </p>
      </div>
    </main>
  );
}

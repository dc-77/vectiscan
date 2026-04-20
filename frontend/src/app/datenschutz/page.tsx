export default function DatenschutzPage() {
  const H2 = ({ children }: { children: string }) => (
    <h2 className="text-base font-semibold mt-8 mb-3" style={{ color: '#F8FAFC' }}>{children}</h2>
  );

  return (
    <main className="flex-1 py-16 px-6">
      <div className="max-w-2xl mx-auto space-y-4 text-sm leading-relaxed" style={{ color: '#94A3B8' }}>
        <h1 className="text-2xl font-semibold mb-6" style={{ color: '#F8FAFC' }}>Datenschutzerklärung</h1>

        <H2>1. Verantwortlicher</H2>
        <p>
          Vectigal GmbH, Heiliger Weg 60, 44135 Dortmund<br />
          E-Mail: <a href="mailto:kontakt@vectigal.gmbh" className="hover:underline" style={{ color: '#2DD4BF' }}>kontakt@vectigal.gmbh</a>
        </p>

        <H2>2. Erhebung und Verarbeitung personenbezogener Daten</H2>
        <p>
          Wir verarbeiten personenbezogene Daten nur, soweit diese zur Bereitstellung unserer
          Dienstleistung erforderlich sind. Die Verarbeitung erfolgt auf Grundlage von Art. 6 Abs. 1 lit. b DSGVO
          (Vertragserfüllung) und Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse).
        </p>

        <H2>3. Welche Daten wir verarbeiten</H2>
        <ul className="list-disc pl-5 space-y-1">
          <li><strong style={{ color: '#CBD5E1' }}>Account-Daten:</strong> E-Mail-Adresse, Passwort (gehasht), Rolle</li>
          <li><strong style={{ color: '#CBD5E1' }}>Scan-Daten:</strong> Zu scannende Domains/IPs, Scan-Ergebnisse, Reports</li>
          <li><strong style={{ color: '#CBD5E1' }}>Nutzungsdaten:</strong> Zeitpunkt des Zugriffs, IP-Adresse (in Audit-Logs)</li>
          <li><strong style={{ color: '#CBD5E1' }}>Zahlungsdaten:</strong> Werden ausschließlich von Stripe verarbeitet (siehe Abschnitt 6)</li>
        </ul>

        <H2>4. Hosting und Infrastruktur</H2>
        <p>
          Unsere Server befinden sich in Deutschland. Die Datenverarbeitung erfolgt ausschließlich
          innerhalb der Europäischen Union. Wir nutzen eigene Server (kein Cloud-Hosting bei Drittanbietern).
        </p>

        <H2>5. KI-gestützte Analyse (Anthropic)</H2>
        <p>
          Für die Analyse der Scan-Ergebnisse und die Erstellung der Reports nutzen wir die
          Claude API von Anthropic, PBC (San Francisco, USA). Dabei werden ausschließlich
          technische Scan-Daten (keine personenbezogenen Daten) an die API übermittelt.
          Die Verarbeitung erfolgt auf Grundlage von Art. 6 Abs. 1 lit. f DSGVO.
          Anthropic verarbeitet die Daten gemäß ihrer Datenschutzrichtlinie und speichert
          keine Eingabedaten für Trainingszwecke (API-Nutzungsbedingungen).
        </p>

        <H2>6. Zahlungsabwicklung (Stripe)</H2>
        <p>
          Die Zahlungsabwicklung erfolgt über Stripe, Inc. Ihre Zahlungsdaten werden
          ausschließlich von Stripe verarbeitet und nicht auf unseren Servern gespeichert.
          Stripe ist nach PCI DSS Level 1 zertifiziert.
        </p>

        <H2>7. E-Mail-Versand (Resend)</H2>
        <p>
          Für den Versand von E-Mails (Passwort-Reset, Report-Zustellung) nutzen wir den
          Dienst Resend. Dabei wird Ihre E-Mail-Adresse an Resend übermittelt.
        </p>

        <H2>8. Cookies</H2>
        <p>
          Wir verwenden ausschließlich technisch notwendige Cookies bzw. Local Storage
          für die Authentifizierung (JWT-Token). Es werden keine Tracking-Cookies oder
          Analyse-Tools eingesetzt.
        </p>

        <H2>9. Ihre Rechte</H2>
        <p>Sie haben das Recht auf:</p>
        <ul className="list-disc pl-5 space-y-1">
          <li>Auskunft über Ihre gespeicherten Daten (Art. 15 DSGVO)</li>
          <li>Berichtigung unrichtiger Daten (Art. 16 DSGVO)</li>
          <li>Löschung Ihrer Daten (Art. 17 DSGVO)</li>
          <li>Einschränkung der Verarbeitung (Art. 18 DSGVO)</li>
          <li>Datenübertragbarkeit (Art. 20 DSGVO)</li>
          <li>Widerspruch gegen die Verarbeitung (Art. 21 DSGVO)</li>
        </ul>
        <p>
          Zur Ausübung Ihrer Rechte wenden Sie sich an{' '}
          <a href="mailto:kontakt@vectigal.gmbh" className="hover:underline" style={{ color: '#2DD4BF' }}>kontakt@vectigal.gmbh</a>.
        </p>

        <H2>10. Aufsichtsbehörde</H2>
        <p>
          Sie haben das Recht, sich bei einer Aufsichtsbehörde zu beschweren.
          Zuständig ist die Landesbeauftragte für Datenschutz und Informationsfreiheit
          Nordrhein-Westfalen (LDI NRW).
        </p>

        <p className="mt-8 text-xs" style={{ color: '#64748B' }}>Stand: April 2026</p>
      </div>
    </main>
  );
}

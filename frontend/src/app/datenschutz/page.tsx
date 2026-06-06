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
          E-Mail: <a href="mailto:support@vectigal.tech" className="hover:underline" style={{ color: '#2DD4BF' }}>support@vectigal.tech</a>
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
          <li><strong style={{ color: '#CBD5E1' }}>Kontakt-/Lead-Daten:</strong> Name, E-Mail-Adresse, Unternehmen, Telefon, Domain, Nachricht sowie Ihre Einwilligung — erhoben über das Demo-/Kontaktformular (siehe Abschnitt 8)</li>
        </ul>

        <H2>4. Hosting und Infrastruktur</H2>
        <p>
          Unsere Server befinden sich in Deutschland; das Hosting der Plattform erfolgt auf eigenen
          Servern innerhalb der Europäischen Union (kein Cloud-Hosting bei Drittanbietern). Eine
          Übermittlung an einzelne, ausdrücklich benannte Auftragsverarbeiter außerhalb der EU
          erfolgt ausschließlich im Rahmen der in den Abschnitten 5 bis 7 beschriebenen Dienste und
          auf Grundlage geeigneter Garantien nach Art. 44 ff. DSGVO.
        </p>

        <H2>5. KI-gestützte Analyse (Anthropic)</H2>
        <p>
          Für die Analyse der Scan-Ergebnisse und die Erstellung der Reports nutzen wir die
          Claude API von Anthropic, PBC (San Francisco, USA). Dabei werden technische
          Scan-Daten übermittelt, die im Einzelfall personenbezogene Daten enthalten können
          (z. B. in Scan-Zielen oder Scan-Ergebnissen enthaltene Hostnamen sowie Kontakt-
          oder WHOIS-Daten). Die Verarbeitung erfolgt auf Grundlage von Art. 6 Abs. 1 lit. f DSGVO.
          Anthropic verarbeitet die Daten gemäß ihrer Datenschutzrichtlinie und speichert
          keine über die API übermittelten Eingabedaten zu Trainingszwecken (API-Nutzungsbedingungen).
        </p>
        <p>
          Da Anthropic, PBC seinen Sitz in den USA (Drittland) hat, erfolgt die Übermittlung auf
          Grundlage der von der EU-Kommission erlassenen Standardvertragsklauseln nach
          Art. 46 Abs. 2 lit. c DSGVO.
        </p>

        <H2>6. Zahlungsabwicklung (Stripe)</H2>
        <p>
          Die Zahlungsabwicklung erfolgt über Stripe, Inc. (USA). Ihre Zahlungsdaten werden
          ausschließlich von Stripe verarbeitet und nicht auf unseren Servern gespeichert.
          Stripe ist nach PCI DSS Level 1 zertifiziert. Da Stripe, Inc. seinen Sitz in den USA
          (Drittland) hat, erfolgt eine etwaige Übermittlung auf Grundlage der von der
          EU-Kommission erlassenen Standardvertragsklauseln nach Art. 46 Abs. 2 lit. c DSGVO.
        </p>

        <H2>7. E-Mail-Versand (Resend)</H2>
        <p>
          Für den Versand von E-Mails (Passwort-Reset, Report-Zustellung) sowie für das
          Routing eingehender Demo-/Kontaktanfragen an unseren Vertrieb (siehe Abschnitt 8)
          nutzen wir den Dienst Resend (Resend, Inc., USA). Dabei werden die für den jeweiligen
          Versand erforderlichen Daten (z. B. Ihre E-Mail-Adresse, bei Demo-Anfragen die im
          Formular angegebenen Kontaktdaten) an Resend übermittelt. Da der Anbieter seinen Sitz
          in den USA (Drittland) hat, erfolgt die Übermittlung auf Grundlage der von der
          EU-Kommission erlassenen Standardvertragsklauseln nach Art. 46 Abs. 2 lit. c DSGVO.
        </p>

        <H2>8. Bearbeitung von Demo- und Kontaktanfragen</H2>
        <p>
          Wenn Sie über unser Demo-/Kontaktformular eine Anfrage stellen, verarbeiten wir die
          von Ihnen angegebenen Daten (Name, E-Mail-Adresse, Unternehmen, Telefon, Domain,
          Nachricht) ausschließlich zum Zweck der Bearbeitung Ihrer Anfrage, der Kontaktaufnahme
          und der Unterbreitung eines Angebots. Rechtsgrundlage ist Ihre ausdrückliche
          Einwilligung nach Art. 6 Abs. 1 lit. a DSGVO, die Sie mit Absenden des Formulars
          erteilen und jederzeit mit Wirkung für die Zukunft widerrufen können (formlos an
          die in Abschnitt 1 genannte Adresse).
        </p>
        <p>
          Zur internen Weiterleitung an unseren Vertrieb wird die Anfrage per E-Mail über
          unseren Auftragsverarbeiter Resend (Resend, Inc., USA) zugestellt; dabei werden die
          oben genannten Kontaktdaten an Resend übermittelt. Da Resend seinen Sitz in den USA
          (Drittland) hat, erfolgt diese Übermittlung auf Grundlage der von der EU-Kommission
          erlassenen Standardvertragsklauseln nach Art. 46 Abs. 2 lit. c DSGVO (vgl. Abschnitt 7).
          Die Speicherung der Anfrage selbst erfolgt auf unseren Servern in Deutschland
          (siehe Abschnitt 4).
        </p>
        <p>
          <strong style={{ color: '#CBD5E1' }}>Kein Weiterverkauf:</strong> Wir geben Ihre
          Kontakt-/Lead-Daten nicht zu Werbe- oder Verkaufszwecken an Dritte weiter und
          verkaufen sie nicht. Eine Übermittlung erfolgt ausschließlich an die in dieser
          Erklärung benannten Auftragsverarbeiter zu den jeweils genannten Zwecken.
        </p>

        <H2>9. Cookies, Local Storage und Reichweitenmessung</H2>
        <p>
          Wir verwenden ausschließlich technisch notwendige Cookies bzw. Local Storage
          für die Authentifizierung (JWT-Token). Es werden keine Tracking- oder Werbe-Cookies
          und keine Dienste von Drittanbietern zur Analyse eingesetzt.
        </p>
        <p>
          Für eine Reichweitenmessung setzen wir ausschließlich eine eigene, cookielose
          First-Party-Lösung ein. Sofern diese aktiviert ist, werden dabei ausschließlich
          anonyme, aggregierte Daten erhoben (aufgerufene Seite, Referrer-Domain,
          UTM-Parameter). Es werden <strong style={{ color: '#CBD5E1' }}>keine
          IP-Adressen, kein User-Agent und keine persistenten Besucher-Identifier</strong>{' '}
          gespeichert. Eine Wiedererkennung einzelner Personen ist damit ausgeschlossen.
          Die Verarbeitung erfolgt auf Grundlage von Art. 6 Abs. 1 lit. f DSGVO; da keine
          personenbezogenen Daten gespeichert und keine Informationen auf Ihrem Endgerät
          ausgelesen werden, ist sie nach § 25 Abs. 2 TDDDG (vormals TTDSG) einwilligungsfrei.
        </p>
        <p>
          Da wir keine zustimmungspflichtigen Cookies einsetzen, dient unser Cookie-Hinweis
          ausschließlich der Transparenz und Information.
        </p>

        <H2>10. Speicherdauer und Löschung</H2>
        <p>
          Wir speichern personenbezogene Daten nur so lange, wie es für die genannten Zwecke
          erforderlich ist oder gesetzliche Aufbewahrungsfristen es vorschreiben. Im Einzelnen:
        </p>
        <ul className="list-disc pl-5 space-y-1">
          <li><strong style={{ color: '#CBD5E1' }}>Account-Daten:</strong> bis zur Löschung des Kontos, spätestens 30 Tage nach Vertragsende</li>
          <li><strong style={{ color: '#CBD5E1' }}>Scan-Daten und Reports:</strong> 12 Monate nach Abschluss des jeweiligen Scans, danach Löschung</li>
          <li><strong style={{ color: '#CBD5E1' }}>Audit-Logs (inkl. IP-Adresse):</strong> 90 Tage</li>
          <li><strong style={{ color: '#CBD5E1' }}>Kontakt-/Lead-Daten:</strong> bis zur abschließenden Bearbeitung Ihrer Anfrage; kommt kein Vertrag zustande, spätestens 12 Monate nach dem letzten Kontakt, sofern keine gesetzlichen Aufbewahrungsfristen entgegenstehen oder Sie zuvor widerrufen</li>
          <li><strong style={{ color: '#CBD5E1' }}>Rechnungs- und Zahlungsbelege:</strong> 10 Jahre (§ 147 AO, § 257 HGB)</li>
        </ul>

        <H2>11. Ihre Rechte</H2>
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
          <a href="mailto:support@vectigal.tech" className="hover:underline" style={{ color: '#2DD4BF' }}>support@vectigal.tech</a>.
        </p>

        <H2>12. Aufsichtsbehörde</H2>
        <p>
          Sie haben das Recht, sich bei einer Aufsichtsbehörde zu beschweren.
          Zuständig ist die Landesbeauftragte für Datenschutz und Informationsfreiheit
          Nordrhein-Westfalen (LDI NRW).
        </p>

        <p className="mt-8 text-xs" style={{ color: '#64748B' }}>Stand: Juni 2026</p>
      </div>
    </main>
  );
}

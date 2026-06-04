export default function AGBPage() {
  const H2 = ({ children }: { children: string }) => (
    <h2 className="text-base font-semibold mt-8 mb-3" style={{ color: '#F8FAFC' }}>{children}</h2>
  );

  return (
    <main className="flex-1 py-16 px-6">
      <div className="max-w-2xl mx-auto space-y-4 text-sm leading-relaxed" style={{ color: '#94A3B8' }}>
        <h1 className="text-2xl font-semibold mb-6" style={{ color: '#F8FAFC' }}>
          Allgemeine Geschäftsbedingungen (AGB)
        </h1>
        <p>Allgemeine Geschäftsbedingungen der Vectigal GmbH</p>

        <H2>§ 1 Geltungsbereich</H2>
        <p>
          (1) Diese AGB gelten für alle Verträge über die Nutzung der Software-as-a-Service-Leistung
          „VectiScan" (nachfolgend „Dienst") zwischen der Vectigal GmbH (nachfolgend „Anbieter") und
          ihren Kunden.
        </p>
        <p>
          (2) Der Dienst richtet sich ausschließlich an Unternehmer i. S. d. § 14 BGB, juristische
          Personen des öffentlichen Rechts und öffentlich-rechtliche Sondervermögen. Ein Vertrag mit
          Verbrauchern (§ 13 BGB) kommt nicht zustande.
        </p>
        <p>
          (3) Abweichenden Bedingungen des Kunden wird widersprochen, soweit nicht ausdrücklich
          schriftlich zugestimmt.
        </p>

        <H2>§ 2 Vertragsgegenstand / Leistungsbeschreibung</H2>
        <p>
          (1) Der Anbieter stellt dem Kunden VectiScan als webbasierten Dienst zur Durchführung von
          Compliance-/Security-Audits über das Internet zur Verfügung.
        </p>
        <p>
          (2) Der konkrete Leistungsumfang ergibt sich aus der jeweils gebuchten Paket-/
          Leistungsbeschreibung bzw. dem individuellen Angebot.
        </p>
        <p>
          (3) Der Dienst stellt ein technisches Hilfsmittel dar und ersetzt keine Rechts-,
          Zertifizierungs- oder Auditberatung. Eine bestimmte Zertifizierungs- oder
          Audit-Erfolgsgarantie wird nicht geschuldet, soweit nicht ausdrücklich vereinbart.
        </p>

        <H2>§ 3 Vertragsschluss</H2>
        <p>
          Der Vertrag kommt durch Annahme des Angebots des Anbieters bzw. durch Freischaltung des
          Zugangs zustande. Bei Online-Bestellung kommt der Vertrag mit Bestätigung durch den
          Anbieter zustande.
        </p>

        <H2>§ 4 Pflichten des Kunden / Zugangsdaten</H2>
        <p>(1) Der Kunde hält Zugangsdaten geheim und schützt sie vor Zugriff Dritter.</p>
        <p>
          (2) Der Kunde stellt sicher, dass er zur Verarbeitung der von ihm eingestellten Daten
          berechtigt ist und keine Rechte Dritter verletzt.
        </p>
        <p>
          (3) Sofern personenbezogene Daten im Auftrag verarbeitet werden, schließen die Parteien
          einen Auftragsverarbeitungsvertrag (Art. 28 DSGVO).
        </p>

        <H2>§ 5 Verfügbarkeit</H2>
        <p>
          Der Anbieter bemüht sich um eine hohe Verfügbarkeit. Wartungsfenster und Störungen
          außerhalb des Einflussbereichs des Anbieters sind hiervon ausgenommen. Eine konkrete
          Verfügbarkeit (SLA) gilt nur, soweit ausdrücklich vereinbart.
        </p>

        <H2>§ 6 Vergütung und Zahlung</H2>
        <p>
          (1) Es gelten die im Angebot/in der Paketbeschreibung genannten Preise zzgl. gesetzlicher
          Umsatzsteuer.
        </p>
        <p>
          (2) Rechnungen sind innerhalb von 14 Tagen ab Rechnungsdatum ohne Abzug zur Zahlung fällig,
          soweit im Angebot nichts Abweichendes vereinbart ist.
        </p>
        <p>(3) Bei Zahlungsverzug gelten die gesetzlichen Regelungen.</p>

        <H2>§ 7 Laufzeit und Kündigung</H2>
        <p>
          Laufzeit und Kündigungsfristen ergeben sich aus dem jeweiligen Angebot/Paket. Das Recht zur
          außerordentlichen Kündigung aus wichtigem Grund bleibt unberührt.
        </p>

        <H2>§ 8 Nutzungsrechte</H2>
        <p>
          Der Kunde erhält für die Vertragslaufzeit ein einfaches, nicht übertragbares Recht zur
          Nutzung des Dienstes im vereinbarten Umfang. An vom Kunden eingestellten Daten verbleiben
          die Rechte beim Kunden.
        </p>

        <H2>§ 9 Haftung</H2>
        <p>
          (1) Der Anbieter haftet unbeschränkt bei Vorsatz und grober Fahrlässigkeit sowie bei
          Verletzung von Leben, Körper oder Gesundheit.
        </p>
        <p>
          (2) Bei einfacher Fahrlässigkeit haftet der Anbieter nur bei Verletzung einer wesentlichen
          Vertragspflicht (Kardinalpflicht), begrenzt auf den vertragstypischen, vorhersehbaren
          Schaden.
        </p>
        <p>
          (3) Im Übrigen ist die Haftung ausgeschlossen. Die Haftung nach dem Produkthaftungsgesetz
          bleibt unberührt.
        </p>

        <H2>§ 10 Datenschutz</H2>
        <p>
          Es gilt die <a href="/datenschutz" className="hover:underline" style={{ color: '#2DD4BF' }}>Datenschutzerklärung</a> des
          Anbieters. Für die Auftragsverarbeitung gilt ein gesonderter AV-Vertrag (Art. 28 DSGVO).
        </p>

        <H2>§ 11 Schlussbestimmungen</H2>
        <p>(1) Es gilt das Recht der Bundesrepublik Deutschland unter Ausschluss des UN-Kaufrechts.</p>
        <p>(2) Gerichtsstand ist, soweit zulässig, der Sitz des Anbieters (Dortmund).</p>
        <p>
          (3) Sollten einzelne Bestimmungen unwirksam sein, bleibt der Vertrag im Übrigen wirksam.
        </p>

        <p className="mt-8 text-xs" style={{ color: '#64748B' }}>Stand: Juni 2026</p>
      </div>
    </main>
  );
}

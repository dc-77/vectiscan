export default function ImpressumPage() {
  return (
    <main className="flex-1 py-16 px-6">
      <div className="max-w-2xl mx-auto space-y-8">
        <h1 className="text-2xl font-semibold" style={{ color: '#F8FAFC' }}>Impressum</h1>

        <section className="space-y-2 text-sm leading-relaxed" style={{ color: '#94A3B8' }}>
          <h2 className="text-base font-semibold" style={{ color: '#F8FAFC' }}>Angaben gemäß § 5 TMG</h2>
          <p>
            Vectigal GmbH<br />
            Heiliger Weg 60<br />
            44135 Dortmund
          </p>
          <p>
            <strong style={{ color: '#CBD5E1' }}>Geschäftsführer:</strong> Daniel Czischke
          </p>
          <p>
            <strong style={{ color: '#CBD5E1' }}>Registergericht:</strong> Amtsgericht Dortmund<br />
            <strong style={{ color: '#CBD5E1' }}>Registernummer:</strong> HRB 35553
          </p>
          <p>
            <strong style={{ color: '#CBD5E1' }}>USt-IdNr.:</strong> DE366aborea (beantragt)
          </p>
        </section>

        <section className="space-y-2 text-sm leading-relaxed" style={{ color: '#94A3B8' }}>
          <h2 className="text-base font-semibold" style={{ color: '#F8FAFC' }}>Kontakt</h2>
          <p>
            E-Mail: <a href="mailto:kontakt@vectigal.gmbh" className="hover:underline" style={{ color: '#2DD4BF' }}>kontakt@vectigal.gmbh</a><br />
            Telefon: +49 231 586 939 30
          </p>
        </section>

        <section className="space-y-2 text-sm leading-relaxed" style={{ color: '#94A3B8' }}>
          <h2 className="text-base font-semibold" style={{ color: '#F8FAFC' }}>Verantwortlich für den Inhalt nach § 18 Abs. 2 MStV</h2>
          <p>
            Daniel Czischke<br />
            Heiliger Weg 60<br />
            44135 Dortmund
          </p>
        </section>

        <section className="space-y-2 text-sm leading-relaxed" style={{ color: '#94A3B8' }}>
          <h2 className="text-base font-semibold" style={{ color: '#F8FAFC' }}>Streitschlichtung</h2>
          <p>
            Die Europäische Kommission stellt eine Plattform zur Online-Streitbeilegung (OS) bereit.
            Wir sind nicht bereit oder verpflichtet, an Streitbeilegungsverfahren vor einer
            Verbraucherschlichtungsstelle teilzunehmen.
          </p>
        </section>
      </div>
    </main>
  );
}

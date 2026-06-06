import type { Metadata } from 'next';
import DemoRequestForm from '@/components/DemoRequestForm';

export const metadata: Metadata = {
  title: 'Demo anfragen — VectiScan',
  description:
    'Fordern Sie eine persönliche VectiScan-Demo an. Automatisierte Security-Scans und Compliance-Nachweise (NIS2, ISO 27001, BSI) für Ihre IT-Infrastruktur. DSGVO-konform, Hosting in Deutschland.',
};

const C = {
  teal: '#2DD4BF',
  offWhite: '#F8FAFC',
  muted: '#94A3B8',
  mutedLight: '#CBD5E1',
};

const BENEFITS = [
  {
    title: 'Audit-Nachweise auf Knopfdruck',
    body: 'Professionelle PDF-Reports als Beleg für NIS2-, ISO-27001- und BSI-Anforderungen — ohne manuelles Pentest-Reporting.',
  },
  {
    title: 'Risiken sehen, bevor es ein Angreifer tut',
    body: 'Regelmäßige, automatisierte Perimeter- und Web-Scans Ihrer extern erreichbaren Systeme — priorisiert nach Geschäftsrisiko.',
  },
  {
    title: 'Vertrauen zeigen',
    body: 'Belastbare Sicherheitsnachweise für Kunden, Versicherer und Auditoren. Made & hosted in Germany, DSGVO-konform.',
  },
];

export default function DemoPage() {
  return (
    <main className="flex-1 py-16 px-6">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-10">
          <h1 className="text-3xl sm:text-4xl font-semibold mb-4" style={{ color: C.offWhite }}>
            Ihre persönliche VectiScan-Demo
          </h1>
          <p className="text-base max-w-2xl mx-auto" style={{ color: C.mutedLight }}>
            Sehen Sie in einem kurzen Gespräch, wie VectiScan Ihre extern erreichbare
            IT automatisiert prüft und Compliance-Nachweise erzeugt. Unverbindlich und
            auf Ihren konkreten Compliance-Anlass zugeschnitten.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-10 items-start">
          <div className="space-y-6">
            {BENEFITS.map((b) => (
              <div key={b.title} className="flex gap-3">
                <span className="mt-1 shrink-0" style={{ color: C.teal }}>
                  ▹
                </span>
                <div>
                  <h3 className="text-sm font-semibold mb-1" style={{ color: C.offWhite }}>
                    {b.title}
                  </h3>
                  <p className="text-sm leading-relaxed" style={{ color: C.muted }}>
                    {b.body}
                  </p>
                </div>
              </div>
            ))}
            <div className="text-xs leading-relaxed pt-2" style={{ color: C.muted }}>
              Lieber direkt schreiben?{' '}
              <a href="mailto:support@vectigal.tech" className="underline" style={{ color: C.teal }}>
                support@vectigal.tech
              </a>
            </div>
          </div>

          <DemoRequestForm />
        </div>
      </div>
    </main>
  );
}

import type { Metadata } from 'next';
import WebCheckFreeForm from '@/components/WebCheckFreeForm';
import { LpView, PricingLink } from '@/components/WebCheckInteractions';

/*
 * WebCheck-Landingpage — Kampagne „NIS2-WebCheck" (VEC-90).
 * Copy & Conversion-Spec: Greta (CMO), Brief in VEC-90 / Quelle GTM §2.3/§4.3.
 *
 * PUBLISH-GATE (verbindlich, §2.4): Security-/Compliance-Zeilen sind §2.4-gegen-
 * gecheckt — Sven-Wording-Sign-off §B erteilt am 2026-06-03 (VEC-92, publish-copy v2.1).
 * Diese Seite trägt jetzt die claim-korrigierte v2.1-§B-Copy. Weiterhin GATED (nicht in
 * der Copy): „DSGVO-konform" → VEC-35; Isolation/Mandantentrennung → VEC-14.
 * Page-Go-live (index) bleibt gekoppelt an Tracking/Lead-Routing (VEC-117) + VEC-14 (P0):
 * daher robots noindex/nofollow + nicht in der Navigation verlinkt, bis scharfgeschaltet.
 */

const C = {
  slate: '#0F172A', slateLight: '#1E293B', teal: '#2DD4BF', tealDark: '#14B8A6',
  offWhite: '#F8FAFC', muted: '#94A3B8', mutedLight: '#CBD5E1',
};

export const metadata: Metadata = {
  title: 'Kostenloser NIS2-WebCheck — Compliance-Report für externe Systeme | VectiScan',
  description:
    'Automatisierter Security- & Compliance-Scan Ihrer von außen erreichbaren Systeme. Versionierter, audit-tauglicher Report mit Mapping zu NIS2, ISO 27001, BSI-Grundschutz und DSGVO. E-Mail + Domain genügen.',
  robots: { index: false, follow: false }, // Publish-Gate: erst nach Sven-Sign-off (VEC-92) auf index.
};

/* ── Icons (claim-disziplinierte Proof-Leiste) ──────────────── */
const I = {
  map: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M9 20 3 17V4l6 3 6-3 6 3v13l-6-3-6 3z" /><path d="M9 7v13M15 4v13" /></svg>,
  layers: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M12 2 2 7l10 5 10-5-10-5z" /><path d="m2 12 10 5 10-5M2 17l10 5 10-5" /></svg>,
  flag: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M4 22V4M4 4h13l-2 4 2 4H4" /></svg>,
  compass: <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><circle cx="12" cy="12" r="10" /><path d="m16 8-6 2-2 6 6-2 2-6z" /></svg>,
  mail: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><rect x="2" y="4" width="20" height="16" rx="2" /><path d="m22 7-10 6L2 7" /></svg>,
  scan: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" /><path d="M7 12h10" /></svg>,
  report: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6M8 13h8M8 17h5" /></svg>,
};

/* Proof-Leiste — claim-korrigierte Copy v2.1 §B (VEC-92). Sven-Wording-Sign-off 2026-06-03.
 * Quelle: publish-copy-Dokument auf VEC-92. Nur live-fähige Kacheln; „DSGVO-konform"
 * bleibt gated an VEC-35, Isolation/Mandantentrennung gesperrt bis VEC-14. */
const PROOF = [
  { icon: I.map, title: 'Report mit Compliance-Mapping', text: 'NIS2 · ISO 27001 · BSI-Grundschutz · DSGVO — direkt im Report.', note: 'Mapping/Orientierung pro Befund — kein zertifizierter Konformitätsnachweis.' },
  { icon: I.layers, title: 'Mehrstufiger Security-Scan', text: 'Versionierter, reproduzierbarer Report mit regelbasierter, deterministischer Risikobewertung — audit-tauglich.' },
  { icon: I.compass, title: 'An den BSI-C5-Kriterien orientiert', text: 'C5-orientierte Entwicklung.' }, // (S) VEC-92/VEC-99 — NIE „C5-zertifiziert", NIE „auf dem Weg zu" (kein Roadmap-Beleg)
  { icon: I.flag, title: 'Serverstandort Deutschland', text: 'Eigene Server in Deutschland, kein Public-Cloud-Hosting.' }, // (S) Sven-Re-Check 2026-06-03, Beleg VEC-99. Region-only — KEINE „keine US-Datenübermittlung"-Aussage (US-Subprozessoren offengelegt, VEC-124)
];

const STEPS = [
  { n: 1, icon: I.mail, title: 'E-Mail + Domain eingeben', text: 'Geschäfts-E-Mail und die zu prüfende Domain — mehr braucht der Start nicht.' },
  { n: 2, icon: I.scan, title: 'Verifizierter Scan läuft', text: 'Unser mehrstufiger Security-Scan analysiert Ihre extern erreichbaren Systeme.' },
  { n: 3, icon: I.report, title: 'Sample-Report per Mail', text: 'Sie erhalten einen versionierten Report mit Compliance-Mapping und priorisierten Maßnahmen.' },
];

export default function WebCheckLandingPage() {
  return (
    <main className="flex-1 relative">
      <LpView />

      {/* ── Dezente Hintergrund-Gradients ── */}
      <div className="fixed inset-0 pointer-events-none z-0" aria-hidden="true">
        <div className="absolute -top-32 -right-32 w-[600px] h-[600px] rounded-full" style={{ background: `radial-gradient(circle, ${C.teal}06 0%, transparent 60%)`, filter: 'blur(80px)' }} />
        <div className="absolute -bottom-48 -left-48 w-[500px] h-[500px] rounded-full" style={{ background: `radial-gradient(circle, ${C.teal}04 0%, transparent 60%)`, filter: 'blur(100px)' }} />
      </div>

      {/* ── HERO ── H1 + Sub + Proof-Leiste direkt darunter + Free-Start-Formular (above the fold) ── */}
      <section className="relative z-10 max-w-6xl mx-auto px-6 pt-12 sm:pt-16 md:pt-20 pb-10">
        <div className="grid grid-cols-1 lg:grid-cols-[1.1fr_0.9fr] gap-10 lg:gap-12 items-start">
          {/* Copy-Spalte */}
          <div>
            <p className="text-xs sm:text-sm uppercase tracking-[0.25em] mb-4 font-medium" style={{ color: C.teal }}>
              NIS2-WebCheck · kostenlos
            </p>
            <h1 className="text-[1.9rem] sm:text-4xl md:text-[2.9rem] font-bold leading-[1.12] tracking-tight mb-5" style={{ color: C.offWhite }}>
              Prüffähiger Compliance-Report für Ihre extern erreichbaren Systeme —{' '}
              <span style={{ color: C.teal }}>in Tagen, nicht Monaten.</span>
            </h1>
            <p className="text-[15px] sm:text-base leading-relaxed max-w-xl mb-7" style={{ color: C.mutedLight }}>
              Automatisierter Security- &amp; Compliance-Scan Ihrer von außen erreichbaren Systeme.
              Versionierter, audit-tauglicher Report mit Mapping zu NIS2, ISO 27001, BSI-Grundschutz und DSGVO —
              ohne 5-stellige Beratung, ohne Wochen Wartezeit, ohne eigenes Security-Team.
            </p>

            {/* Proof-Leiste direkt unter H1 (3–4 Kacheln) */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {PROOF.map(p => (
                <div key={p.title} className="flex items-start gap-3 p-3.5 rounded-xl h-full" style={{ backgroundColor: C.slateLight, border: '1px solid rgba(45,212,191,0.06)' }}>
                  <span className="mt-0.5 shrink-0" style={{ color: C.teal }}>{p.icon}</span>
                  <div>
                    <p className="text-[13px] font-semibold mb-0.5" style={{ color: C.offWhite }}>{p.title}</p>
                    <p className="text-[11.5px] leading-relaxed" style={{ color: C.muted }}>{p.text}</p>
                    {p.note && <p className="text-[10.5px] leading-snug mt-1 italic" style={{ color: `${C.muted}cc` }}>{p.note}</p>}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Conversion-Spalte: EINE Primär-CTA = Free-Start-Formular */}
          <div className="lg:sticky lg:top-24">
            <div className="mb-3 text-center lg:text-left">
              <p className="text-sm font-semibold" style={{ color: C.offWhite }}>Kostenlosen WebCheck starten</p>
              <p className="text-xs" style={{ color: C.muted }}>Ohne Account, ohne Installation — E-Mail + Domain genügen.</p>
            </div>
            <WebCheckFreeForm />
          </div>
        </div>
      </section>

      {/* ── TRUST-SIGNALE ── */}
      <section className="relative z-10 border-t border-b py-5" style={{ borderColor: 'rgba(45,212,191,0.08)' }}>
        <div className="max-w-5xl mx-auto px-6 flex flex-wrap items-center justify-center gap-x-6 gap-y-3 text-xs" style={{ color: C.muted }}>
          <span className="font-medium" style={{ color: C.mutedLight }}>Standards-Mapping: NIS2 · ISO 27001 · BSI-Grundschutz · DSGVO</span>
          <span aria-hidden="true" style={{ color: `${C.muted}55` }}>·</span>
          <span>Serverstandort Deutschland</span>
          <span aria-hidden="true" style={{ color: `${C.muted}55` }}>·</span>
          <a href="mailto:support@vectigal.tech" className="hover:text-white transition-colors" style={{ color: C.muted }}>support@vectigal.tech</a>
          <span aria-hidden="true" style={{ color: `${C.muted}55` }}>·</span>
          <a href="/impressum" className="hover:text-white transition-colors" style={{ color: C.muted }}>Impressum</a>
          <span aria-hidden="true" style={{ color: `${C.muted}55` }}>·</span>
          <a href="/datenschutz" className="hover:text-white transition-colors" style={{ color: C.muted }}>Datenschutz</a>
          <span aria-hidden="true" style={{ color: `${C.muted}55` }}>·</span>
          <PricingLink className="hover:text-white transition-colors font-medium" style={{ color: C.teal }}>Pakete &amp; Preise</PricingLink>
        </div>
      </section>

      {/* ── WIE ES FUNKTIONIERT (3 Schritte) ── */}
      <section className="relative z-10 py-14 md:py-20">
        <div className="max-w-5xl mx-auto px-6">
          <h2 className="text-[1.4rem] sm:text-2xl md:text-3xl font-semibold text-center mb-12" style={{ color: C.offWhite }}>So funktioniert&apos;s</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {STEPS.map(s => (
              <div key={s.n} className="p-6 rounded-2xl h-full text-center md:text-left" style={{ backgroundColor: C.slateLight, border: '1px solid rgba(45,212,191,0.06)' }}>
                <div className="flex items-center justify-center md:justify-start gap-3 mb-3">
                  <span className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold" style={{ backgroundColor: `${C.teal}20`, color: C.teal }}>{s.n}</span>
                  <span style={{ color: C.teal }}>{s.icon}</span>
                </div>
                <h3 className="text-base font-semibold mb-1.5" style={{ color: C.offWhite }}>{s.title}</h3>
                <p className="text-sm leading-relaxed" style={{ color: C.muted }}>{s.text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── SEKUNDÄR-CTA → /pricing ── */}
      <section className="relative z-10 py-12 md:py-16">
        <div className="max-w-2xl mx-auto px-6 text-center">
          <h2 className="text-[1.3rem] sm:text-2xl font-semibold mb-3" style={{ color: C.offWhite }}>Transparente Pakete — kein „Preis auf Anfrage".</h2>
          <p className="text-sm mb-7" style={{ color: C.muted }}>Vom kostenlosen WebCheck bis zum vollständigen Compliance-Report. Alle Stufen offen einsehbar.</p>
          <PricingLink
            className="inline-block px-8 py-3.5 rounded-lg text-sm font-medium transition-all duration-300 hover:border-[#2DD4BF60]"
            style={{ color: C.offWhite, border: '1px solid rgba(45,212,191,0.25)' }}>
            Alle Pakete &amp; Preise ansehen →
          </PricingLink>
        </div>
      </section>
    </main>
  );
}

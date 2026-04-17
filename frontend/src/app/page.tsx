'use client';

import { useState, useEffect, useRef, useCallback, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { VectiScanShield } from '@/components/VectiScanLogo';

/* ── Brand Colors ────────────────────────────────────────── */
const C = {
  slate: '#0F172A',
  slateLight: '#1E293B',
  teal: '#2DD4BF',
  tealDark: '#14B8A6',
  offWhite: '#F8FAFC',
  muted: '#94A3B8',
  mutedLight: '#CBD5E1',
};

/* ── Scroll-Reveal Hook ──────────────────────────────────── */
function useReveal(threshold = 0.1) {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      ([e]) => { if (e.isIntersecting) { setVisible(true); obs.disconnect(); } },
      { threshold },
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [threshold]);
  return { ref, visible };
}

function Reveal({ children, delay = 0 }: { children: React.ReactNode; delay?: number }) {
  const { ref, visible } = useReveal();
  return (
    <div ref={ref} className="transition-all duration-700 ease-out"
      style={{ opacity: visible ? 1 : 0, transform: visible ? 'translateY(0)' : 'translateY(20px)', transitionDelay: `${delay}ms` }}>
      {children}
    </div>
  );
}

/* ── Redirect wrapper ────────────────────────────────────── */
function OrderIdRedirect() {
  const router = useRouter();
  const searchParams = useSearchParams();
  useEffect(() => {
    const orderId = searchParams.get('orderId');
    if (orderId) router.replace(`/scan?orderId=${orderId}`);
  }, [searchParams, router]);
  return null;
}

/* ── Interactive Hero Shield ─────────────────────────────── */
function HeroShield() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [tilt, setTilt] = useState({ x: 0, y: 0 });
  const rafRef = useRef<number | null>(null);

  const handleMouseMove = useCallback((e: MouseEvent) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    rafRef.current = requestAnimationFrame(() => {
      setTilt({ x: x * 24, y: -y * 24 });
    });
  }, []);

  const handleMouseLeave = useCallback(() => {
    setTilt({ x: 0, y: 0 });
  }, []);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    el.addEventListener('mousemove', handleMouseMove);
    el.addEventListener('mouseleave', handleMouseLeave);
    return () => {
      el.removeEventListener('mousemove', handleMouseMove);
      el.removeEventListener('mouseleave', handleMouseLeave);
    };
  }, [handleMouseMove, handleMouseLeave]);

  return (
    <div ref={containerRef} className="relative flex items-center justify-center" style={{ height: 420 }}>
      {/* Glow behind shield */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <div className="w-64 h-64 rounded-full transition-all duration-500"
          style={{
            background: `radial-gradient(circle, ${C.teal}12 0%, transparent 70%)`,
            transform: `translate(${tilt.x * 0.5}px, ${-tilt.y * 0.5}px)`,
          }} />
      </div>
      {/* Shield with 3D tilt */}
      <div className="transition-transform duration-200 ease-out"
        style={{
          transform: `perspective(800px) rotateY(${tilt.x}deg) rotateX(${tilt.y}deg)`,
        }}>
        <VectiScanShield size={280} variant="teal" className="opacity-[0.14] animate-[pulse_4s_ease-in-out_infinite]" />
      </div>
    </div>
  );
}

/* ── Feature Icons (clean SVGs) ──────────────────────────── */
const Icons = {
  target: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>,
  brain: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M12 2a4 4 0 014 4v2a4 4 0 01-8 0V6a4 4 0 014-4z"/><path d="M6 10v1a6 6 0 0012 0v-1"/><line x1="12" y1="17" x2="12" y2="21"/><line x1="8" y1="21" x2="16" y2="21"/></svg>,
  file: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/></svg>,
  refresh: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 014-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 01-4 4H3"/></svg>,
  shield: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>,
  lock: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M14 9V5a3 3 0 00-6 0v4"/><rect x="6" y="9" width="12" height="12" rx="2"/><circle cx="12" cy="15" r="1.5"/></svg>,
  search: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>,
  alert: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  clipboard: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M16 4h2a2 2 0 012 2v14a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2h2"/><rect x="8" y="2" width="8" height="4" rx="1"/></svg>,
};

/* ── Step Sequence ───────────────────────────────────────── */
function StepSequence() {
  const { ref, visible } = useReveal();
  const [activeStep, setActiveStep] = useState(-1);
  useEffect(() => {
    if (!visible) return;
    const start = setTimeout(() => setActiveStep(0), 400);
    const iv = setInterval(() => setActiveStep(prev => (prev + 1) % 4), 3000);
    return () => { clearTimeout(start); clearInterval(iv); };
  }, [visible]);

  const steps = [
    { title: 'Ziele definieren', text: 'Domains, IPs oder Subnetze — bis zu 30 Ziele pro Abo' },
    { title: 'Automatisch scannen', text: 'Regelmäßige Scans im gewählten Intervall' },
    { title: 'Report erhalten', text: 'Geprüfter PDF-Report per E-Mail' },
    { title: 'Maßnahmen umsetzen', text: 'Priorisierter Plan mit konkreten Schritten' },
  ];

  return (
    <div ref={ref} className="max-w-3xl mx-auto">
      <div className="hidden md:flex items-center justify-between mb-10 px-8 relative">
        <div className="absolute left-8 right-8 top-1/2 h-0.5 -translate-y-1/2" style={{ backgroundColor: `${C.slateLight}` }} />
        <div className="absolute left-8 top-1/2 h-0.5 -translate-y-1/2 transition-all duration-700 ease-out"
          style={{ backgroundColor: C.teal, opacity: 0.6, width: activeStep < 0 ? '0%' : `${(activeStep / 3) * 100}%`, maxWidth: 'calc(100% - 4rem)' }} />
        {steps.map((_, i) => (
          <div key={i} className="relative z-10 w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all duration-500"
            style={{
              backgroundColor: i <= activeStep ? C.teal : C.slateLight,
              color: i <= activeStep ? C.slate : C.muted,
              boxShadow: i === activeStep ? `0 0 16px ${C.teal}50` : 'none',
            }}>
            {i < activeStep ? '\u2713' : i + 1}
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {steps.map((step, i) => (
          <div key={i} className="text-center p-4 rounded-2xl transition-all duration-500"
            style={{ backgroundColor: i === activeStep ? `${C.teal}08` : 'transparent' }}>
            <div className="md:hidden w-8 h-8 rounded-full mx-auto mb-3 flex items-center justify-center text-xs font-bold"
              style={{ backgroundColor: i <= activeStep ? C.teal : C.slateLight, color: i <= activeStep ? C.slate : C.muted }}>
              {i < activeStep ? '\u2713' : i + 1}
            </div>
            <h4 className="text-sm font-semibold mb-1.5 transition-colors duration-500"
              style={{ color: i === activeStep ? C.offWhite : i < activeStep ? C.mutedLight : C.muted }}>{step.title}</h4>
            <p className="text-xs leading-relaxed transition-colors duration-500"
              style={{ color: i === activeStep ? C.muted : `${C.muted}80` }}>{step.text}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Flickering Badge ────────────────────────────────────── */
function FlickerBadge({ text }: { text: string }) {
  const [dim, setDim] = useState(false);
  useEffect(() => {
    const flicker = () => { setDim(true); setTimeout(() => setDim(false), 200); setTimeout(flicker, 5000 + Math.random() * 8000); };
    const t = setTimeout(flicker, 2000 + Math.random() * 10000);
    return () => clearTimeout(t);
  }, []);
  return <span className="text-xs font-medium tracking-wide uppercase transition-opacity duration-200" style={{ color: C.muted, opacity: dim ? 0.3 : 1 }}>{text}</span>;
}

/* ── Main Page ───────────────────────────────────────────── */
export default function LandingPage() {
  return (
    <main className="flex-1 relative">
      <Suspense><OrderIdRedirect /></Suspense>

      {/* ── Hero ──────────────────────────────────────── */}
      <section className="relative overflow-hidden">
        <div className="max-w-5xl mx-auto px-6 pt-8 pb-20 md:pb-28 flex flex-col items-center text-center">
          <HeroShield />
          <div className="relative z-10 -mt-16">
            <h1 className="text-4xl md:text-6xl font-semibold leading-tight tracking-tight mb-4" style={{ color: C.offWhite }}>
              Kennen Sie Ihre<br />
              <span style={{ color: C.teal }}>Angriffsoberfläche</span>?
            </h1>
            <p className="text-lg md:text-xl font-normal mb-2" style={{ color: C.teal }}>
              Finden, bevor es andere tun.
            </p>
            <p className="text-base max-w-2xl mx-auto mb-10 leading-relaxed" style={{ color: C.muted }}>
              VectiScan analysiert Ihre exponierte IT-Infrastruktur automatisiert auf Schwachstellen.
              Regelmäßig, zuverlässig und nach anerkannten Standards — damit Sie wissen,
              wo Sie stehen, bevor es ein Angreifer tut.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link href="/pricing" className="px-7 py-3.5 rounded-lg text-sm font-semibold transition-all hover:shadow-[0_0_20px_#2DD4BF30]"
                style={{ backgroundColor: C.teal, color: C.slate }}>
                Angebot anfordern
              </Link>
              <Link href="/pricing#pakete" className="px-7 py-3.5 rounded-lg text-sm font-medium transition-all hover:border-[#2DD4BF60]"
                style={{ color: C.offWhite, border: `1px solid rgba(45,212,191,0.25)` }}>
                Pakete vergleichen
              </Link>
            </div>
          </div>
        </div>
        <div className="border-t border-b py-4" style={{ borderColor: 'rgba(45,212,191,0.08)' }}>
          <div className="max-w-4xl mx-auto flex flex-wrap items-center justify-center gap-x-8 gap-y-2 px-6">
            {['BSI-konform', 'PTES-Standard', 'CVSS v3.1', 'DSGVO-konform', 'Hosting in Deutschland'].map(t => (
              <FlickerBadge key={t} text={t} />
            ))}
          </div>
        </div>
      </section>

      {/* ── Pain Section ──────────────────────────────── */}
      <section className="py-20 md:py-24">
        <div className="max-w-5xl mx-auto px-6">
          <Reveal>
            <h2 className="text-2xl md:text-3xl font-semibold text-center mb-4" style={{ color: C.offWhite }}>
              Wissen Sie, wie angreifbar Ihr Unternehmen ist?
            </h2>
            <p className="text-sm text-center max-w-2xl mx-auto mb-12" style={{ color: C.muted }}>
              Die meisten Unternehmen kennen nur einen Bruchteil ihrer exponierten Systeme.
              Angreifer kennen sie alle.
            </p>
          </Reveal>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { icon: Icons.search, title: 'Unbekannte Angriffsoberfläche', text: 'Vergessene Subdomains, Testserver, offene Ports — Ihre externe IT-Landschaft ist größer als Sie denken. Jeder exponierte Dienst ist ein potenzielles Einfallstor.', d: 0 },
              { icon: Icons.alert, title: 'Veraltete Software', text: 'End-of-Life Betriebssysteme, fehlende Patches, bekannte CVEs — Schwachstellen, die seit Monaten öffentlich dokumentiert sind und aktiv ausgenutzt werden.', d: 120 },
              { icon: Icons.clipboard, title: 'Compliance-Druck', text: 'NIS2, BSI-Grundschutz, Cyberversicherungen — alle fordern regelmäßige Nachweise Ihrer IT-Sicherheit. Ohne belastbare Dokumentation wird es teuer.', d: 240 },
            ].map(({ icon, title, text, d }) => (
              <Reveal key={title} delay={d}>
                <div className="p-6 rounded-2xl h-full" style={{ backgroundColor: C.slateLight }}>
                  <div className="mb-3" style={{ color: C.teal }}>{icon}</div>
                  <h3 className="text-base font-semibold mb-2" style={{ color: C.offWhite }}>{title}</h3>
                  <p className="text-sm leading-relaxed" style={{ color: C.muted }}>{text}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ── Features Section ──────────────────────────── */}
      <section className="py-20 md:py-24" style={{ backgroundColor: `${C.slateLight}40` }}>
        <div className="max-w-5xl mx-auto px-6">
          <Reveal>
            <h2 className="text-2xl md:text-3xl font-semibold text-center mb-4" style={{ color: C.offWhite }}>
              Automatisierte Perimeter-Analyse.<br />Regelmäßig. Zuverlässig.
            </h2>
            <p className="text-sm text-center max-w-2xl mx-auto mb-12" style={{ color: C.muted }}>
              VectiScan kombiniert etablierte Open-Source-Scanner mit KI-gestützter
              Analyse zu einem vollautomatisierten Perimeter-Assessment.
            </p>
          </Reveal>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              { icon: Icons.target, title: 'Perimeter-Analyse', text: 'Port-Scanning, DNS-Enumeration, Web-Schwachstellen, SSL/TLS-Prüfung — über 20 spezialisierte Scanner analysieren Ihre externe Angriffsoberfläche.', d: 0 },
              { icon: Icons.brain, title: 'KI-gestützte Bewertung', text: 'Intelligente Korrelation über Tool-Grenzen hinweg. False-Positive-Filterung und kontextbezogene Risikobewertung nach CVSS v3.1.', d: 80 },
              { icon: Icons.file, title: 'Professionelle Reports', text: 'Executive Summary für die Geschäftsleitung, technische Details für Ihr IT-Team, priorisierter Maßnahmenplan mit konkreten Handlungsempfehlungen.', d: 160 },
              { icon: Icons.refresh, title: 'Automatische Wiederholung', text: 'Wöchentliche, monatliche oder quartalsweise Scans — Sie definieren den Rhythmus, wir liefern zuverlässig aktuelle Ergebnisse.', d: 240 },
              { icon: Icons.shield, title: 'Compliance-Nachweise', text: 'Mappings auf NIS2 (§30 BSIG), BSI-Grundschutz, ISO 27001 und Cyberversicherungs-Anforderungen — direkt im Report.', d: 320 },
              { icon: Icons.lock, title: 'Qualitätsgesichert', text: 'Jeder Report wird vor der Zustellung manuell geprüft. False Positives werden markiert, Befunde validiert — keine automatisierten Fehlalarme.', d: 400 },
            ].map(({ icon, title, text, d }) => (
              <Reveal key={title} delay={d}>
                <div className="p-5 rounded-2xl h-full group hover:shadow-[0_0_30px_#2DD4BF06] transition-all duration-300" style={{ backgroundColor: C.slateLight }}>
                  <div className="mb-3 opacity-80 group-hover:opacity-100 transition-opacity" style={{ color: C.teal }}>{icon}</div>
                  <h4 className="text-sm font-semibold mb-1.5" style={{ color: C.offWhite }}>{title}</h4>
                  <p className="text-xs leading-relaxed" style={{ color: C.muted }}>{text}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ── Packages Preview ──────────────────────────── */}
      <section className="py-20 md:py-24">
        <div className="max-w-4xl mx-auto px-6">
          <Reveal>
            <h2 className="text-2xl md:text-3xl font-semibold text-center mb-12" style={{ color: C.offWhite }}>
              Zwei Pakete. Ein Ziel: Ihre Sicherheit.
            </h2>
          </Reveal>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {[
              { name: 'Perimeter-Scan', sub: 'Vollständige Sicherheitsanalyse Ihrer externen Angriffsoberfläche', recommended: true,
                features: ['Port-Scanning & Service-Erkennung', 'Web-Schwachstellen-Analyse (OWASP)', 'DNS- & E-Mail-Security-Prüfung', 'PTES-konformer Report mit Maßnahmenplan', 'NIS2/BSI-Compliance-Mapping'] },
              { name: 'Cyberversicherung', sub: 'Nachweis und Dokumentation für Ihren Versicherungsantrag', recommended: false,
                features: ['Alles aus dem Perimeter-Scan', '10-Punkte Versicherungs-Fragebogen', 'Risk-Score & Ransomware-Indikator', 'Versicherungskonformer Nachweis-Report', 'Direkt einreichbar bei Ihrem Versicherer'] },
            ].map((pkg, i) => (
              <Reveal key={pkg.name} delay={i * 120}>
                <div className="rounded-2xl p-6 relative h-full transition-all duration-300 hover:shadow-[0_0_40px_#2DD4BF06]"
                  style={{ backgroundColor: C.slateLight }}>
                  {pkg.recommended && (
                    <span className="absolute -top-2.5 left-5 text-[10px] font-semibold px-2.5 py-0.5 rounded-full"
                      style={{ backgroundColor: `${C.teal}20`, color: C.teal }}>Empfohlen</span>
                  )}
                  <h3 className="text-lg font-semibold mt-2 mb-1" style={{ color: C.offWhite }}>{pkg.name}</h3>
                  <p className="text-xs mb-4" style={{ color: C.muted }}>{pkg.sub}</p>
                  <ul className="space-y-2 mb-5">
                    {pkg.features.map(f => (
                      <li key={f} className="flex items-start gap-2 text-xs" style={{ color: C.mutedLight }}>
                        <span style={{ color: C.teal }} className="mt-0.5">&#x2713;</span> {f}
                      </li>
                    ))}
                  </ul>
                  <p className="text-xs font-medium" style={{ color: C.muted }}>Preis auf Anfrage</p>
                </div>
              </Reveal>
            ))}
          </div>
          <Reveal delay={200}>
            <div className="text-center mt-8">
              <Link href="/pricing" className="text-sm font-medium transition-colors hover:underline" style={{ color: C.teal }}>
                Alle Details und Preise vergleichen &#8594;
              </Link>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ── Interstitial Statement ─────────────────────── */}
      <section className="py-28 md:py-32 relative">
        <div className="absolute left-1/2 -translate-x-1/2 top-8 w-24 h-px" style={{ backgroundColor: `${C.teal}18` }} />
        <div className="max-w-3xl mx-auto px-6 text-center">
          <Reveal>
            <p className="text-2xl md:text-3xl font-semibold leading-snug" style={{ color: C.offWhite }}>
              Sicherheit ist kein Gefühl.<br />
              <span style={{ color: C.teal }}>Sondern ein Ergebnis.</span>
            </p>
          </Reveal>
        </div>
        <div className="absolute left-1/2 -translate-x-1/2 bottom-8 w-24 h-px" style={{ backgroundColor: `${C.teal}18` }} />
      </section>

      {/* ── How It Works ──────────────────────────────── */}
      <section className="py-20 md:py-28" style={{ backgroundColor: `${C.slateLight}40` }}>
        <div className="max-w-5xl mx-auto px-6">
          <Reveal>
            <h2 className="text-2xl md:text-3xl font-semibold text-center mb-16" style={{ color: C.offWhite }}>
              So funktioniert&apos;s
            </h2>
          </Reveal>
          <StepSequence />
        </div>
      </section>

      {/* ── Trust Section ─────────────────────────────── */}
      <section className="py-16">
        <div className="max-w-4xl mx-auto px-6">
          <p className="text-xs text-center uppercase tracking-widest mb-6" style={{ color: C.muted }}>Standards &amp; Technologie</p>
          <div className="flex flex-wrap items-center justify-center gap-x-8 gap-y-3">
            {['OWASP ZAP', 'Nmap', 'Nuclei', 'testssl.sh', 'Claude AI', 'PTES', 'CVSS v3.1', 'BSI TR-03116-4'].map(t => (
              <span key={t} className="text-xs font-light" style={{ color: `${C.muted}90` }}>{t}</span>
            ))}
          </div>
          <p className="text-center mt-6 text-xs font-light" style={{ color: C.muted }}>
            Made in Germany — Entwicklung und Hosting in Deutschland
          </p>
        </div>
      </section>

      {/* ── Final CTA ─────────────────────────────────── */}
      <section className="py-20 md:py-28">
        <div className="max-w-2xl mx-auto px-6 text-center">
          <Reveal>
            <h2 className="text-2xl md:text-3xl font-semibold mb-4" style={{ color: C.offWhite }}>
              Bereit für Ihren ersten Security-Scan?
            </h2>
            <p className="text-sm mb-8 font-light" style={{ color: C.muted }}>
              Lassen Sie sich ein individuelles Angebot erstellen — oder starten Sie direkt.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link href="/pricing" className="px-7 py-3.5 rounded-lg text-sm font-semibold transition-all hover:shadow-[0_0_20px_#2DD4BF30]"
                style={{ backgroundColor: C.teal, color: C.slate }}>
                Angebot anfordern
              </Link>
              <Link href="/subscribe" className="px-7 py-3.5 rounded-lg text-sm font-medium transition-all"
                style={{ color: C.offWhite, border: '1px solid rgba(45,212,191,0.25)' }}>
                Direkt Abo starten
              </Link>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ── Footer ────────────────────────────────────── */}
      <footer className="border-t py-10 px-6" style={{ borderColor: 'rgba(45,212,191,0.08)' }}>
        <div className="max-w-5xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-2.5">
            <VectiScanShield size={28} variant="teal" />
            <span className="text-sm font-bold tracking-tight" style={{ letterSpacing: '-0.5px' }}>
              <span style={{ color: C.offWhite }}>vecti</span><span style={{ color: C.teal }}>scan</span>
            </span>
          </div>
          <div className="flex items-center gap-6">
            <a href="mailto:kontakt@vectigal.gmbh" className="text-xs font-light transition-colors hover:text-white" style={{ color: C.muted }}>Kontakt</a>
            <a href="/impressum" className="text-xs font-light transition-colors hover:text-white" style={{ color: C.muted }}>Impressum</a>
            <a href="/datenschutz" className="text-xs font-light transition-colors hover:text-white" style={{ color: C.muted }}>Datenschutz</a>
          </div>
          <p className="text-xs font-light" style={{ color: `${C.muted}60` }}>&copy; 2026 Vectigal GmbH</p>
        </div>
      </footer>
    </main>
  );
}

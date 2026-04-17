'use client';

import { useState, useEffect, useRef, useCallback, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';

/* ── Brand Colors ────────────────────────────────────────── */
const C = {
  slate: '#0F172A',
  slateLight: '#1E293B',
  teal: '#2DD4BF',
  tealDark: '#14B8A6',
  offWhite: '#F8FAFC',
  muted: '#94A3B8',
  mutedLight: '#CBD5E1',
  border: 'rgba(45,212,191,0.12)',
  borderSubtle: 'rgba(30,58,95,0.35)',
};

/* ── Scroll-Reveal Hook ──────────────────────────────────── */
function useReveal() {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      ([e]) => { if (e.isIntersecting) { setVisible(true); obs.disconnect(); } },
      { threshold: 0.1 },
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, []);
  return { ref, visible };
}

/* ── Cursor Grid entfernt — wird später durch besseren Effekt ersetzt ── */

/* ── Shield SVG (Hero visual, animated) ───────────────── */
function ShieldGraphic({ offsetX, offsetY }: { offsetX: number; offsetY: number }) {
  return (
    <svg width="340" height="340" viewBox="0 0 280 280" fill="none"
      className="transition-transform duration-300 ease-out"
      style={{ transform: `translate(${offsetX}px, ${offsetY}px)`, opacity: 0.12 }}>
      <path d="M140 20L30 65v75c0 70 48 118 110 130 62-12 110-60 110-130V65L140 20z"
        fill="none" stroke={C.teal} strokeWidth="1.5" />
      <path d="M140 50L55 85v55c0 55 38 93 85 102 47-9 85-47 85-102V85L140 50z"
        fill="none" stroke={C.teal} strokeWidth="0.75" opacity="0.4" />
      <line x1="80" y1="140" x2="200" y2="140" stroke={C.teal} strokeWidth="0.75" opacity="0.25" />
      <line x1="140" y1="80" x2="140" y2="200" stroke={C.teal} strokeWidth="0.75" opacity="0.25" />
      <circle cx="140" cy="140" r="4" fill={C.teal} opacity="0.4" />
      <g className="animate-[spin_25s_linear_infinite]" style={{ transformOrigin: '140px 140px' }}>
        {[100, 120, 160, 180].map(y => (
          <line key={y} x1="85" y1={y} x2="195" y2={y} stroke={C.teal} strokeWidth="0.5" opacity="0.1" />
        ))}
      </g>
      <circle cx="140" cy="140" r="12" fill="none" stroke={C.teal} strokeWidth="0.5"
        className="animate-[ping_4s_ease-out_infinite]" opacity="0.15" />
      <circle cx="140" cy="140" r="30" fill="none" stroke={C.teal} strokeWidth="0.3"
        className="animate-[ping_6s_ease-out_infinite]" opacity="0.08" style={{ animationDelay: '2s' }} />
    </svg>
  );
}

/* ── Glitch Text ─────────────────────────────────────── */
function GlitchText({ children }: { children: string }) {
  const [glitch, setGlitch] = useState(false);
  useEffect(() => {
    const trigger = () => {
      setGlitch(true);
      setTimeout(() => setGlitch(false), 80);
      setTimeout(trigger, 8000 + Math.random() * 6000);
    };
    const t = setTimeout(trigger, 3000 + Math.random() * 4000);
    return () => clearTimeout(t);
  }, []);
  return (
    <span style={{
      color: C.teal,
      ...(glitch ? { textShadow: `2px 0 ${C.teal}80, -2px 0 #ff006630`, filter: 'hue-rotate(8deg)' } : {}),
    }}>
      {children}
    </span>
  );
}

/* ── Reveal Wrapper ───────────────────────────────────── */
function Reveal({ children, delay = 0 }: { children: React.ReactNode; delay?: number }) {
  const { ref, visible } = useReveal();
  return (
    <div ref={ref} className="transition-all duration-700 ease-out"
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateY(0)' : 'translateY(20px)',
        transitionDelay: `${delay}ms`,
      }}>
      {children}
    </div>
  );
}

/* ── Sequential Steps (So funktioniert's) ─────────────── */
function StepSequence() {
  const { ref, visible } = useReveal();
  const [activeStep, setActiveStep] = useState(-1);

  useEffect(() => {
    if (!visible) return;
    // Initial delay, then cycle
    const start = setTimeout(() => setActiveStep(0), 400);
    const iv = setInterval(() => {
      setActiveStep(prev => (prev + 1) % 4);
    }, 3000);
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
      {/* Progress bar */}
      <div className="hidden md:flex items-center justify-between mb-10 px-8 relative">
        {/* Background track */}
        <div className="absolute left-8 right-8 top-1/2 h-0.5 -translate-y-1/2" style={{ backgroundColor: C.borderSubtle }} />
        {/* Filled track */}
        <div className="absolute left-8 top-1/2 h-0.5 -translate-y-1/2 transition-all duration-700 ease-out"
          style={{
            backgroundColor: C.teal,
            opacity: 0.6,
            width: activeStep < 0 ? '0%' : `${(activeStep / 3) * 100}%`,
            maxWidth: 'calc(100% - 4rem)',
          }} />
        {/* Step dots on the track */}
        {steps.map((_, i) => {
          const done = i <= activeStep;
          return (
            <div key={i} className="relative z-10 w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all duration-500"
              style={{
                backgroundColor: done ? C.teal : C.slateLight,
                color: done ? C.slate : C.muted,
                border: `2px solid ${done ? C.teal : C.borderSubtle}`,
                boxShadow: i === activeStep ? `0 0 16px ${C.teal}50` : 'none',
              }}>
              {i < activeStep ? '\u2713' : i + 1}
            </div>
          );
        })}
      </div>

      {/* Step cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {steps.map((step, i) => {
          const isActive = i === activeStep;
          const isDone = i < activeStep;
          return (
            <div key={i} className="text-center p-4 rounded-lg transition-all duration-500"
              style={{
                backgroundColor: isActive ? `${C.teal}08` : 'transparent',
                border: `1px solid ${isActive ? `${C.teal}20` : 'transparent'}`,
              }}>
              {/* Mobile number (hidden on desktop where progress bar shows) */}
              <div className="md:hidden w-8 h-8 rounded-full mx-auto mb-3 flex items-center justify-center text-xs font-bold"
                style={{
                  backgroundColor: isActive || isDone ? C.teal : C.slateLight,
                  color: isActive || isDone ? C.slate : C.muted,
                  border: `2px solid ${isActive || isDone ? C.teal : C.borderSubtle}`,
                }}>
                {isDone ? '\u2713' : i + 1}
              </div>
              <h4 className="text-sm font-bold mb-1.5 transition-colors duration-500"
                style={{ color: isActive ? C.offWhite : isDone ? C.mutedLight : C.muted }}>
                {step.title}
              </h4>
              <p className="text-xs leading-relaxed transition-colors duration-500"
                style={{ color: isActive ? C.muted : `${C.muted}80` }}>
                {step.text}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ── Pain Card ───────────────────────────────────────── */
function PainCard({ icon, title, text, delay }: { icon: string; title: string; text: string; delay: number }) {
  return (
    <Reveal delay={delay}>
      <div className="p-6 rounded-xl h-full group hover:border-[#2DD4BF20] transition-all duration-300"
        style={{ backgroundColor: C.slateLight, border: `1px solid ${C.borderSubtle}` }}>
        <div className="text-2xl mb-3">{icon}</div>
        <h3 className="text-base font-semibold mb-2" style={{ color: C.offWhite }}>{title}</h3>
        <p className="text-sm leading-relaxed" style={{ color: C.muted }}>{text}</p>
      </div>
    </Reveal>
  );
}

/* ── Feature Card ────────────────────────────────────── */
function FeatureCard({ icon, title, text, delay }: { icon: React.ReactNode; title: string; text: string; delay: number }) {
  return (
    <Reveal delay={delay}>
      <div className="p-5 rounded-lg h-full group hover:border-[#2DD4BF25] transition-all duration-300 hover:shadow-[0_0_30px_#2DD4BF08]"
        style={{ backgroundColor: C.slateLight, border: `1px solid ${C.borderSubtle}` }}>
        <div className="mb-3 text-[#2DD4BF] opacity-80 group-hover:opacity-100 transition-opacity duration-300">
          {icon}
        </div>
        <h4 className="text-sm font-semibold mb-1.5" style={{ color: C.offWhite }}>{title}</h4>
        <p className="text-xs leading-relaxed" style={{ color: C.muted }}>{text}</p>
      </div>
    </Reveal>
  );
}

/* ── Feature Icons (Teal SVGs) ────────────────────────── */
const FeatureIcons = {
  perimeter: (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="2" />
      <line x1="12" y1="2" x2="12" y2="4" /><line x1="12" y1="20" x2="12" y2="22" />
      <line x1="2" y1="12" x2="4" y2="12" /><line x1="20" y1="12" x2="22" y2="12" />
    </svg>
  ),
  ai: (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2a4 4 0 0 1 4 4v2a4 4 0 0 1-8 0V6a4 4 0 0 1 4-4z" />
      <path d="M6 10v1a6 6 0 0 0 12 0v-1" />
      <line x1="12" y1="17" x2="12" y2="21" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <circle cx="9" cy="7" r="0.5" fill="currentColor" /><circle cx="15" cy="7" r="0.5" fill="currentColor" />
    </svg>
  ),
  report: (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="8" y1="13" x2="16" y2="13" /><line x1="8" y1="17" x2="13" y2="17" />
      <path d="M10 9l2 2 4-4" />
    </svg>
  ),
  repeat: (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="17 1 21 5 17 9" /><path d="M3 11V9a4 4 0 0 1 4-4h14" />
      <polyline points="7 23 3 19 7 15" /><path d="M21 13v2a4 4 0 0 1-4 4H3" />
    </svg>
  ),
  compliance: (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  ),
  quality: (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 9V5a3 3 0 0 0-6 0v4" /><rect x="6" y="9" width="12" height="12" rx="2" />
      <circle cx="12" cy="15" r="1.5" />
      <line x1="12" y1="16.5" x2="12" y2="18" />
    </svg>
  ),
};

/* ── Flickering Badge ────────────────────────────────── */
function FlickerBadge({ text }: { text: string }) {
  const [dim, setDim] = useState(false);
  useEffect(() => {
    const flicker = () => {
      setDim(true);
      setTimeout(() => setDim(false), 200);
      setTimeout(flicker, 5000 + Math.random() * 8000);
    };
    const t = setTimeout(flicker, 2000 + Math.random() * 10000);
    return () => clearTimeout(t);
  }, []);
  return (
    <span className="text-xs font-medium tracking-wide uppercase transition-opacity duration-200"
      style={{ color: C.muted, opacity: dim ? 0.3 : 1 }}>
      {text}
    </span>
  );
}

/* ── Redirect wrapper (needs Suspense for useSearchParams) ── */
function OrderIdRedirect() {
  const router = useRouter();
  const searchParams = useSearchParams();
  useEffect(() => {
    const orderId = searchParams.get('orderId');
    if (orderId) { router.replace(`/scan?orderId=${orderId}`); }
  }, [searchParams, router]);
  return null;
}

/* ── Main Landing Page ─────────────────────────────────── */
export default function LandingPage() {
  const [mouseOffset, setMouseOffset] = useState({ x: 0, y: 0 });
  const heroRef = useRef<HTMLDivElement>(null);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!heroRef.current) return;
    const rect = heroRef.current.getBoundingClientRect();
    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;
    setMouseOffset({
      x: ((e.clientX - cx) / rect.width) * -25,
      y: ((e.clientY - cy) / rect.height) * -18,
    });
  }, []);

  return (
    <main className="flex-1 relative">
      {/* Legacy orderId redirect */}
      <Suspense><OrderIdRedirect /></Suspense>

      {/* ── Hero ──────────────────────────────────────── */}
      <section ref={heroRef} className="relative overflow-hidden z-10" onMouseMove={handleMouseMove}>
        <div className="max-w-5xl mx-auto px-6 py-24 md:py-36 flex flex-col items-center text-center">
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <ShieldGraphic offsetX={mouseOffset.x} offsetY={mouseOffset.y} />
          </div>
          <div className="relative z-10">
            <h1 className="text-4xl md:text-6xl font-bold leading-tight tracking-tight mb-6"
              style={{ color: C.offWhite }}>
              Kennen Sie Ihre<br />
              <GlitchText>Angriffsoberfläche</GlitchText>
              <span style={{ color: C.offWhite }}>?</span>
            </h1>
            <p className="text-base md:text-lg max-w-2xl mx-auto mb-10 leading-relaxed"
              style={{ color: C.muted }}>
              VectiScan analysiert Ihre gesamte IT-Infrastruktur automatisiert auf Schwachstellen.
              Regelmäßig, zuverlässig und nach anerkannten Standards — damit Sie wissen,
              wo Sie stehen, bevor es ein Angreifer tut.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link href="/pricing"
                className="px-8 py-3.5 rounded-lg text-sm font-semibold transition-all hover:shadow-[0_0_25px_#2DD4BF40] hover:scale-[1.02]"
                style={{ backgroundColor: C.teal, color: C.slate }}>
                Angebot anfordern
              </Link>
              <Link href="/pricing#pakete"
                className="px-8 py-3.5 rounded-lg text-sm font-medium transition-all hover:bg-[#2DD4BF10] hover:border-[#2DD4BF60]"
                style={{ color: C.teal, border: `1px solid ${C.teal}35` }}>
                Pakete vergleichen
              </Link>
            </div>
          </div>
        </div>

        {/* Trust Bar */}
        <div className="border-t border-b py-4 relative z-10" style={{ borderColor: C.borderSubtle }}>
          <div className="max-w-4xl mx-auto flex flex-wrap items-center justify-center gap-x-8 gap-y-2 px-6">
            {['BSI-konform', 'PTES-Standard', 'CVSS v3.1', 'DSGVO-konform', 'Hosting in Deutschland'].map(t => (
              <FlickerBadge key={t} text={t} />
            ))}
          </div>
        </div>
      </section>

      {/* ── Pain Section ──────────────────────────────── */}
      <section className="py-20 md:py-24 relative z-10">
        <div className="max-w-5xl mx-auto px-6">
          <Reveal>
            <h2 className="text-2xl md:text-3xl font-bold text-center mb-4" style={{ color: C.offWhite }}>
              Wissen Sie, wie angreifbar Ihr Unternehmen ist?
            </h2>
            <p className="text-sm text-center max-w-2xl mx-auto mb-12" style={{ color: C.muted }}>
              Die meisten Unternehmen kennen nur einen Bruchteil ihrer exponierten Systeme.
              Angreifer kennen sie alle.
            </p>
          </Reveal>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <PainCard delay={0} icon="&#x1F50D;" title="Unbekannte Angriffsoberfläche"
              text="Vergessene Subdomains, Testserver, offene Ports — Ihre IT-Landschaft ist größer als Sie denken. Jeder exponierte Dienst ist ein potenzielles Einfallstor." />
            <PainCard delay={120} icon="&#x26A0;" title="Veraltete Software"
              text="End-of-Life Betriebssysteme, fehlende Patches, bekannte CVEs — Schwachstellen die seit Monaten öffentlich dokumentiert sind und aktiv ausgenutzt werden." />
            <PainCard delay={240} icon="&#x1F4CB;" title="Compliance-Druck"
              text="NIS2, BSI-Grundschutz, Cyberversicherungen — alle fordern regelmäßige Nachweise Ihrer IT-Sicherheit. Ohne belastbare Dokumentation wird es teuer." />
          </div>
        </div>
      </section>

      {/* ── Features Section ──────────────────────────── */}
      <section className="py-20 md:py-24 relative z-10" style={{ backgroundColor: `${C.slateLight}40` }}>
        <div className="max-w-5xl mx-auto px-6">
          <Reveal>
            <h2 className="text-2xl md:text-3xl font-bold text-center mb-4" style={{ color: C.offWhite }}>
              Automatisierte Security-Analyse.<br />Regelmäßig. Zuverlässig.
            </h2>
            <p className="text-sm text-center max-w-2xl mx-auto mb-12" style={{ color: C.muted }}>
              VectiScan kombiniert etablierte Open-Source-Scanner mit KI-gestützter
              Analyse zu einem vollautomatisierten Security-Assessment.
            </p>
          </Reveal>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <FeatureCard delay={0} icon={FeatureIcons.perimeter} title="Perimeter-Analyse"
              text="Port-Scanning, DNS-Enumeration, Web-Schwachstellen, SSL/TLS-Prüfung — über 15 spezialisierte Scanner analysieren Ihre gesamte Angriffsoberfläche." />
            <FeatureCard delay={80} icon={FeatureIcons.ai} title="KI-gestützte Bewertung"
              text="Intelligente Korrelation über Tool-Grenzen hinweg. False-Positive-Filterung und kontextbezogene Risikobewertung nach CVSS v3.1." />
            <FeatureCard delay={160} icon={FeatureIcons.report} title="Professionelle Reports"
              text="Executive Summary für die Geschäftsleitung, technische Details für Ihr IT-Team, priorisierter Maßnahmenplan mit konkreten Handlungsempfehlungen." />
            <FeatureCard delay={240} icon={FeatureIcons.repeat} title="Automatische Wiederholung"
              text="Wöchentliche, monatliche oder quartalsweise Scans — Sie definieren den Rhythmus, wir liefern zuverlässig aktuelle Ergebnisse." />
            <FeatureCard delay={320} icon={FeatureIcons.compliance} title="Compliance-Nachweise"
              text="Mappings auf NIS2 (§30 BSIG), BSI-Grundschutz, ISO 27001 und Cyberversicherungs-Anforderungen — direkt im Report." />
            <FeatureCard delay={400} icon={FeatureIcons.quality} title="Qualitätsgesichert"
              text="Jeder Report wird vor der Zustellung manuell geprüft. False Positives werden markiert, Befunde validiert — keine automatisierten Fehlalarme." />
          </div>
        </div>
      </section>

      {/* ── Packages Preview ──────────────────────────── */}
      <section className="py-20 md:py-24 relative z-10">
        <div className="max-w-4xl mx-auto px-6">
          <Reveal>
            <h2 className="text-2xl md:text-3xl font-bold text-center mb-12" style={{ color: C.offWhite }}>
              Zwei Pakete. Ein Ziel: Ihre Sicherheit.
            </h2>
          </Reveal>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <Reveal delay={0}>
              <div className="rounded-xl p-6 relative h-full hover:border-[#2DD4BF30] hover:shadow-[0_0_40px_#2DD4BF08] transition-all duration-500"
                style={{ backgroundColor: C.slateLight, border: `1px solid ${C.border}` }}>
                <span className="absolute -top-2.5 left-5 text-[10px] font-semibold px-2.5 py-0.5 rounded-full"
                  style={{ backgroundColor: `${C.teal}20`, color: C.teal }}>Empfohlen</span>
                <h3 className="text-lg font-bold mt-2 mb-1" style={{ color: C.offWhite }}>Perimeter-Scan</h3>
                <p className="text-xs mb-4" style={{ color: C.muted }}>Vollständige Sicherheitsanalyse Ihrer externen Angriffsoberfläche</p>
                <ul className="space-y-2 mb-5">
                  {['Port-Scanning & Service-Erkennung', 'Web-Schwachstellen-Analyse (OWASP)', 'DNS- & E-Mail-Security-Prüfung', 'PTES-konformer Report mit Maßnahmenplan', 'NIS2/BSI-Compliance-Mapping'].map(f => (
                    <li key={f} className="flex items-start gap-2 text-xs" style={{ color: C.mutedLight }}>
                      <span style={{ color: C.teal }} className="mt-0.5">&#x2713;</span> {f}
                    </li>
                  ))}
                </ul>
                <p className="text-xs font-medium" style={{ color: C.muted }}>Preis auf Anfrage</p>
              </div>
            </Reveal>
            <Reveal delay={120}>
              <div className="rounded-xl p-6 h-full hover:border-[#2DD4BF20] hover:shadow-[0_0_40px_#2DD4BF06] transition-all duration-500"
                style={{ backgroundColor: C.slateLight, border: `1px solid ${C.borderSubtle}` }}>
                <h3 className="text-lg font-bold mt-2 mb-1" style={{ color: C.offWhite }}>Cyberversicherung</h3>
                <p className="text-xs mb-4" style={{ color: C.muted }}>Nachweis und Dokumentation für Ihren Versicherungsantrag</p>
                <ul className="space-y-2 mb-5">
                  {['Alles aus dem Perimeter-Scan', '10-Punkte Versicherungs-Fragebogen', 'Risk-Score & Ransomware-Indikator', 'Versicherungskonformer Nachweis-Report', 'Direkt einreichbar bei Ihrem Versicherer'].map(f => (
                    <li key={f} className="flex items-start gap-2 text-xs" style={{ color: C.mutedLight }}>
                      <span style={{ color: C.teal }} className="mt-0.5">&#x2713;</span> {f}
                    </li>
                  ))}
                </ul>
                <p className="text-xs font-medium" style={{ color: C.muted }}>Preis auf Anfrage</p>
              </div>
            </Reveal>
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

      {/* ── How It Works (with animated arrows) ───────── */}
      <section className="py-20 md:py-28 relative z-10" style={{ backgroundColor: `${C.slateLight}40` }}>
        <div className="max-w-5xl mx-auto px-6">
          <Reveal>
            <h2 className="text-2xl md:text-3xl font-bold text-center mb-16" style={{ color: C.offWhite }}>
              So funktioniert&apos;s
            </h2>
          </Reveal>
          <StepSequence />
        </div>
      </section>

      {/* ── Trust Section ─────────────────────────────── */}
      <section className="py-16 relative z-10">
        <div className="max-w-4xl mx-auto px-6">
          <p className="text-xs text-center uppercase tracking-widest mb-6" style={{ color: C.muted }}>
            Standards &amp; Technologie
          </p>
          <div className="flex flex-wrap items-center justify-center gap-x-8 gap-y-3">
            {['OWASP ZAP', 'Nmap', 'Nuclei', 'testssl.sh', 'Claude AI', 'PTES', 'CVSS v3.1', 'BSI TR-03116-4'].map(t => (
              <span key={t} className="text-xs font-mono" style={{ color: `${C.muted}90` }}>{t}</span>
            ))}
          </div>
          <p className="text-center mt-6 text-xs" style={{ color: C.muted }}>
            Made in Germany — Entwicklung und Hosting in Deutschland
          </p>
        </div>
      </section>

      {/* ── Final CTA ─────────────────────────────────── */}
      <section className="py-20 md:py-28 relative z-10">
        <div className="max-w-2xl mx-auto px-6 text-center">
          <Reveal>
            <h2 className="text-2xl md:text-3xl font-bold mb-4" style={{ color: C.offWhite }}>
              Bereit für Ihren ersten Security-Scan?
            </h2>
            <p className="text-sm mb-8" style={{ color: C.muted }}>
              Lassen Sie sich ein individuelles Angebot erstellen — oder starten Sie direkt.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link href="/pricing"
                className="px-8 py-3.5 rounded-lg text-sm font-semibold transition-all hover:shadow-[0_0_25px_#2DD4BF40] hover:scale-[1.02]"
                style={{ backgroundColor: C.teal, color: C.slate }}>
                Angebot anfordern
              </Link>
              <Link href="/subscribe"
                className="px-8 py-3.5 rounded-lg text-sm font-medium transition-all hover:bg-[#1E293B80]"
                style={{ color: C.muted, border: `1px solid ${C.borderSubtle}` }}>
                Direkt Abo starten
              </Link>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ── Footer ────────────────────────────────────── */}
      <footer className="border-t py-8 px-6 relative z-10" style={{ borderColor: C.borderSubtle }}>
        <div className="max-w-5xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <span className="text-xs font-semibold" style={{ color: C.muted }}>
            vectigal<span style={{ color: C.teal }}>.</span><span style={{ color: C.teal }}>ai</span>
          </span>
          <div className="flex items-center gap-6">
            <a href="mailto:kontakt@vectigal.gmbh" className="text-xs transition-colors hover:text-white" style={{ color: C.muted }}>Kontakt</a>
            <a href="/impressum" className="text-xs transition-colors hover:text-white" style={{ color: C.muted }}>Impressum</a>
            <a href="/datenschutz" className="text-xs transition-colors hover:text-white" style={{ color: C.muted }}>Datenschutz</a>
          </div>
          <p className="text-xs" style={{ color: `${C.muted}60` }}>&copy; 2026 Vectigal GmbH</p>
        </div>
      </footer>
    </main>
  );
}

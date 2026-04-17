'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
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
      { threshold: 0.15 },
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, []);
  return { ref, visible };
}

/* ── Shield SVG (Hero visual, animated) ───────────────── */
function ShieldGraphic({ offsetX, offsetY }: { offsetX: number; offsetY: number }) {
  return (
    <svg width="320" height="320" viewBox="0 0 280 280" fill="none"
      className="opacity-15 transition-transform duration-200 ease-out"
      style={{ transform: `translate(${offsetX}px, ${offsetY}px)` }}>
      <path d="M140 20L30 65v75c0 70 48 118 110 130 62-12 110-60 110-130V65L140 20z"
        fill="none" stroke={C.teal} strokeWidth="1.5" />
      <path d="M140 50L55 85v55c0 55 38 93 85 102 47-9 85-47 85-102V85L140 50z"
        fill="none" stroke={C.teal} strokeWidth="0.75" opacity="0.4" />
      <line x1="80" y1="140" x2="200" y2="140" stroke={C.teal} strokeWidth="0.75" opacity="0.3" />
      <line x1="140" y1="80" x2="140" y2="200" stroke={C.teal} strokeWidth="0.75" opacity="0.3" />
      <circle cx="140" cy="140" r="4" fill={C.teal} opacity="0.5" />
      {/* Scanning lines with slow rotation */}
      <g className="animate-[spin_25s_linear_infinite]" style={{ transformOrigin: '140px 140px' }}>
        {[100, 120, 160, 180].map(y => (
          <line key={y} x1="85" y1={y} x2="195" y2={y} stroke={C.teal} strokeWidth="0.5" opacity="0.12" />
        ))}
      </g>
      {/* Pulsing center */}
      <circle cx="140" cy="140" r="8" fill="none" stroke={C.teal} strokeWidth="0.5"
        className="animate-[ping_3s_ease-out_infinite]" opacity="0.2" />
    </svg>
  );
}

/* ── Glitch Text Component ────────────────────────────── */
function GlitchText({ children, className }: { children: string; className?: string }) {
  const [glitch, setGlitch] = useState(false);
  useEffect(() => {
    const trigger = () => {
      setGlitch(true);
      setTimeout(() => setGlitch(false), 80);
      const next = 8000 + Math.random() * 6000;
      setTimeout(trigger, next);
    };
    const initial = 3000 + Math.random() * 4000;
    const t = setTimeout(trigger, initial);
    return () => clearTimeout(t);
  }, []);

  return (
    <span className={className} style={glitch ? {
      textShadow: `2px 0 ${C.teal}60, -2px 0 #ff006620`,
      filter: 'hue-rotate(5deg)',
    } : undefined}>
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
        transform: visible ? 'translateY(0)' : 'translateY(24px)',
        transitionDelay: `${delay}ms`,
      }}>
      {children}
    </div>
  );
}

/* ── Pain Point Card ─────────────────────────────────── */
function PainCard({ icon, title, text, delay }: { icon: string; title: string; text: string; delay: number }) {
  return (
    <Reveal delay={delay}>
      <div className="p-6 rounded-xl h-full animate-[panelBreathe_8s_ease-in-out_infinite]"
        style={{ backgroundColor: C.slateLight, border: `1px solid ${C.borderSubtle}` }}>
        <div className="text-2xl mb-3">{icon}</div>
        <h3 className="text-base font-semibold mb-2" style={{ color: C.offWhite }}>{title}</h3>
        <p className="text-sm leading-relaxed" style={{ color: C.muted }}>{text}</p>
      </div>
    </Reveal>
  );
}

/* ── Feature Card ────────────────────────────────────── */
function FeatureCard({ title, text, delay }: { title: string; text: string; delay: number }) {
  return (
    <Reveal delay={delay}>
      <div className="p-5 rounded-lg h-full group hover:border-[#2DD4BF30] transition-colors duration-300"
        style={{ backgroundColor: C.slateLight, border: `1px solid ${C.borderSubtle}` }}>
        <div className="w-1.5 h-1.5 rounded-full mb-3 group-hover:shadow-[0_0_8px_#2DD4BF60] transition-shadow duration-300"
          style={{ backgroundColor: C.teal }} />
        <h4 className="text-sm font-semibold mb-1.5" style={{ color: C.offWhite }}>{title}</h4>
        <p className="text-xs leading-relaxed" style={{ color: C.muted }}>{text}</p>
      </div>
    </Reveal>
  );
}

/* ── Step Card ───────────────────────────────────────── */
function StepCard({ num, title, text, delay }: { num: number; title: string; text: string; delay: number }) {
  return (
    <Reveal delay={delay}>
      <div className="flex-1 text-center p-5">
        <div className="w-10 h-10 rounded-full mx-auto mb-3 flex items-center justify-center text-sm font-semibold animate-[sparkPulse_3s_ease-in-out_infinite]"
          style={{
            backgroundColor: `${C.teal}12`,
            color: C.teal,
            border: `1px solid ${C.teal}30`,
            animationDelay: `${num * 0.6}s`,
          }}>
          {num}
        </div>
        <h4 className="text-sm font-semibold mb-1" style={{ color: C.offWhite }}>{title}</h4>
        <p className="text-xs" style={{ color: C.muted }}>{text}</p>
      </div>
    </Reveal>
  );
}

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
      style={{ color: C.muted, opacity: dim ? 0.4 : 1 }}>
      {text}
    </span>
  );
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
    const x = ((e.clientX - cx) / rect.width) * -20;
    const y = ((e.clientY - cy) / rect.height) * -15;
    setMouseOffset({ x, y });
  }, []);

  // Cursor glow
  const [glowPos, setGlowPos] = useState({ x: 0, y: 0 });
  const handleGlobalMove = useCallback((e: React.MouseEvent) => {
    setGlowPos({ x: e.clientX, y: e.clientY });
  }, []);

  return (
    <main className="flex-1 relative" onMouseMove={handleGlobalMove}>
      {/* Cursor glow */}
      <div className="pointer-events-none fixed inset-0 z-0 transition-opacity duration-300"
        style={{
          background: `radial-gradient(600px circle at ${glowPos.x}px ${glowPos.y}px, ${C.teal}06, transparent 60%)`,
        }} />

      {/* ── Hero ──────────────────────────────────────── */}
      <section ref={heroRef} className="relative overflow-hidden" onMouseMove={handleMouseMove}>
        <div className="max-w-5xl mx-auto px-6 py-24 md:py-32 flex flex-col items-center text-center relative z-10">
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <ShieldGraphic offsetX={mouseOffset.x} offsetY={mouseOffset.y} />
          </div>
          <div className="relative z-10">
            <h1 className="text-3xl md:text-5xl font-semibold leading-tight tracking-tight mb-6"
              style={{ color: C.offWhite }}>
              Kennen Sie Ihre<br />
              <GlitchText className="inline-block">{'\u00ADAngriffsoberfl\u00e4che'}</GlitchText>
              <span style={{ color: C.teal }}>?</span>
            </h1>
            <p className="text-base md:text-lg max-w-2xl mx-auto mb-10 leading-relaxed"
              style={{ color: C.muted }}>
              VectiScan analysiert Ihre gesamte IT-Infrastruktur automatisiert auf Schwachstellen.
              Regelmäßig, zuverlässig und nach anerkannten Standards — damit Sie wissen,
              wo Sie stehen, bevor es ein Angreifer tut.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link href="/pricing"
                className="px-7 py-3 rounded-lg text-sm font-medium transition-all hover:shadow-[0_0_20px_#2DD4BF30]"
                style={{ backgroundColor: C.teal, color: C.slate }}>
                Angebot anfordern
              </Link>
              <Link href="/pricing#pakete"
                className="px-7 py-3 rounded-lg text-sm font-medium transition-all hover:bg-[#2DD4BF10]"
                style={{ color: C.teal, border: `1px solid ${C.teal}40` }}>
                Pakete vergleichen
              </Link>
            </div>
          </div>
        </div>

        {/* Trust Bar */}
        <div className="border-t border-b py-4" style={{ borderColor: C.borderSubtle }}>
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
      <section className="py-20 md:py-24" style={{ backgroundColor: `${C.slateLight}40` }}>
        <div className="max-w-5xl mx-auto px-6">
          <Reveal>
            <h2 className="text-2xl md:text-3xl font-semibold text-center mb-4" style={{ color: C.offWhite }}>
              Automatisierte Security-Analyse.<br />Regelmäßig. Zuverlässig.
            </h2>
            <p className="text-sm text-center max-w-2xl mx-auto mb-12" style={{ color: C.muted }}>
              VectiScan kombiniert etablierte Open-Source-Scanner mit KI-gestützter
              Analyse zu einem vollautomatisierten Security-Assessment.
            </p>
          </Reveal>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <FeatureCard delay={0} title="Perimeter-Analyse"
              text="Port-Scanning, DNS-Enumeration, Web-Schwachstellen, SSL/TLS-Prüfung — über 15 spezialisierte Scanner analysieren Ihre gesamte Angriffsoberfläche." />
            <FeatureCard delay={80} title="KI-gestützte Bewertung"
              text="Intelligente Korrelation über Tool-Grenzen hinweg. False-Positive-Filterung und kontextbezogene Risikobewertung nach CVSS v3.1." />
            <FeatureCard delay={160} title="Professionelle Reports"
              text="Executive Summary für die Geschäftsleitung, technische Details für Ihr IT-Team, priorisierter Maßnahmenplan mit konkreten Handlungsempfehlungen." />
            <FeatureCard delay={240} title="Automatische Wiederholung"
              text="Wöchentliche, monatliche oder quartalsweise Scans — Sie definieren den Rhythmus, wir liefern zuverlässig aktuelle Ergebnisse." />
            <FeatureCard delay={320} title="Compliance-Nachweise"
              text="Mappings auf NIS2 (§30 BSIG), BSI-Grundschutz, ISO 27001 und Cyberversicherungs-Anforderungen — direkt im Report." />
            <FeatureCard delay={400} title="Qualitätsgesichert"
              text="Jeder Report wird vor der Zustellung manuell geprüft. False Positives werden markiert, Befunde validiert — keine automatisierten Fehlalarme." />
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
            <Reveal delay={0}>
              <div className="rounded-xl p-6 relative h-full hover:border-[#2DD4BF25] transition-colors duration-300"
                style={{ backgroundColor: C.slateLight, border: `1px solid ${C.border}` }}>
                <span className="absolute -top-2.5 left-5 text-[10px] font-semibold px-2.5 py-0.5 rounded-full"
                  style={{ backgroundColor: `${C.teal}20`, color: C.teal }}>Empfohlen</span>
                <h3 className="text-lg font-semibold mt-2 mb-1" style={{ color: C.offWhite }}>Perimeter-Scan</h3>
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
              <div className="rounded-xl p-6 h-full hover:border-[#2DD4BF25] transition-colors duration-300"
                style={{ backgroundColor: C.slateLight, border: `1px solid ${C.borderSubtle}` }}>
                <h3 className="text-lg font-semibold mt-2 mb-1" style={{ color: C.offWhite }}>Cyberversicherung</h3>
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

      {/* ── How It Works ──────────────────────────────── */}
      <section className="py-20 md:py-24" style={{ backgroundColor: `${C.slateLight}40` }}>
        <div className="max-w-4xl mx-auto px-6">
          <Reveal>
            <h2 className="text-2xl md:text-3xl font-semibold text-center mb-12" style={{ color: C.offWhite }}>
              So funktioniert&apos;s
            </h2>
          </Reveal>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            <StepCard delay={0} num={1} title="Ziele definieren" text="Domains, IPs oder Subnetze — bis zu 30 Ziele pro Abo" />
            <StepCard delay={150} num={2} title="Automatisch scannen" text="Regelmäßige Scans im gewählten Intervall" />
            <StepCard delay={300} num={3} title="Report erhalten" text="Geprüfter PDF-Report per E-Mail" />
            <StepCard delay={450} num={4} title="Maßnahmen umsetzen" text="Priorisierter Plan mit konkreten Schritten" />
          </div>
        </div>
      </section>

      {/* ── Trust Section ─────────────────────────────── */}
      <section className="py-16">
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
      <section className="py-20 md:py-24">
        <div className="max-w-2xl mx-auto px-6 text-center">
          <Reveal>
            <h2 className="text-2xl md:text-3xl font-semibold mb-4" style={{ color: C.offWhite }}>
              Bereit für Ihren ersten Security-Scan?
            </h2>
            <p className="text-sm mb-8" style={{ color: C.muted }}>
              Lassen Sie sich ein individuelles Angebot erstellen — oder starten Sie direkt.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link href="/pricing"
                className="px-7 py-3 rounded-lg text-sm font-medium transition-all hover:shadow-[0_0_20px_#2DD4BF30]"
                style={{ backgroundColor: C.teal, color: C.slate }}>
                Angebot anfordern
              </Link>
              <Link href="/subscribe"
                className="px-7 py-3 rounded-lg text-sm font-medium transition-colors hover:bg-[#1E293B80]"
                style={{ color: C.muted, border: `1px solid ${C.borderSubtle}` }}>
                Direkt Abo starten
              </Link>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ── Footer ────────────────────────────────────── */}
      <footer className="border-t py-8 px-6" style={{ borderColor: C.borderSubtle }}>
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

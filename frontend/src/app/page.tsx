'use client';

import { useState, useEffect, useRef, useCallback, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { VectiScanShield } from '@/components/VectiScanLogo';
import { isLoggedIn } from '@/lib/auth';
import { track } from '@/lib/analytics';
import { getTier, formatEur } from '@/lib/pricing';
import { webcheckCtaHref, webcheckCtaLabel } from '@/lib/webcheck';
import { PACKAGE_CATALOG } from '@/lib/catalog.generated';

const C = {
  slate: '#0F172A', slateLight: '#1E293B', teal: '#2DD4BF', tealDark: '#14B8A6',
  offWhite: '#F8FAFC', muted: '#94A3B8', mutedLight: '#CBD5E1',
};

/* ── Hooks ────────────────────────────────────────────────── */
// WCAG 2.2.2: respektiert die Betriebssystem-Einstellung „reduzierte Bewegung"
// für die JS-getriebenen Animationen (CSS-Seite deckt globals.css ab).
function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setReduced(mq.matches);
    update();
    mq.addEventListener('change', update);
    return () => mq.removeEventListener('change', update);
  }, []);
  return reduced;
}

function useReveal(threshold = 0.1) {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const el = ref.current; if (!el) return;
    const obs = new IntersectionObserver(([e]) => { if (e.isIntersecting) { setVisible(true); obs.disconnect(); } }, { threshold });
    obs.observe(el); return () => obs.disconnect();
  }, [threshold]);
  return { ref, visible };
}

function Reveal({ children, delay = 0 }: { children: React.ReactNode; delay?: number }) {
  const { ref, visible } = useReveal();
  return <div ref={ref} className="transition-all duration-700 ease-out"
    style={{ opacity: visible ? 1 : 0, transform: visible ? 'translateY(0)' : 'translateY(20px)', transitionDelay: `${delay}ms` }}>{children}</div>;
}

function useGlitch() {
  const reduced = usePrefersReducedMotion();
  const [on, setOn] = useState(false);
  useEffect(() => {
    // Hero-Glitch ist dezent und bei reduzierter Bewegung komplett aus
    // (Security-Marke: kein hektisches Flackern, WCAG 2.2.2).
    if (reduced) { setOn(false); return; }
    let t: ReturnType<typeof setTimeout>;
    const fire = () => { setOn(true); setTimeout(() => setOn(false), 50); t = setTimeout(fire, 9000 + Math.random() * 12000); };
    t = setTimeout(fire, 4000 + Math.random() * 6000);
    return () => clearTimeout(t);
  }, [reduced]);
  return on;
}

function OrderIdRedirect() {
  const router = useRouter(); const sp = useSearchParams();
  useEffect(() => {
    const id = sp.get('orderId');
    if (id) { router.replace(`/scan?orderId=${id}`); return; }
    // Eingeloggte User → Dashboard statt Landing Page
    if (isLoggedIn()) { router.replace('/dashboard'); }
  }, [sp, router]);
  return null;
}

/* ── Cursor Glow (full page, very subtle) ─────────────── */
function CursorGlow() {
  const reduced = usePrefersReducedMotion();
  const [pos, setPos] = useState({ x: -1000, y: -1000 });
  useEffect(() => {
    if (reduced) return;
    const h = (e: MouseEvent) => setPos({ x: e.clientX, y: e.clientY });
    window.addEventListener('mousemove', h); return () => window.removeEventListener('mousemove', h);
  }, [reduced]);
  if (reduced) return null;
  return <div className="pointer-events-none fixed inset-0 z-0"
    style={{ background: `radial-gradient(800px circle at ${pos.x}px ${pos.y}px, ${C.teal}05, transparent 50%)` }} />;
}

/* ── Hero Shield with lerp parallax ───────────────────── */
function HeroShield({ containerRef }: { containerRef: React.RefObject<HTMLElement | null> }) {
  const reduced = usePrefersReducedMotion();
  const [tilt, setTilt] = useState({ x: 0, y: 0 });
  const [isTouch, setIsTouch] = useState(false);
  const target = useRef({ x: 0, y: 0 });
  const current = useRef({ x: 0, y: 0 });
  const raf = useRef(0);
  const noParallax = isTouch || reduced;

  useEffect(() => { setIsTouch('ontouchstart' in window || navigator.maxTouchPoints > 0); }, []);

  useEffect(() => {
    if (noParallax) return;
    const onMove = (e: MouseEvent) => {
      const el = containerRef.current; if (!el) return;
      const r = el.getBoundingClientRect();
      if (e.clientY < r.top || e.clientY > r.bottom) { target.current = { x: 0, y: 0 }; return; }
      const nx = ((e.clientX - r.left) / r.width - 0.5) * 2;
      const ny = ((e.clientY - r.top) / r.height - 0.5) * 2;
      target.current = { x: ny * -8, y: nx * 8 };
    };
    const onLeave = () => { target.current = { x: 0, y: 0 }; };
    const animate = () => {
      current.current.x += (target.current.x - current.current.x) * 0.08;
      current.current.y += (target.current.y - current.current.y) * 0.08;
      setTilt({ x: current.current.x, y: current.current.y });
      raf.current = requestAnimationFrame(animate);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseleave', onLeave);
    raf.current = requestAnimationFrame(animate);
    return () => { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseleave', onLeave); cancelAnimationFrame(raf.current); };
  }, [noParallax, containerRef]);

  return (
    <div className="absolute inset-0 flex items-center justify-center pointer-events-none" style={{ perspective: '1000px' }}>
      {/* Teal glow behind shield */}
      <div className="absolute w-[300px] h-[300px] sm:w-[450px] sm:h-[450px] rounded-full"
        style={{ background: `radial-gradient(circle, ${C.teal}0A 0%, transparent 70%)`, filter: 'blur(40px)' }} />
      <div style={{ transform: noParallax ? 'none' : `rotateX(${tilt.x}deg) rotateY(${tilt.y}deg)`, willChange: 'transform' }}>
        <svg viewBox="0 0 200 210" fill="none" aria-hidden="true"
          className="w-[280px] h-[294px] sm:w-[400px] sm:h-[420px] md:w-[500px] md:h-[525px] opacity-[0.12]">
          <path d="M100 8 L178 48 L178 116 C178 156 144 186 100 200 C56 186 22 156 22 116 L22 48 Z"
            fill="none" stroke={C.teal} strokeWidth="3" className="shield-pulse" />
          <path d="M100 22 L166 56 L166 110 C166 146 138 174 100 186 C62 174 34 146 34 110 L34 56 Z"
            fill="none" stroke={C.teal} strokeWidth="5" opacity="0.6" />
          <path d="M70 74 L100 140 L130 74" fill="none" stroke={C.teal} strokeWidth="12"
            strokeLinecap="round" strokeLinejoin="round" opacity="0.5" />
        </svg>
      </div>
    </div>
  );
}

/* ── Icons ────────────────────────────────────────────── */
const I = {
  search: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>,
  alert: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  clipboard: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M16 4h2a2 2 0 012 2v14a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2h2"/><rect x="8" y="2" width="8" height="4" rx="1"/></svg>,
  target: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>,
  brain: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M12 2a4 4 0 014 4v2a4 4 0 01-8 0V6a4 4 0 014-4z"/><path d="M6 10v1a6 6 0 0012 0v-1"/><line x1="12" y1="17" x2="12" y2="21"/><line x1="8" y1="21" x2="16" y2="21"/></svg>,
  file: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/></svg>,
  refresh: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 014-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 01-4 4H3"/></svg>,
  shield: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>,
  lock: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M14 9V5a3 3 0 00-6 0v4"/><rect x="6" y="9" width="12" height="12" rx="2"/><circle cx="12" cy="15" r="1.5"/></svg>,
};

/* ── Steps ────────────────────────────────────────────── */
function StepSequence() {
  const reduced = usePrefersReducedMotion();
  const { ref, visible } = useReveal();
  const [active, setActive] = useState(-1);
  useEffect(() => {
    if (!visible) return;
    // Reduzierte Bewegung: keine Auto-Advance-Schleife, alle Schritte statisch sichtbar.
    if (reduced) { setActive(3); return; }
    const s = setTimeout(() => setActive(0), 400);
    const iv = setInterval(() => setActive(p => (p + 1) % 4), 3000);
    return () => { clearTimeout(s); clearInterval(iv); };
  }, [visible, reduced]);
  const steps = [
    { title: 'Ziele definieren', text: 'Domains, IPs oder Subnetze — bis zu 30 Ziele pro Abo' },
    { title: 'Automatisch scannen', text: 'Regelmäßige Scans im gewählten Intervall' },
    { title: 'Report erhalten', text: 'Geprüfter PDF-Report per E-Mail' },
    { title: 'Maßnahmen umsetzen', text: 'Priorisierter Plan mit konkreten Schritten' },
  ];
  return (
    <div ref={ref} className="max-w-3xl mx-auto">
      <div className="hidden md:flex items-center justify-between mb-10 px-8 relative">
        <div className="absolute left-8 right-8 top-1/2 h-0.5 -translate-y-1/2" style={{ backgroundColor: C.slateLight }} />
        <div className="absolute left-8 top-1/2 h-0.5 -translate-y-1/2 transition-all duration-700 ease-out"
          style={{ backgroundColor: C.teal, opacity: 0.6, width: active < 0 ? '0%' : `${(active / 3) * 100}%`, maxWidth: 'calc(100% - 4rem)' }} />
        {steps.map((_, i) => (
          <div key={i} className="relative z-10 w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all duration-500"
            style={{
              backgroundColor: i <= active ? C.teal : C.slateLight, color: i <= active ? C.slate : C.muted,
              boxShadow: i === active ? `0 0 16px ${C.teal}50` : 'none',
              animation: i === active ? 'stepPulse 2s ease-in-out infinite' : 'none',
            }}>
            {i < active ? '\u2713' : i + 1}
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {steps.map((s, i) => (
          <div key={i} className="text-center p-4 rounded-2xl transition-all duration-500"
            style={{ backgroundColor: i === active ? `${C.teal}08` : 'transparent' }}>
            <div className="md:hidden w-8 h-8 rounded-full mx-auto mb-3 flex items-center justify-center text-xs font-bold"
              style={{ backgroundColor: i <= active ? C.teal : C.slateLight, color: i <= active ? C.slate : C.muted }}>
              {i < active ? '\u2713' : i + 1}
            </div>
            <h4 className="text-sm font-semibold mb-1.5" style={{ color: i === active ? C.offWhite : i < active ? C.mutedLight : C.muted }}>{s.title}</h4>
            <p className="text-xs leading-relaxed" style={{ color: i === active ? C.muted : `${C.muted}80` }}>{s.text}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Trust Badge with flicker ─────────────────────────── */
function TrustBadge({ text, delay }: { text: string; delay: number }) {
  const reduced = usePrefersReducedMotion();
  const [dim, setDim] = useState(false);
  useEffect(() => {
    if (reduced) { setDim(false); return; }
    let t: ReturnType<typeof setTimeout>;
    const fire = () => { setDim(true); setTimeout(() => setDim(false), 200); t = setTimeout(fire, 5000 + Math.random() * 8000); };
    t = setTimeout(fire, delay + Math.random() * 5000);
    return () => clearTimeout(t);
  }, [delay, reduced]);
  return <span className="text-xs font-medium tracking-wide uppercase transition-opacity duration-200"
    style={{ color: C.muted, opacity: dim ? 0.3 : 1 }}>{text}</span>;
}

/* ── Main Page ───────────────────────────────────────────── */
export default function LandingPage() {
  const heroRef = useRef<HTMLElement>(null);
  const glitching = useGlitch();

  return (
    <main className="flex-1 relative">
      <CursorGlow />
      <Suspense><OrderIdRedirect /></Suspense>

      {/* ── Background gradients (subtle, decorative) ── */}
      <div className="fixed inset-0 pointer-events-none z-0" aria-hidden="true">
        {/* Top-right teal wash */}
        <div className="absolute -top-32 -right-32 w-[600px] h-[600px] rounded-full"
          style={{ background: `radial-gradient(circle, ${C.teal}06 0%, transparent 60%)`, filter: 'blur(80px)' }} />
        {/* Bottom-left accent */}
        <div className="absolute -bottom-48 -left-48 w-[500px] h-[500px] rounded-full"
          style={{ background: `radial-gradient(circle, ${C.teal}04 0%, transparent 60%)`, filter: 'blur(100px)' }} />
        {/* Mid-page subtle highlight */}
        <div className="absolute top-[60%] right-[10%] w-[400px] h-[400px] rounded-full"
          style={{ background: `radial-gradient(circle, ${C.tealDark}03 0%, transparent 60%)`, filter: 'blur(120px)' }} />
      </div>

      {/* ── HERO ──────────────────────────────────── */}
      <section ref={heroRef} className="relative overflow-hidden min-h-[90vh] flex items-center justify-center">
        <HeroShield containerRef={heroRef} />
        <div className="relative z-10 max-w-4xl mx-auto px-6 text-center">
          <p className="text-xs sm:text-sm uppercase tracking-[0.25em] mb-4 sm:mb-6 font-medium" style={{ color: C.teal }}>
            Automatisierte Schwachstellen-Scans nach PTES
          </p>
          <h1 className="text-[2rem] sm:text-4xl md:text-5xl lg:text-7xl font-bold leading-[1.1] tracking-tight mb-4 sm:mb-5" style={{ color: C.offWhite }}>
            Kennen Sie Ihre<br />
            <span style={{ color: C.teal, textShadow: glitching ? '1px 0 #2DD4BF, -1px 0 #3B82F6' : 'none' }}>Angriffsoberfläche</span>?
          </h1>
          <p className="text-lg sm:text-xl md:text-2xl font-normal mb-3" style={{ color: C.teal }}>
            Finden, bevor es andere tun.
          </p>
          <p className="text-[15px] sm:text-base max-w-xl mx-auto mb-6 sm:mb-8 leading-relaxed font-light" style={{ color: C.muted }}>
            VectiScan analysiert Ihre exponierte IT-Infrastruktur automatisiert auf Schwachstellen — regelmäßig, zuverlässig, nach anerkannten Standards. Damit Sie Lücken schließen, bevor sie ausgenutzt werden.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link href={webcheckCtaHref()} onClick={() => track('webcheck_cta_click', { surface: 'home_hero' })}
              className="w-full sm:w-auto px-8 py-4 rounded-lg text-sm font-semibold transition-all duration-300 hover:scale-[1.02] cta-glow text-center"
              style={{ backgroundColor: C.teal, color: C.slate }}>{webcheckCtaLabel()}</Link>
            <Link href="/demo" className="w-full sm:w-auto px-8 py-4 rounded-lg text-sm font-medium transition-all duration-300 hover:border-[#2DD4BF60] text-center"
              style={{ color: C.offWhite, border: '1px solid rgba(45,212,191,0.25)' }}>Demo anfragen</Link>
          </div>
          <p className="text-xs mt-4 font-light" style={{ color: `${C.muted}B0` }}>
            Kostenlos · ohne Kreditkarte · Ergebnis in ~15&nbsp;Minuten
          </p>
        </div>
      </section>

      {/* ── TRUST BAR ─────────────────────────────── */}
      <div className="border-t border-b py-4 relative z-10" style={{ borderColor: 'rgba(45,212,191,0.08)' }}>
        <div className="max-w-4xl mx-auto flex flex-wrap items-center justify-center gap-x-6 sm:gap-x-8 gap-y-2 px-4">
          {['BSI-Grundschutz-Mapping', 'PTES-konform', 'CVSS v3.1', 'DSGVO-konform', 'Hosting in DE'].map((t, i) =>
            <TrustBadge key={t} text={t} delay={i * 1000} />)}
        </div>
      </div>

      {/* ── PAIN SECTION ──────────────────────────── */}
      <section className="py-12 md:py-20 relative z-10">
        <div className="max-w-5xl mx-auto px-6">
          <Reveal>
            <h2 className="text-[1.4rem] sm:text-2xl md:text-3xl font-semibold text-center mb-4" style={{ color: C.offWhite }}>Wissen Sie, wie angreifbar Ihr Unternehmen ist?</h2>
            <p className="text-sm text-center max-w-2xl mx-auto mb-12" style={{ color: C.muted }}>Die meisten Unternehmen kennen nur einen Bruchteil ihrer exponierten Systeme. Angreifer kennen sie alle.</p>
          </Reveal>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { icon: I.search, title: 'Unbekannte Angriffsoberfläche', text: 'Vergessene Subdomains, Testserver, offene Ports — Ihre externe IT-Landschaft ist größer als Sie denken. Jeder exponierte Dienst ist ein potenzielles Einfallstor.' },
              { icon: I.alert, title: 'Veraltete Software', text: 'End-of-Life Betriebssysteme, fehlende Patches, bekannte CVEs — Schwachstellen, die seit Monaten öffentlich dokumentiert sind und aktiv ausgenutzt werden.' },
              { icon: I.clipboard, title: 'Compliance-Druck', text: 'NIS2, BSI-Grundschutz, Cyberversicherungen — alle fordern regelmäßige Nachweise Ihrer IT-Sicherheit. Ohne belastbaren Nachweis riskieren Sie Bußgelder und Versicherungslücken.' },
            ].map(({ icon, title, text }, i) => (
              <Reveal key={title} delay={i * 120}><div className="p-6 rounded-2xl h-full" style={{ backgroundColor: C.slateLight }}>
                <div className="mb-3" style={{ color: C.teal }}>{icon}</div>
                <h3 className="text-base font-semibold mb-2" style={{ color: C.offWhite }}>{title}</h3>
                <p className="text-sm leading-relaxed" style={{ color: C.muted }}>{text}</p>
              </div></Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ── FEATURES ──────────────────────────────── */}
      <section className="py-12 md:py-20 relative z-10" style={{ backgroundColor: `${C.slateLight}30` }}>
        <div className="max-w-5xl mx-auto px-6">
          <Reveal>
            <h2 className="text-[1.4rem] sm:text-2xl md:text-3xl font-semibold text-center mb-4" style={{ color: C.offWhite }}>Automatisierte Perimeter-Analyse.<br className="hidden sm:block" />Regelmäßig. Zuverlässig.</h2>
            <p className="text-sm text-center max-w-2xl mx-auto mb-12" style={{ color: C.muted }}>VectiScan kombiniert etablierte Open-Source-Scanner mit KI-gestützter Analyse zu einem vollautomatisierten Perimeter-Assessment.</p>
          </Reveal>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              { icon: I.target, title: 'Perimeter-Analyse', text: 'Port-Scanning, DNS-Enumeration, Web-Schwachstellen, SSL/TLS-Prüfung — über 20 spezialisierte Scanner analysieren Ihre externe Angriffsoberfläche.' },
              { icon: I.brain, title: 'KI-gestützte Bewertung', text: 'Intelligente Korrelation über Tool-Grenzen hinweg. False-Positive-Filterung und kontextbezogene Risikobewertung nach CVSS v3.1.' },
              { icon: I.file, title: 'Professionelle Reports', text: 'Executive Summary für die Geschäftsleitung, technische Details für Ihr IT-Team, priorisierter Maßnahmenplan mit konkreten Handlungsempfehlungen.' },
              { icon: I.refresh, title: 'Automatische Wiederholung', text: 'Wöchentliche, monatliche oder quartalsweise Scans — Sie definieren den Rhythmus, wir liefern zuverlässig aktuelle Ergebnisse.' },
              { icon: I.shield, title: 'Compliance-Nachweise', text: 'Mappings auf NIS2 (§30 BSIG), BSI-Grundschutz, ISO 27001 und Cyberversicherungs-Anforderungen — direkt im Report.' },
              { icon: I.lock, title: 'Qualitätsgesichert', text: 'Jeder Report wird vor der Zustellung manuell geprüft. False Positives werden markiert, Befunde validiert — keine automatisierten Fehlalarme.' },
            ].map(({ icon, title, text }, i) => (
              <Reveal key={title} delay={i * 100}><div className="p-5 rounded-2xl h-full group transition-all duration-300 hover:shadow-[0_0_30px_#2DD4BF08]"
                style={{ backgroundColor: C.slateLight, border: '1px solid rgba(45,212,191,0.06)' }}>
                <div className="mb-3 opacity-70 group-hover:opacity-100 transition-opacity duration-300" style={{ color: C.teal }}>{icon}</div>
                <h4 className="text-sm font-semibold mb-1.5" style={{ color: C.offWhite }}>{title}</h4>
                <p className="text-xs leading-relaxed" style={{ color: C.muted }}>{text}</p>
              </div></Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ── INTERSTITIAL ──────────────────────────── */}
      <section className="py-16 md:py-28 relative z-10">
        <div className="absolute left-1/2 -translate-x-1/2 top-8 w-16 h-px" style={{ backgroundColor: `${C.teal}18` }} />
        <Reveal><p className="text-[1.4rem] sm:text-2xl md:text-3xl font-semibold text-center leading-snug px-6" style={{ color: C.offWhite }}>
          Sicherheit ist kein Gefühl.<br /><span style={{ color: C.teal }}>Sondern ein Ergebnis.</span>
        </p></Reveal>
        <div className="absolute left-1/2 -translate-x-1/2 bottom-8 w-16 h-px" style={{ backgroundColor: `${C.teal}18` }} />
      </section>

      {/* ── PACKAGES ──────────────────────────────── */}
      <section className="py-12 md:py-20 relative z-10">
        <div className="max-w-5xl mx-auto px-6">
          <Reveal><h2 className="text-[1.4rem] sm:text-2xl md:text-3xl font-semibold text-center mb-12" style={{ color: C.offWhite }}>Vom kostenlosen Schnell-Check zum Vollscan.</h2></Reveal>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {PACKAGE_CATALOG.map((pkg, i) => {
              const tier = getTier(pkg.key);
              const isWebcheck = pkg.key === 'webcheck';
              const isSelfService = pkg.sellability === 'self_service';
              const ctaLabel = isWebcheck ? webcheckCtaLabel() : isSelfService ? 'Jetzt kaufen' : 'Angebot anfragen';
              const ctaHref = isWebcheck ? webcheckCtaHref() : isSelfService ? '/subscribe' : '/contact';
              const ctaPrimary = isSelfService;
              const priceLabel = isWebcheck ? 'Kostenlos' : tier?.priceEur != null ? `ab ${formatEur(tier.priceEur)} / Jahr` : 'Auf Anfrage';
              const priceNote = tier?.billingNote ?? '';
              return (
                <Reveal key={pkg.key} delay={i * 100}>
                  <div className="rounded-2xl p-6 relative h-full flex flex-col transition-all duration-300 hover:shadow-[0_0_40px_#2DD4BF06]"
                    style={{ backgroundColor: C.slateLight, border: isSelfService ? `1px solid ${pkg.accentColor}40` : '1px solid rgba(45,212,191,0.06)' }}>
                    {pkg.badge && (
                      <span className="absolute -top-2.5 left-5 text-[10px] font-semibold px-2.5 py-0.5 rounded-full"
                        style={{ backgroundColor: `${pkg.accentColor}25`, color: pkg.accentColor }}>
                        {pkg.badge}
                      </span>
                    )}
                    <h3 className="text-lg font-semibold mt-2 mb-1" style={{ color: C.offWhite }}>{pkg.marketingName}</h3>
                    <p className="text-xs mb-4" style={{ color: C.muted }}>{pkg.subtitle}</p>
                    <ul className="space-y-2 mb-5 flex-1">
                      {pkg.reportFocus.map(f => (
                        <li key={f} className="flex items-start gap-2 text-xs" style={{ color: C.mutedLight }}>
                          <span style={{ color: pkg.accentColor }} className="mt-0.5">&#x2713;</span> {f}
                        </li>
                      ))}
                    </ul>
                    <div className="mb-4">
                      <p className="text-sm font-semibold" style={{ color: C.offWhite }}>{priceLabel}</p>
                      <p className="text-[11px]" style={{ color: C.muted }}>{priceNote}</p>
                    </div>
                    <Link href={ctaHref}
                      onClick={isWebcheck ? () => track('webcheck_cta_click', { surface: 'home_packages' }) : undefined}
                      className="block w-full text-center px-5 py-2.5 rounded-lg text-sm font-medium transition-all duration-300"
                      style={ctaPrimary
                        ? { backgroundColor: pkg.accentColor, color: C.slate }
                        : { color: C.offWhite, border: '1px solid rgba(45,212,191,0.25)' }}>
                      {ctaLabel}
                    </Link>
                  </div>
                </Reveal>
              );
            })}
          </div>
          <Reveal delay={200}><div className="text-center mt-8"><Link href="/pricing" onClick={() => track('webcheck_pricing_click', { surface: 'home_packages' })} className="text-sm font-medium hover:underline" style={{ color: C.teal }}>Alle Details und Preise vergleichen &#8594;</Link></div></Reveal>
        </div>
      </section>

      {/* ── STEPS ─────────────────────────────────── */}
      <section className="py-12 md:py-24 relative z-10" style={{ backgroundColor: `${C.slateLight}30` }}>
        <div className="max-w-5xl mx-auto px-6">
          <Reveal><h2 className="text-[1.4rem] sm:text-2xl md:text-3xl font-semibold text-center mb-12 md:mb-16" style={{ color: C.offWhite }}>So funktioniert&apos;s</h2></Reveal>
          <StepSequence />
        </div>
      </section>

      {/* ── SOCIAL PROOF (ehrlich, ohne erfundene Zahlen) ── */}
      <section className="py-12 md:py-20 relative z-10">
        <div className="max-w-4xl mx-auto px-6">
          <Reveal><div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
            {[
              { stat: 'Jeder Report', label: 'wird vor Zustellung manuell geprüft — keine automatischen Fehlalarme.' },
              { stat: '~15 Min', label: 'bis zum WebCheck-Ergebnis Ihrer Domain.' },
              { stat: '20+ Scanner', label: 'kombiniert mit KI-gestützter Korrelation nach CVSS v3.1.' },
            ].map(s => (
              <div key={s.stat} className="p-5 rounded-2xl text-center h-full" style={{ backgroundColor: C.slateLight, border: '1px solid rgba(45,212,191,0.06)' }}>
                <p className="text-xl font-semibold mb-1" style={{ color: C.teal }}>{s.stat}</p>
                <p className="text-xs leading-relaxed" style={{ color: C.muted }}>{s.label}</p>
              </div>
            ))}
          </div></Reveal>
          {process.env.NEXT_PUBLIC_SAMPLE_REPORT_URL && (
            <Reveal delay={120}><div className="text-center">
              <a href={process.env.NEXT_PUBLIC_SAMPLE_REPORT_URL} target="_blank" rel="noopener noreferrer"
                className="inline-flex items-center gap-2 text-sm font-medium hover:underline" style={{ color: C.teal }}>
                So sieht Ihr Report aus — Beispiel-Report ansehen &#8594;
              </a>
            </div></Reveal>
          )}
        </div>
      </section>

      {/* ── TRUST ─────────────────────────────────── */}
      <section className="py-12 md:py-16 relative z-10">
        <div className="max-w-4xl mx-auto px-6">
          <p className="text-[10px] text-center uppercase tracking-widest mb-6" style={{ color: C.muted }}>Standards &amp; Technologie</p>
          <div className="flex flex-wrap items-center justify-center gap-x-6 sm:gap-x-8 gap-y-3">
            {['OWASP ZAP', 'Nmap', 'Nuclei', 'testssl.sh', 'Claude AI', 'PTES', 'CVSS v3.1', 'BSI TR-03116-4'].map(t =>
              <span key={t} className="text-xs font-light" style={{ color: `${C.muted}90` }}>{t}</span>)}
          </div>
          <p className="text-center mt-6 text-xs font-light" style={{ color: C.muted }}>Made in Germany — Entwicklung und Hosting in Deutschland</p>
        </div>
      </section>

      {/* ── FINAL CTA ─────────────────────────────── */}
      <section className="py-12 md:py-24 relative z-10">
        <Reveal><div className="max-w-2xl mx-auto px-6 text-center">
          <h2 className="text-[1.4rem] sm:text-2xl md:text-3xl font-semibold mb-4" style={{ color: C.offWhite }}>Bereit für Ihren ersten Security-Scan?</h2>
          <p className="text-sm mb-8 font-light" style={{ color: C.muted }}>Starten Sie mit dem kostenlosen WebCheck — oder buchen Sie direkt den Perimeter-Scan.</p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link href={webcheckCtaHref()} onClick={() => track('webcheck_cta_click', { surface: 'home_final_cta' })}
              className="w-full sm:w-auto px-8 py-3.5 rounded-lg text-sm font-semibold transition-all duration-300 cta-glow text-center"
              style={{ backgroundColor: C.teal, color: C.slate }}>{webcheckCtaLabel()}</Link>
            <Link href="/subscribe" className="w-full sm:w-auto px-8 py-3.5 rounded-lg text-sm font-medium transition-all duration-300 text-center"
              style={{ color: C.offWhite, border: '1px solid rgba(45,212,191,0.25)' }}>Direkt Abo starten</Link>
          </div>
          <p className="text-xs mt-5 font-light" style={{ color: C.muted }}>
            Lieber persönlich? <Link href="/demo" className="hover:underline" style={{ color: C.teal }}>Demo anfragen</Link>
          </p>
        </div></Reveal>
      </section>

      {/* ── FOOTER ────────────────────────────────── */}
      <footer className="border-t py-8 sm:py-10 px-6 relative z-10" style={{ borderColor: 'rgba(45,212,191,0.08)' }}>
        <div className="max-w-5xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 sm:gap-6">
          <div className="flex items-center gap-2.5">
            <VectiScanShield size={32} variant="teal" />
            <span className="text-sm font-bold tracking-tight" style={{ letterSpacing: '-0.5px' }}>
              <span style={{ color: C.offWhite }}>vecti</span><span style={{ color: C.teal }}>scan</span>
            </span>
          </div>
          <div className="flex items-center gap-6">
            <a href="mailto:support@vectiscan.de" className="text-xs font-light hover:text-white transition-colors" style={{ color: C.muted }}>Kontakt</a>
            <a href="/impressum" className="text-xs font-light hover:text-white transition-colors" style={{ color: C.muted }}>Impressum</a>
            <a href="/datenschutz" className="text-xs font-light hover:text-white transition-colors" style={{ color: C.muted }}>Datenschutz</a>
            <a href="/agb" className="text-xs font-light hover:text-white transition-colors" style={{ color: C.muted }}>AGB</a>
          </div>
          <p className="text-xs font-light" style={{ color: `${C.muted}60` }}>&copy; 2026 Vectigal GmbH</p>
        </div>
      </footer>
    </main>
  );
}

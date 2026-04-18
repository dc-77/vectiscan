'use client';

import { useState, useEffect, useRef, useCallback, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { VectiScanShield } from '@/components/VectiScanLogo';

const C = {
  slate: '#0F172A', slateLight: '#1E293B', teal: '#2DD4BF', tealDark: '#14B8A6',
  offWhite: '#F8FAFC', muted: '#94A3B8', mutedLight: '#CBD5E1',
};

/* ── Hooks ────────────────────────────────────────────────── */
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
    style={{ opacity: visible ? 1 : 0, transform: visible ? 'translateY(0)' : 'translateY(16px)', transitionDelay: `${delay}ms` }}>{children}</div>;
}

function OrderIdRedirect() {
  const router = useRouter(); const searchParams = useSearchParams();
  useEffect(() => { const id = searchParams.get('orderId'); if (id) router.replace(`/scan?orderId=${id}`); }, [searchParams, router]);
  return null;
}

/* ── Subtle cursor glow (full page, very faint) ──────────── */
function CursorGlow() {
  const [pos, setPos] = useState({ x: -1000, y: -1000 });
  useEffect(() => {
    const h = (e: MouseEvent) => setPos({ x: e.clientX, y: e.clientY });
    window.addEventListener('mousemove', h); return () => window.removeEventListener('mousemove', h);
  }, []);
  return <div className="pointer-events-none fixed inset-0 z-0 transition-opacity duration-500"
    style={{ background: `radial-gradient(800px circle at ${pos.x}px ${pos.y}px, ${C.teal}04, transparent 50%)` }} />;
}

/* ── SVG Icons ────────────────────────────────────────────── */
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

/* ── Steps ────────────────────────────────────────────────── */
function StepSequence() {
  const { ref, visible } = useReveal();
  const [active, setActive] = useState(-1);
  useEffect(() => {
    if (!visible) return;
    const s = setTimeout(() => setActive(0), 400);
    const iv = setInterval(() => setActive(p => (p + 1) % 4), 3000);
    return () => { clearTimeout(s); clearInterval(iv); };
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
        <div className="absolute left-8 right-8 top-1/2 h-0.5 -translate-y-1/2" style={{ backgroundColor: C.slateLight }} />
        <div className="absolute left-8 top-1/2 h-0.5 -translate-y-1/2 transition-all duration-700 ease-out"
          style={{ backgroundColor: C.teal, opacity: 0.6, width: active < 0 ? '0%' : `${(active / 3) * 100}%`, maxWidth: 'calc(100% - 4rem)' }} />
        {steps.map((_, i) => (
          <div key={i} className="relative z-10 w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all duration-500"
            style={{ backgroundColor: i <= active ? C.teal : C.slateLight, color: i <= active ? C.slate : C.muted, boxShadow: i === active ? `0 0 16px ${C.teal}50` : 'none' }}>
            {i < active ? '\u2713' : i + 1}
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {steps.map((s, i) => (
          <div key={i} className="text-center p-4 rounded-2xl transition-all duration-500"
            style={{ backgroundColor: i === active ? `${C.teal}08` : 'transparent' }}>
            <h4 className="text-sm font-semibold mb-1.5 transition-colors duration-500"
              style={{ color: i === active ? C.offWhite : i < active ? C.mutedLight : C.muted }}>{s.title}</h4>
            <p className="text-xs leading-relaxed transition-colors duration-500"
              style={{ color: i === active ? C.muted : `${C.muted}80` }}>{s.text}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Shared sections ─────────────────────────────────────── */
function PainSection() {
  const items = [
    { icon: I.search, title: 'Unbekannte Angriffsoberfläche', text: 'Vergessene Subdomains, Testserver, offene Ports — Ihre externe IT-Landschaft ist größer als Sie denken. Jeder exponierte Dienst ist ein potenzielles Einfallstor.' },
    { icon: I.alert, title: 'Veraltete Software', text: 'End-of-Life Betriebssysteme, fehlende Patches, bekannte CVEs — Schwachstellen, die seit Monaten öffentlich dokumentiert sind und aktiv ausgenutzt werden.' },
    { icon: I.clipboard, title: 'Compliance-Druck', text: 'NIS2, BSI-Grundschutz, Cyberversicherungen — alle fordern regelmäßige Nachweise Ihrer IT-Sicherheit. Ohne belastbare Dokumentation wird es teuer.' },
  ];
  return (
    <section className="py-20 md:py-24 relative z-10">
      <div className="max-w-5xl mx-auto px-6">
        <Reveal><h2 className="text-2xl md:text-3xl font-semibold text-center mb-4" style={{ color: C.offWhite }}>Wissen Sie, wie angreifbar Ihr Unternehmen ist?</h2>
          <p className="text-sm text-center max-w-2xl mx-auto mb-12" style={{ color: C.muted }}>Die meisten Unternehmen kennen nur einen Bruchteil ihrer exponierten Systeme. Angreifer kennen sie alle.</p></Reveal>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {items.map(({ icon, title, text }, i) => (
            <Reveal key={title} delay={i * 120}><div className="p-6 rounded-2xl h-full" style={{ backgroundColor: C.slateLight }}>
              <div className="mb-3" style={{ color: C.teal }}>{icon}</div>
              <h3 className="text-base font-semibold mb-2" style={{ color: C.offWhite }}>{title}</h3>
              <p className="text-sm leading-relaxed" style={{ color: C.muted }}>{text}</p>
            </div></Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

function FeaturesSection() {
  const items = [
    { icon: I.target, title: 'Perimeter-Analyse', text: 'Port-Scanning, DNS-Enumeration, Web-Schwachstellen, SSL/TLS-Prüfung — über 20 spezialisierte Scanner analysieren Ihre externe Angriffsoberfläche.' },
    { icon: I.brain, title: 'KI-gestützte Bewertung', text: 'Intelligente Korrelation über Tool-Grenzen hinweg. False-Positive-Filterung und kontextbezogene Risikobewertung nach CVSS v3.1.' },
    { icon: I.file, title: 'Professionelle Reports', text: 'Executive Summary für die Geschäftsleitung, technische Details für Ihr IT-Team, priorisierter Maßnahmenplan mit konkreten Handlungsempfehlungen.' },
    { icon: I.refresh, title: 'Automatische Wiederholung', text: 'Wöchentliche, monatliche oder quartalsweise Scans — Sie definieren den Rhythmus, wir liefern zuverlässig aktuelle Ergebnisse.' },
    { icon: I.shield, title: 'Compliance-Nachweise', text: 'Mappings auf NIS2 (§30 BSIG), BSI-Grundschutz, ISO 27001 und Cyberversicherungs-Anforderungen — direkt im Report.' },
    { icon: I.lock, title: 'Qualitätsgesichert', text: 'Jeder Report wird vor der Zustellung manuell geprüft. False Positives werden markiert, Befunde validiert — keine automatisierten Fehlalarme.' },
  ];
  return (
    <section className="py-20 md:py-24 relative z-10" style={{ backgroundColor: `${C.slateLight}40` }}>
      <div className="max-w-5xl mx-auto px-6">
        <Reveal><h2 className="text-2xl md:text-3xl font-semibold text-center mb-4" style={{ color: C.offWhite }}>Automatisierte Perimeter-Analyse.<br/>Regelmäßig. Zuverlässig.</h2>
          <p className="text-sm text-center max-w-2xl mx-auto mb-12" style={{ color: C.muted }}>VectiScan kombiniert etablierte Open-Source-Scanner mit KI-gestützter Analyse zu einem vollautomatisierten Perimeter-Assessment.</p></Reveal>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {items.map(({ icon, title, text }, i) => (
            <Reveal key={title} delay={i * 80}><div className="p-5 rounded-2xl h-full group hover:shadow-[0_0_30px_#2DD4BF06] transition-all duration-300" style={{ backgroundColor: C.slateLight }}>
              <div className="mb-3 opacity-80 group-hover:opacity-100 transition-opacity" style={{ color: C.teal }}>{icon}</div>
              <h4 className="text-sm font-semibold mb-1.5" style={{ color: C.offWhite }}>{title}</h4>
              <p className="text-xs leading-relaxed" style={{ color: C.muted }}>{text}</p>
            </div></Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

function PackagesSection() {
  const pkgs = [
    { name: 'Perimeter-Scan', sub: 'Vollständige Sicherheitsanalyse Ihrer externen Angriffsoberfläche', rec: true,
      features: ['Port-Scanning & Service-Erkennung', 'Web-Schwachstellen-Analyse (OWASP)', 'DNS- & E-Mail-Security-Prüfung', 'PTES-konformer Report mit Maßnahmenplan', 'NIS2/BSI-Compliance-Mapping'] },
    { name: 'Cyberversicherung', sub: 'Nachweis und Dokumentation für Ihren Versicherungsantrag', rec: false,
      features: ['Alles aus dem Perimeter-Scan', '10-Punkte Versicherungs-Fragebogen', 'Risk-Score & Ransomware-Indikator', 'Versicherungskonformer Nachweis-Report', 'Direkt einreichbar bei Ihrem Versicherer'] },
  ];
  return (
    <section className="py-20 md:py-24 relative z-10">
      <div className="max-w-4xl mx-auto px-6">
        <Reveal><h2 className="text-2xl md:text-3xl font-semibold text-center mb-12" style={{ color: C.offWhite }}>Zwei Pakete. Ein Ziel: Ihre Sicherheit.</h2></Reveal>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {pkgs.map((p, i) => (
            <Reveal key={p.name} delay={i * 120}><div className="rounded-2xl p-6 relative h-full transition-all duration-300 hover:shadow-[0_0_40px_#2DD4BF06]" style={{ backgroundColor: C.slateLight }}>
              {p.rec && <span className="absolute -top-2.5 left-5 text-[10px] font-semibold px-2.5 py-0.5 rounded-full" style={{ backgroundColor: `${C.teal}20`, color: C.teal }}>Empfohlen</span>}
              <h3 className="text-lg font-semibold mt-2 mb-1" style={{ color: C.offWhite }}>{p.name}</h3>
              <p className="text-xs mb-4" style={{ color: C.muted }}>{p.sub}</p>
              <ul className="space-y-2 mb-5">{p.features.map(f => <li key={f} className="flex items-start gap-2 text-xs" style={{ color: C.mutedLight }}><span style={{ color: C.teal }} className="mt-0.5">&#x2713;</span> {f}</li>)}</ul>
              <p className="text-xs font-medium" style={{ color: C.muted }}>Preis auf Anfrage</p>
            </div></Reveal>
          ))}
        </div>
        <Reveal delay={200}><div className="text-center mt-8"><Link href="/pricing" className="text-sm font-medium hover:underline" style={{ color: C.teal }}>Alle Details und Preise vergleichen &#8594;</Link></div></Reveal>
      </div>
    </section>
  );
}

function StepsSection() {
  return (
    <section className="py-20 md:py-28 relative z-10" style={{ backgroundColor: `${C.slateLight}40` }}>
      <div className="max-w-5xl mx-auto px-6">
        <Reveal><h2 className="text-2xl md:text-3xl font-semibold text-center mb-16" style={{ color: C.offWhite }}>So funktioniert&apos;s</h2></Reveal>
        <StepSequence />
      </div>
    </section>
  );
}

function TrustSection() {
  return (
    <section className="py-16 relative z-10">
      <div className="max-w-4xl mx-auto px-6">
        <p className="text-xs text-center uppercase tracking-widest mb-6" style={{ color: C.muted }}>Standards &amp; Technologie</p>
        <div className="flex flex-wrap items-center justify-center gap-x-8 gap-y-3">
          {['OWASP ZAP', 'Nmap', 'Nuclei', 'testssl.sh', 'Claude AI', 'PTES', 'CVSS v3.1', 'BSI TR-03116-4'].map(t =>
            <span key={t} className="text-xs font-light" style={{ color: `${C.muted}90` }}>{t}</span>)}
        </div>
        <p className="text-center mt-6 text-xs font-light" style={{ color: C.muted }}>Made in Germany — Entwicklung und Hosting in Deutschland</p>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="border-t py-10 px-6 relative z-10" style={{ borderColor: 'rgba(45,212,191,0.08)' }}>
      <div className="max-w-5xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-6">
        <div className="flex items-center gap-2.5">
          <VectiScanShield size={28} variant="teal" />
          <span className="text-sm font-bold tracking-tight" style={{ letterSpacing: '-0.5px' }}>
            <span style={{ color: C.offWhite }}>vecti</span><span style={{ color: C.teal }}>scan</span>
          </span>
        </div>
        <div className="flex items-center gap-6">
          <a href="mailto:kontakt@vectigal.gmbh" className="text-xs font-light hover:text-white transition-colors" style={{ color: C.muted }}>Kontakt</a>
          <a href="/impressum" className="text-xs font-light hover:text-white transition-colors" style={{ color: C.muted }}>Impressum</a>
          <a href="/datenschutz" className="text-xs font-light hover:text-white transition-colors" style={{ color: C.muted }}>Datenschutz</a>
        </div>
        <p className="text-xs font-light" style={{ color: `${C.muted}60` }}>&copy; 2026 Vectigal GmbH</p>
      </div>
    </footer>
  );
}

/* ════════════════════════════════════════════════════════════
   VARIANTE A — Bold / Direkt / "Bildzeitung"
   Große Headlines, starke Claims, klare CTAs
   ════════════════════════════════════════════════════════════ */
function VarianteA() {
  return (
    <>
      {/* Hero — bold, großes Shield im Hintergrund */}
      <section className="relative overflow-hidden min-h-[90vh] flex items-center justify-center">
        {/* Shield als Hintergrundelement */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <VectiScanShield size={500} variant="teal" className="opacity-[0.06]" />
        </div>
        <div className="relative z-10 max-w-4xl mx-auto px-6 text-center">
          <h1 className="text-5xl md:text-7xl font-bold leading-[1.1] tracking-tight mb-6" style={{ color: C.offWhite }}>
            Kennen Sie Ihre<br /><span style={{ color: C.teal }}>Angriffsoberfläche</span>?
          </h1>
          <p className="text-xl md:text-2xl font-normal mb-3" style={{ color: C.teal }}>
            Finden, bevor es andere tun.
          </p>
          <p className="text-base max-w-xl mx-auto mb-10 leading-relaxed" style={{ color: C.muted }}>
            VectiScan analysiert Ihre exponierte IT-Infrastruktur automatisiert auf Schwachstellen — regelmäßig, zuverlässig, nach anerkannten Standards.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link href="/pricing" className="px-8 py-4 rounded-lg text-sm font-semibold transition-all hover:shadow-[0_0_25px_#2DD4BF40] hover:scale-[1.02]"
              style={{ backgroundColor: C.teal, color: C.slate }}>Jetzt Angebot anfordern</Link>
            <Link href="/pricing#pakete" className="px-8 py-4 rounded-lg text-sm font-medium transition-all hover:border-[#2DD4BF60]"
              style={{ color: C.offWhite, border: '1px solid rgba(45,212,191,0.25)' }}>Pakete vergleichen</Link>
          </div>
        </div>
      </section>
      <div className="border-t border-b py-4 relative z-10" style={{ borderColor: 'rgba(45,212,191,0.08)' }}>
        <div className="max-w-4xl mx-auto flex flex-wrap items-center justify-center gap-x-8 gap-y-2 px-6">
          {['BSI-konform', 'PTES-Standard', 'CVSS v3.1', 'DSGVO-konform', 'Hosting in Deutschland'].map(t =>
            <span key={t} className="text-xs font-medium tracking-wide uppercase" style={{ color: C.muted }}>{t}</span>)}
        </div>
      </div>
      <PainSection />
      <FeaturesSection />
      <PackagesSection />
      {/* Interstitial */}
      <section className="py-28 md:py-32 relative z-10">
        <div className="absolute left-1/2 -translate-x-1/2 top-8 w-24 h-px" style={{ backgroundColor: `${C.teal}18` }} />
        <Reveal><p className="text-2xl md:text-3xl font-semibold text-center leading-snug px-6" style={{ color: C.offWhite }}>
          Sicherheit ist kein Gefühl.<br /><span style={{ color: C.teal }}>Sondern ein Ergebnis.</span>
        </p></Reveal>
        <div className="absolute left-1/2 -translate-x-1/2 bottom-8 w-24 h-px" style={{ backgroundColor: `${C.teal}18` }} />
      </section>
      <StepsSection />
      <TrustSection />
      {/* Final CTA */}
      <section className="py-20 md:py-28 relative z-10">
        <Reveal><div className="max-w-2xl mx-auto px-6 text-center">
          <h2 className="text-2xl md:text-3xl font-semibold mb-4" style={{ color: C.offWhite }}>Bereit für Ihren ersten Security-Scan?</h2>
          <p className="text-sm mb-8 font-light" style={{ color: C.muted }}>Lassen Sie sich ein individuelles Angebot erstellen — oder starten Sie direkt.</p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link href="/pricing" className="px-8 py-3.5 rounded-lg text-sm font-semibold transition-all hover:shadow-[0_0_20px_#2DD4BF30]"
              style={{ backgroundColor: C.teal, color: C.slate }}>Angebot anfordern</Link>
            <Link href="/subscribe" className="px-8 py-3.5 rounded-lg text-sm font-medium transition-all"
              style={{ color: C.offWhite, border: '1px solid rgba(45,212,191,0.25)' }}>Direkt Abo starten</Link>
          </div>
        </div></Reveal>
      </section>
    </>
  );
}

/* ════════════════════════════════════════════════════════════
   VARIANTE B — Subtil / Executive / "Quiet Confidence"
   Weniger Text, mehr Raum, Entscheider abholen.
   Für GFs die sich sicher fühlen wollen.
   ════════════════════════════════════════════════════════════ */
function VarianteB() {
  return (
    <>
      {/* Hero — ruhig, viel Weißraum, Shield als dezenter BG */}
      <section className="relative overflow-hidden min-h-[85vh] flex items-center justify-center">
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <VectiScanShield size={600} variant="teal" className="opacity-[0.035]" />
        </div>
        <div className="relative z-10 max-w-3xl mx-auto px-6 text-center">
          <p className="text-xs uppercase tracking-[0.3em] mb-8 font-medium" style={{ color: C.teal }}>
            Automatisierte Perimeter-Analyse
          </p>
          <h1 className="text-3xl md:text-5xl font-semibold leading-tight tracking-tight mb-8" style={{ color: C.offWhite }}>
            Wie sicher ist Ihre<br />IT-Infrastruktur wirklich?
          </h1>
          <p className="text-base max-w-lg mx-auto mb-12 leading-relaxed font-light" style={{ color: C.muted }}>
            VectiScan prüft Ihre exponierte Infrastruktur regelmäßig auf Schwachstellen — automatisiert, dokumentiert und nach BSI-Standards. Damit Sie Gewissheit haben.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link href="/pricing" className="px-8 py-3.5 rounded-lg text-sm font-medium transition-all hover:shadow-[0_0_20px_#2DD4BF20]"
              style={{ backgroundColor: C.teal, color: C.slate }}>Unverbindlich anfragen</Link>
            <Link href="/pricing#pakete" className="px-8 py-3.5 rounded-lg text-sm font-light transition-all hover:text-white"
              style={{ color: C.muted }}>Leistungen ansehen</Link>
          </div>
        </div>
      </section>

      {/* Subtler trust bar */}
      <div className="py-6 relative z-10">
        <div className="max-w-3xl mx-auto flex flex-wrap items-center justify-center gap-x-10 gap-y-2 px-6">
          {['BSI-konform', 'PTES', 'CVSS v3.1', 'DSGVO', 'Made in Germany'].map(t =>
            <span key={t} className="text-[10px] font-light tracking-widest uppercase" style={{ color: `${C.muted}70` }}>{t}</span>)}
        </div>
      </div>

      {/* Value proposition — less aggressive */}
      <section className="py-24 md:py-32 relative z-10">
        <div className="max-w-3xl mx-auto px-6">
          <Reveal>
            <p className="text-lg md:text-xl font-light leading-relaxed text-center" style={{ color: C.mutedLight }}>
              Die meisten Unternehmen wissen nicht, welche Systeme von außen erreichbar sind — und welche Schwachstellen dort schlummern. VectiScan macht das Unsichtbare sichtbar.
            </p>
          </Reveal>
        </div>
      </section>

      {/* Compact features — 3 columns, less text */}
      <section className="py-20 relative z-10">
        <div className="max-w-4xl mx-auto px-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              { icon: I.target, title: 'Analyse', text: 'Über 20 Scanner prüfen Ports, DNS, Web-Apps, E-Mail und SSL/TLS — vollautomatisch.' },
              { icon: I.file, title: 'Report', text: 'Professioneller PDF-Report mit Executive Summary, Maßnahmenplan und Compliance-Mapping.' },
              { icon: I.shield, title: 'Kontinuität', text: 'Regelmäßige Scans dokumentieren Ihren Sicherheitsstatus — für Aufsichtsräte, Versicherer und Auditoren.' },
            ].map(({ icon, title, text }, i) => (
              <Reveal key={title} delay={i * 100}>
                <div className="text-center">
                  <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl mb-4" style={{ backgroundColor: `${C.teal}08`, color: C.teal }}>{icon}</div>
                  <h3 className="text-sm font-semibold mb-2" style={{ color: C.offWhite }}>{title}</h3>
                  <p className="text-xs leading-relaxed font-light" style={{ color: C.muted }}>{text}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* Interstitial — quiet power */}
      <section className="py-32 md:py-40 relative z-10">
        <Reveal>
          <p className="text-xl md:text-2xl font-light text-center leading-relaxed px-6" style={{ color: C.mutedLight }}>
            Sicherheit ist kein Gefühl.<br />
            <span className="font-semibold" style={{ color: C.offWhite }}>Sondern ein Ergebnis.</span>
          </p>
        </Reveal>
      </section>

      {/* Packages — clean, less is more */}
      <section className="py-20 relative z-10">
        <div className="max-w-3xl mx-auto px-6">
          <Reveal><h2 className="text-xl font-semibold text-center mb-10" style={{ color: C.offWhite }}>Zwei Pakete</h2></Reveal>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {[
              { name: 'Perimeter-Scan', desc: 'Vollständige Analyse Ihrer externen Angriffsoberfläche mit professionellem Report und Maßnahmenplan.', rec: true },
              { name: 'Cyberversicherung', desc: 'Alles aus dem Perimeter-Scan plus Versicherungs-Fragebogen, Risk-Score und versicherungskonformer Nachweis.', rec: false },
            ].map((p, i) => (
              <Reveal key={p.name} delay={i * 100}>
                <div className="p-6 rounded-2xl h-full" style={{ backgroundColor: C.slateLight }}>
                  {p.rec && <p className="text-[10px] font-medium uppercase tracking-wider mb-3" style={{ color: C.teal }}>Empfohlen</p>}
                  <h3 className="text-base font-semibold mb-2" style={{ color: C.offWhite }}>{p.name}</h3>
                  <p className="text-sm font-light leading-relaxed mb-4" style={{ color: C.muted }}>{p.desc}</p>
                  <Link href="/pricing" className="text-xs font-medium hover:underline" style={{ color: C.teal }}>Details &amp; Preis &#8594;</Link>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      <StepsSection />
      <TrustSection />

      {/* Final CTA — understated */}
      <section className="py-24 md:py-32 relative z-10">
        <Reveal><div className="max-w-xl mx-auto px-6 text-center">
          <h2 className="text-xl font-semibold mb-4" style={{ color: C.offWhite }}>Lassen Sie uns sprechen.</h2>
          <p className="text-sm font-light mb-8" style={{ color: C.muted }}>Wir erstellen Ihnen ein individuelles Angebot — unverbindlich, innerhalb von 24 Stunden.</p>
          <Link href="/pricing" className="inline-block px-8 py-3.5 rounded-lg text-sm font-medium transition-all hover:shadow-[0_0_16px_#2DD4BF20]"
            style={{ backgroundColor: C.teal, color: C.slate }}>Angebot anfordern</Link>
        </div></Reveal>
      </section>
    </>
  );
}

/* ── Page Router ─────────────────────────────────────────── */
function PageContent() {
  const searchParams = useSearchParams();
  const variant = searchParams.get('v');
  return variant === 'b' ? <VarianteB /> : <VarianteA />;
}

export default function LandingPage() {
  return (
    <main className="flex-1 relative">
      <CursorGlow />
      <Suspense>
        <OrderIdRedirect />
        <PageContent />
      </Suspense>
      <Footer />
    </main>
  );
}

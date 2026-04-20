'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

import { createSubscription } from '@/lib/api';
import { isLoggedIn, getUser } from '@/lib/auth';

const DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const IPV4_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const MAX_HOSTS = 30;

// Valid dotted-decimal masks → CIDR prefix
const DOTTED_TO_CIDR: Record<string, number> = {
  '255.255.255.255': 32, '255.255.255.254': 31, '255.255.255.252': 30,
  '255.255.255.248': 29, '255.255.255.240': 28, '255.255.255.224': 27,
  '255.255.255.192': 26, '255.255.255.128': 25, '255.255.255.0': 24,
  '255.255.254.0': 23, '255.255.252.0': 22, '255.255.248.0': 21,
  '255.255.240.0': 20, '255.255.224.0': 19, '255.255.192.0': 18,
  '255.255.128.0': 17, '255.255.0.0': 16,
};

function isValidTarget(input: string): boolean {
  const s = input.trim();
  if (!s) return false;
  if (DOMAIN_REGEX.test(s)) return true;
  if (s.includes('/')) {
    const [ip, mask] = s.split('/', 2);
    if (!IPV4_REGEX.test(ip)) return false;
    if (/^\d{1,2}$/.test(mask)) { const n = parseInt(mask); return n >= 8 && n <= 32; }
    return IPV4_REGEX.test(mask) && mask in DOTTED_TO_CIDR;
  }
  if (IPV4_REGEX.test(s)) {
    return s.split('.').every(o => { const n = parseInt(o); return n >= 0 && n <= 255; });
  }
  return false;
}

/** Calculate number of hosts a target represents */
function countHosts(input: string): number {
  const s = input.trim();
  if (!s || !isValidTarget(s)) return 0;
  if (DOMAIN_REGEX.test(s)) return 1;
  if (s.includes('/')) {
    const [, mask] = s.split('/', 2);
    let prefix: number;
    if (/^\d{1,2}$/.test(mask)) {
      prefix = parseInt(mask);
    } else {
      prefix = DOTTED_TO_CIDR[mask] ?? 32;
    }
    return Math.pow(2, 32 - prefix);
  }
  return 1; // single IP
}

const PACKAGES = [
  {
    id: 'perimeter',
    name: 'Perimeter-Scan',
    subtitle: 'Vollständige Sicherheitsanalyse Ihrer Angriffsoberfläche',
    recommended: true,
    color: '#38BDF8',
    features: [
      'Vollständige Angriffsoberflächen-Analyse',
      'Port-Scanning, Web-Schwachstellen, DNS, E-Mail-Security',
      'PTES-konformer Report mit Executive Summary',
      'Priorisierter Massnahmenplan mit Zeitrahmen',
    ],
  },
  {
    id: 'insurance',
    name: 'Cyberversicherung',
    subtitle: 'Nachweis fur Ihren Versicherungsantrag',
    recommended: false,
    color: '#34D399',
    features: [
      'Alles aus dem Perimeter-Scan',
      '10-Punkte Versicherungs-Fragebogen',
      'Risk-Score und Ransomware-Indikator',
      'Nachweis fur Cyberversicherungsantrag',
    ],
  },
] as const;

const INTERVALS = [
  { id: 'weekly', label: 'Wöchentlich', desc: 'Scan jede Woche' },
  { id: 'monthly', label: 'Monatlich', desc: 'Scan jeden Monat' },
  { id: 'quarterly', label: 'Quartalsweise', desc: 'Scan alle 3 Monate' },
] as const;

const STEPS = ['Paket', 'Domains', 'E-Mail', 'Intervall', 'Zusammenfassung'];

function cleanDomain(input: string): string {
  let d = input.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '');
  d = d.replace(/\/.*$/, '');
  d = d.replace(/:\d+$/, '');
  d = d.replace(/\.$/, '');
  return d;
}

export default function SubscribePage() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [userEmail, setUserEmail] = useState('');

  const [step, setStep] = useState(1);
  const [selectedPackage, setSelectedPackage] = useState<string>('perimeter');
  const [domains, setDomains] = useState<string[]>(['']);
  const [reportEmails, setReportEmails] = useState<string[]>(['']);
  const [scanInterval, setScanInterval] = useState<string>('monthly');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    if (!isLoggedIn()) { router.replace('/login'); return; }
    const user = getUser();
    const email = user?.email || '';
    setUserEmail(email);
    setReportEmails([email]);
    setReady(true);
  }, [router]);

  const cleanedDomains = domains.map(cleanDomain).filter(d => d);
  const validDomains = cleanedDomains.filter(d => isValidTarget(d));
  const totalHosts = cleanedDomains.reduce((sum, d) => sum + countHosts(d), 0);
  const overLimit = totalHosts > MAX_HOSTS;
  const validEmails = reportEmails.filter(e => e.includes('@'));

  const canAdvance = () => {
    switch (step) {
      case 1: return !!selectedPackage;
      case 2: return validDomains.length > 0 && !overLimit;
      case 3: return validEmails.length > 0;
      case 4: return !!scanInterval;
      default: return true;
    }
  };

  const handleSubmit = async () => {
    setError(null);
    setSubmitting(true);
    try {
      const res = await createSubscription({
        package: selectedPackage,
        domains: validDomains,
        scanInterval,
        reportEmails: validEmails,
      });
      if (res.success) {
        setSuccess(res.data?.id || 'ok');
      } else {
        setError(res.error || 'Unbekannter Fehler');
      }
    } catch {
      setError('Verbindung zum Server fehlgeschlagen.');
    } finally {
      setSubmitting(false);
    }
  };

  if (!ready) return null;

  if (success) {
    return (
      <main className="flex-1 px-4 py-8 md:px-8">
        <div className="max-w-lg mx-auto text-center space-y-6">
          <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto">
            <svg className="w-8 h-8 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
          </div>
          <h1 className="text-xl font-semibold text-white">Abo erfolgreich erstellt</h1>
          <p className="text-sm text-gray-400">
            Ihre Domains werden jetzt von einem Administrator geprüft und freigegeben.
            Nach der Freigabe startet der erste Scan automatisch.
          </p>
          <Link href="/dashboard"
            className="inline-block bg-[#2DD4BF] hover:bg-[#14B8A6] text-[#0F172A] text-white font-medium px-6 py-3 rounded-lg transition-colors text-sm">
            Zum Dashboard
          </Link>
        </div>
      </main>
    );
  }

  return (
    <main className="flex-1 px-4 py-8 md:px-8">
      <div className="max-w-2xl mx-auto space-y-6">
        <h1 className="text-lg font-semibold text-white">Neues Abo erstellen</h1>

        {/* Step Indicator */}
        <div className="flex items-center gap-1">
          {STEPS.map((label, i) => {
            const stepNum = i + 1;
            const isActive = stepNum === step;
            const isDone = stepNum < step;
            return (
              <div key={label} className="flex items-center gap-1 flex-1">
                <div className={`flex items-center gap-1.5 ${isActive ? 'text-[#2DD4BF]' : isDone ? 'text-green-400' : 'text-slate-600'}`}>
                  <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium border ${
                    isActive ? 'border-[#2DD4BF] bg-[#2DD4BF]/10' : isDone ? 'border-green-400 bg-green-400/10' : 'border-slate-700'
                  }`}>
                    {isDone ? '\u2713' : stepNum}
                  </span>
                  <span className="text-xs hidden sm:inline">{label}</span>
                </div>
                {i < STEPS.length - 1 && <div className={`flex-1 h-px ${isDone ? 'bg-green-400/30' : 'bg-slate-700'}`} />}
              </div>
            );
          })}
        </div>

        {/* Error */}
        {error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">{error}</div>
        )}

        {/* Step 1: Package Selection */}
        {step === 1 && (
          <div className="space-y-3">
            <p className="text-sm text-gray-400">Wählen Sie Ihr Scan-Paket:</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {PACKAGES.map((pkg) => {
                const isSelected = selectedPackage === pkg.id;
                return (
                  <button key={pkg.id} onClick={() => setSelectedPackage(pkg.id)}
                    className={`text-left p-5 rounded-lg border-2 transition-all ${
                      isSelected
                        ? 'border-[#2DD4BF] bg-[#2DD4BF]/5'
                        : 'border-gray-800 bg-[#1e293b] hover:bg-[#253347] hover:border-gray-700'
                    }`}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-sm font-semibold text-white">{pkg.name}</span>
                      {pkg.recommended && (
                        <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-blue-500/20 text-[#2DD4BF]">Empfohlen</span>
                      )}
                    </div>
                    <p className="text-xs text-gray-500 mb-3">{pkg.subtitle}</p>
                    <ul className="space-y-1.5">
                      {pkg.features.map((f) => (
                        <li key={f} className="text-xs text-gray-400 flex items-start gap-1.5">
                          <span className="mt-0.5 w-1 h-1 rounded-full flex-shrink-0" style={{ backgroundColor: pkg.color }} />
                          {f}
                        </li>
                      ))}
                    </ul>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Step 2: Domain Input */}
        {step === 2 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-400">Welche Ziele sollen regelmäßig gescannt werden?</p>
              <span className={`text-xs font-mono px-2 py-0.5 rounded ${
                overLimit ? 'bg-red-500/20 text-red-400' : totalHosts > 0 ? 'bg-[#2DD4BF]/10 text-[#2DD4BF]' : 'text-gray-600'
              }`}>
                {totalHosts} / {MAX_HOSTS} Hosts
              </span>
            </div>
            <div className="space-y-2">
              {domains.map((d, i) => {
                const cleaned = cleanDomain(d);
                const hosts = countHosts(cleaned);
                return (
                  <div key={i} className="flex gap-2 items-center">
                    <input
                      type="text"
                      value={d}
                      onChange={(e) => {
                        const next = [...domains];
                        next[i] = e.target.value;
                        setDomains(next);
                      }}
                      placeholder="beispiel.de oder 85.22.47.0/24"
                      className="flex-1 bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#2DD4BF] focus:ring-1 focus:ring-[#2DD4BF] text-sm font-mono"
                    />
                    {hosts > 1 && (
                      <span className="text-[10px] text-gray-500 font-mono w-16 text-right flex-shrink-0">{hosts} Hosts</span>
                    )}
                    {domains.length > 1 && (
                      <button onClick={() => setDomains(domains.filter((_, j) => j !== i))}
                        className="text-red-400 hover:text-red-300 px-1 transition-colors flex-shrink-0">x</button>
                    )}
                  </div>
                );
              })}
            </div>
            {domains.length < 30 && (
              <button onClick={() => setDomains([...domains, ''])}
                className="text-xs text-[#2DD4BF] hover:text-[#5EEAD4] font-medium transition-colors">
                + Ziel hinzufügen
              </button>
            )}

            {/* Over-limit warning */}
            {overLimit && (
              <div className="bg-amber-900/20 border border-amber-800/50 rounded-lg p-4 space-y-3">
                <p className="text-sm text-amber-300">
                  Sie haben {totalHosts} Hosts konfiguriert — das übersteigt das Standard-Limit von {MAX_HOSTS}.
                </p>
                <p className="text-xs text-amber-300/70">
                  Für größere Infrastrukturen erstellen wir Ihnen ein maßgeschneidertes Angebot.
                </p>
                <a href="mailto:kontakt@vectigal.gmbh?subject=Maßgeschneidertes%20Angebot%20(über%2030%20Hosts)&body=Guten%20Tag%2C%0A%0Awir%20benötigen%20ein%20Angebot%20für%20mehr%20als%2030%20Hosts.%0A%0AAnzahl%20Hosts%3A%20%0ADomains%2FSubnetze%3A%20%0A%0AMit%20freundlichen%20Grüßen"
                  className="inline-block px-4 py-2 rounded-lg text-xs font-medium bg-amber-500/20 text-amber-300 hover:bg-amber-500/30 transition-colors">
                  Individuelles Angebot anfordern
                </a>
              </div>
            )}

            <p className="text-xs text-gray-600">
              FQDN (beispiel.de), IPv4 (1.2.3.4), CIDR (1.2.3.0/24) oder Subnetzmaske (1.2.3.4/255.255.255.224).
              Ziele werden nach der Bestellung von einem Administrator geprüft.
            </p>
          </div>
        )}

        {/* Step 3: Report Emails */}
        {step === 3 && (
          <div className="space-y-3">
            <p className="text-sm text-gray-400">An welche E-Mail-Adressen sollen die Reports versandt werden?</p>
            <div className="space-y-2">
              {reportEmails.map((email, i) => (
                <div key={i} className="flex gap-2">
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => {
                      const next = [...reportEmails];
                      next[i] = e.target.value;
                      setReportEmails(next);
                    }}
                    placeholder="it-leitung@firma.de"
                    className="flex-1 bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#2DD4BF] focus:ring-1 focus:ring-[#2DD4BF] text-sm"
                  />
                  {reportEmails.length > 1 && (
                    <button onClick={() => setReportEmails(reportEmails.filter((_, j) => j !== i))}
                      className="text-red-400 hover:text-red-300 px-2 transition-colors">x</button>
                  )}
                </div>
              ))}
            </div>
            {reportEmails.length < 10 && (
              <button onClick={() => setReportEmails([...reportEmails, ''])}
                className="text-xs text-[#2DD4BF] hover:text-[#5EEAD4] font-medium transition-colors">
                + Empfänger hinzufügen
              </button>
            )}
          </div>
        )}

        {/* Step 4: Scan Interval */}
        {step === 4 && (
          <div className="space-y-3">
            <p className="text-sm text-gray-400">Wie oft sollen Ihre Domains gescannt werden?</p>
            <div className="grid grid-cols-3 gap-3">
              {INTERVALS.map((iv) => {
                const isSelected = scanInterval === iv.id;
                return (
                  <button key={iv.id} onClick={() => setScanInterval(iv.id)}
                    className={`text-center p-4 rounded-lg border-2 transition-all ${
                      isSelected
                        ? 'border-[#2DD4BF] bg-[#2DD4BF]/10'
                        : 'border-gray-800 bg-[#1e293b] hover:bg-[#253347]'
                    }`}>
                    <p className="text-sm font-medium text-white">{iv.label}</p>
                    <p className="text-xs text-gray-500 mt-1">{iv.desc}</p>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Step 5: Summary */}
        {step === 5 && (
          <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-5 space-y-4">
            <h2 className="text-sm font-medium text-white">Zusammenfassung</h2>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500">Paket</span>
                <span className="text-white font-medium">{PACKAGES.find(p => p.id === selectedPackage)?.name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Ziele ({validDomains.length} Einträge, {totalHosts} Hosts)</span>
                <span className="text-white font-mono text-xs max-w-[200px] text-right truncate">{validDomains.join(', ')}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Report-Empfänger</span>
                <span className="text-white text-xs">{validEmails.join(', ')}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Scan-Intervall</span>
                <span className="text-white">{INTERVALS.find(i => i.id === scanInterval)?.label}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Laufzeit</span>
                <span className="text-white">12 Monate</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Re-Scans inklusive</span>
                <span className="text-white">3 pro Jahr</span>
              </div>
            </div>
            <div className="border-t border-gray-700 pt-3">
              <p className="text-xs text-gray-500">
                Nach der Bestellung werden Ihre Domains von einem Administrator geprüft.
                Nach Freigabe startet der erste Scan automatisch.
              </p>
            </div>
          </div>
        )}

        {/* Navigation */}
        <div className="flex justify-between items-center pt-2">
          {step > 1 ? (
            <button onClick={() => { setStep(step - 1); setError(null); }}
              className="text-sm text-gray-400 hover:text-gray-300 transition-colors">
              Zurück
            </button>
          ) : <div />}

          {step < 5 ? (
            <button onClick={() => { if (canAdvance()) setStep(step + 1); }}
              disabled={!canAdvance()}
              className="bg-[#2DD4BF] hover:bg-[#14B8A6] text-[#0F172A] disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-medium px-6 py-2.5 rounded-lg transition-colors text-sm">
              Weiter
            </button>
          ) : (
            <button onClick={handleSubmit} disabled={submitting}
              className="bg-[#2DD4BF] hover:bg-[#14B8A6] text-[#0F172A] disabled:bg-gray-700 text-white font-medium px-6 py-2.5 rounded-lg transition-colors text-sm">
              {submitting ? 'Wird erstellt...' : 'Abo starten'}
            </button>
          )}
        </div>
      </div>
    </main>
  );
}

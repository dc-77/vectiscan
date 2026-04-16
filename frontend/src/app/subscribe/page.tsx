'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

import { createSubscription } from '@/lib/api';
import { isLoggedIn, getUser } from '@/lib/auth';

const DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const IPV4_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isValidTarget(input: string): boolean {
  const s = input.trim();
  if (!s) return false;
  if (DOMAIN_REGEX.test(s)) return true;
  // IPv4 with optional CIDR or dotted mask
  if (s.includes('/')) {
    const [ip, mask] = s.split('/', 2);
    if (!IPV4_REGEX.test(ip)) return false;
    if (/^\d{1,2}$/.test(mask)) { const n = parseInt(mask); return n >= 8 && n <= 32; }
    return IPV4_REGEX.test(mask); // dotted-decimal mask
  }
  if (IPV4_REGEX.test(s)) {
    return s.split('.').every(o => { const n = parseInt(o); return n >= 0 && n <= 255; });
  }
  return false;
}

const PACKAGES = [
  {
    id: 'perimeter',
    name: 'Perimeter-Scan',
    subtitle: 'Vollstandige Sicherheitsanalyse Ihrer Angriffsoberflache',
    recommended: true,
    color: '#38BDF8',
    features: [
      'Vollstandige Angriffsoberflachen-Analyse',
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
  { id: 'weekly', label: 'Wochentlich', desc: 'Scan jede Woche' },
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

  const validDomains = domains.map(cleanDomain).filter(d => d && isValidTarget(d));
  const validEmails = reportEmails.filter(e => e.includes('@'));

  const canAdvance = () => {
    switch (step) {
      case 1: return !!selectedPackage;
      case 2: return validDomains.length > 0;
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
            Ihre Domains werden jetzt von einem Administrator gepruft und freigegeben.
            Nach der Freigabe startet der erste Scan automatisch.
          </p>
          <Link href="/dashboard"
            className="inline-block bg-blue-600 hover:bg-blue-500 text-white font-medium px-6 py-3 rounded-lg transition-colors text-sm">
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
                <div className={`flex items-center gap-1.5 ${isActive ? 'text-blue-400' : isDone ? 'text-green-400' : 'text-slate-600'}`}>
                  <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium border ${
                    isActive ? 'border-blue-400 bg-blue-400/10' : isDone ? 'border-green-400 bg-green-400/10' : 'border-slate-700'
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
            <p className="text-sm text-gray-400">Wahlen Sie Ihr Scan-Paket:</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {PACKAGES.map((pkg) => {
                const isSelected = selectedPackage === pkg.id;
                return (
                  <button key={pkg.id} onClick={() => setSelectedPackage(pkg.id)}
                    className={`text-left p-5 rounded-lg border-2 transition-all ${
                      isSelected
                        ? 'border-blue-500 bg-blue-500/5'
                        : 'border-gray-800 bg-[#1e293b] hover:bg-[#253347] hover:border-gray-700'
                    }`}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-sm font-semibold text-white">{pkg.name}</span>
                      {pkg.recommended && (
                        <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400">Empfohlen</span>
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
            <p className="text-sm text-gray-400">Welche Ziele sollen regelmaessig gescannt werden? (max. 5)</p>
            <div className="space-y-2">
              {domains.map((d, i) => (
                <div key={i} className="flex gap-2">
                  <input
                    type="text"
                    value={d}
                    onChange={(e) => {
                      const next = [...domains];
                      next[i] = e.target.value;
                      setDomains(next);
                    }}
                    placeholder="beispiel.de oder 85.22.47.0/24"
                    className="flex-1 bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm font-mono"
                  />
                  {domains.length > 1 && (
                    <button onClick={() => setDomains(domains.filter((_, j) => j !== i))}
                      className="text-red-400 hover:text-red-300 px-2 transition-colors">x</button>
                  )}
                </div>
              ))}
            </div>
            {domains.length < 5 && (
              <button onClick={() => setDomains([...domains, ''])}
                className="text-xs text-blue-400 hover:text-blue-300 font-medium transition-colors">
                + Domain hinzufugen
              </button>
            )}
            <p className="text-xs text-gray-600">FQDN (beispiel.de), IPv4 (1.2.3.4), CIDR (1.2.3.0/24) oder Subnetzmaske (1.2.3.4/255.255.255.224). Ziele werden nach der Bestellung von einem Administrator geprueft.</p>
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
                    className="flex-1 bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm"
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
                className="text-xs text-blue-400 hover:text-blue-300 font-medium transition-colors">
                + Empfanger hinzufugen
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
                        ? 'border-blue-500 bg-blue-500/10'
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
                <span className="text-gray-500">Domains ({validDomains.length})</span>
                <span className="text-white font-mono text-xs">{validDomains.join(', ')}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Report-Empfanger</span>
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
                Nach der Bestellung werden Ihre Domains von einem Administrator gepruft.
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
              Zuruck
            </button>
          ) : <div />}

          {step < 5 ? (
            <button onClick={() => { if (canAdvance()) setStep(step + 1); }}
              disabled={!canAdvance()}
              className="bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-medium px-6 py-2.5 rounded-lg transition-colors text-sm">
              Weiter
            </button>
          ) : (
            <button onClick={handleSubmit} disabled={submitting}
              className="bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 text-white font-medium px-6 py-2.5 rounded-lg transition-colors text-sm">
              {submitting ? 'Wird erstellt...' : 'Abo starten'}
            </button>
          )}
        </div>
      </div>
    </main>
  );
}

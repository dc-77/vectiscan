'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { getVerificationStatus, checkVerification, manualVerify } from '@/lib/api';


type Tab = 'dns_txt' | 'file' | 'meta_tag';

export default function VerifyPage() {
  const params = useParams();
  const router = useRouter();
  const orderId = params.orderId as string;

  const [domain, setDomain] = useState('');
  const [token, setToken] = useState('');
  const [activeTab, setActiveTab] = useState<Tab>('dns_txt');
  const [checking, setChecking] = useState(false);
  const [verified, setVerified] = useState(false);
  const [verifiedMethod, setVerifiedMethod] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Load verification status on mount
  useEffect(() => {
    async function load() {
      try {
        const res = await getVerificationStatus(orderId);
        if (res.success && res.data) {
          setDomain(res.data.domain);
          setToken(res.data.token);
          setVerified(res.data.verified);
          setVerifiedMethod(res.data.method);
        }
      } catch {
        setError('Verifizierungsstatus konnte nicht geladen werden.');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [orderId]);

  // Auto-poll every 30 seconds
  useEffect(() => {
    if (verified) return;
    pollRef.current = setInterval(async () => {
      try {
        const res = await checkVerification(orderId);
        if (res.success && res.data?.verified) {
          setVerified(true);
          setVerifiedMethod(res.data.method || null);
        }
      } catch {
        // Silently retry
      }
    }, 30_000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [orderId, verified]);

  // Redirect after verification
  useEffect(() => {
    if (verified) {
      if (pollRef.current) clearInterval(pollRef.current);
      const timer = setTimeout(() => router.push(`/?orderId=${orderId}`), 2000);
      return () => clearTimeout(timer);
    }
  }, [verified, orderId, router]);

  const handleCheck = useCallback(async () => {
    setChecking(true);
    setError(null);
    try {
      const res = await checkVerification(orderId);
      if (res.success && res.data?.verified) {
        setVerified(true);
        setVerifiedMethod(res.data.method || null);
      } else {
        setError('Verifizierung noch nicht erkannt. Bitte prufe die Einrichtung und versuche es erneut.');
      }
    } catch {
      setError('API nicht erreichbar.');
    } finally {
      setChecking(false);
    }
  }, [orderId]);

  const handleManualVerify = useCallback(async () => {
    setChecking(true);
    setError(null);
    try {
      const res = await manualVerify(orderId);
      if (res.success && res.data?.verified) {
        setVerified(true);
        setVerifiedMethod('manual');
      } else {
        setError(res.error || 'Manuelle Verifizierung fehlgeschlagen.');
      }
    } catch {
      setError('API nicht erreichbar.');
    } finally {
      setChecking(false);
    }
  }, [orderId]);

  const copyToClipboard = useCallback(async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 2000);
    } catch {
      // Fallback ignored
    }
  }, []);

  if (loading) {
    return (
      <main className="flex-1 flex items-center justify-center">
        <div className="text-gray-400">Laden...</div>
      </main>
    );
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: 'dns_txt', label: 'DNS-TXT-Record' },
    { id: 'file', label: 'Datei-Upload' },
    { id: 'meta_tag', label: 'Meta-Tag' },
  ];

  const dnsRecord = `_vectiscan-verify.${domain} TXT "${token}"`;
  const filePath = `https://${domain}/.well-known/vectiscan-verify.txt`;
  const metaTag = `<meta name="vectiscan-verify" content="${token}">`;

  return (
    <main className="flex-1 flex flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-2xl space-y-6">
        <div className="text-center space-y-2">
          <h1 className="text-2xl font-bold text-white">Domain verifizieren</h1>
          <p className="text-gray-400">
            Verifiziere deine Domain, um den Scan zu starten:
          </p>
          <p className="text-lg font-bold text-cyan-400">{domain}</p>
        </div>

        {/* Verified banner */}
        {verified && (
          <div className="bg-green-900/30 border border-green-700 rounded-lg px-4 py-3 text-center" data-testid="verified-banner">
            <span className="text-green-400 text-lg mr-2">&#10003;</span>
            <span className="text-green-300 font-medium">
              Verifiziert!{verifiedMethod && ` (${verifiedMethod})`}
            </span>
            <p className="text-green-400/70 text-sm mt-1">Scan wird gestartet...</p>
          </div>
        )}

        {/* Tabs */}
        {!verified && (
          <>
            <div className="flex border-b border-gray-700">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex-1 py-3 text-sm font-medium transition-colors ${
                    activeTab === tab.id
                      ? 'text-cyan-400 border-b-2 border-cyan-400'
                      : 'text-gray-500 hover:text-gray-300'
                  }`}
                  data-testid={`tab-${tab.id}`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div className="bg-[#1e293b] rounded-lg p-6 space-y-4">
              {activeTab === 'dns_txt' && (
                <div data-testid="tab-content-dns_txt">
                  <p className="text-gray-300 mb-3">
                    Erstelle einen TXT-Record fur deine Domain:
                  </p>
                  <div className="relative">
                    <pre className="bg-[#0f172a] rounded-lg p-4 text-cyan-300 font-mono text-sm overflow-x-auto">
                      {dnsRecord}
                    </pre>
                    <button
                      onClick={() => copyToClipboard(dnsRecord, 'dns')}
                      className="absolute top-2 right-2 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded transition-colors"
                      data-testid="copy-dns"
                    >
                      {copied === 'dns' ? 'Kopiert!' : 'Kopieren'}
                    </button>
                  </div>
                  <p className="text-gray-500 text-sm mt-3">
                    DNS-Anderungen konnen bis zu 5 Minuten dauern.
                  </p>
                </div>
              )}

              {activeTab === 'file' && (
                <div data-testid="tab-content-file">
                  <p className="text-gray-300 mb-3">
                    Lege eine Datei auf deinem Webserver ab:
                  </p>
                  <p className="text-gray-400 text-sm mb-2">Pfad:</p>
                  <div className="relative">
                    <pre className="bg-[#0f172a] rounded-lg p-4 text-cyan-300 font-mono text-sm overflow-x-auto">
                      {filePath}
                    </pre>
                  </div>
                  <p className="text-gray-400 text-sm mt-3 mb-2">Datei-Inhalt:</p>
                  <div className="relative">
                    <pre className="bg-[#0f172a] rounded-lg p-4 text-cyan-300 font-mono text-sm overflow-x-auto">
                      {token}
                    </pre>
                    <button
                      onClick={() => copyToClipboard(token, 'file')}
                      className="absolute top-2 right-2 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded transition-colors"
                      data-testid="copy-file"
                    >
                      {copied === 'file' ? 'Kopiert!' : 'Kopieren'}
                    </button>
                  </div>
                </div>
              )}

              {activeTab === 'meta_tag' && (
                <div data-testid="tab-content-meta_tag">
                  <p className="text-gray-300 mb-3">
                    Fuge diesen Meta-Tag in den &lt;head&gt; deiner Startseite ein:
                  </p>
                  <div className="relative">
                    <pre className="bg-[#0f172a] rounded-lg p-4 text-cyan-300 font-mono text-sm overflow-x-auto">
                      {metaTag}
                    </pre>
                    <button
                      onClick={() => copyToClipboard(metaTag, 'meta')}
                      className="absolute top-2 right-2 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded transition-colors"
                      data-testid="copy-meta"
                    >
                      {copied === 'meta' ? 'Kopiert!' : 'Kopieren'}
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Action buttons */}
            <div className="flex gap-3">
              <button
                onClick={handleCheck}
                disabled={checking}
                className="flex-1 bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-medium px-6 py-3 rounded-lg transition-colors"
                data-testid="check-button"
              >
                {checking ? 'Prufe...' : 'Verifizierung prufen'}
              </button>
              <button
                onClick={handleManualVerify}
                className="bg-gray-700 hover:bg-gray-600 text-gray-300 font-medium px-4 py-3 rounded-lg transition-colors text-sm"
                data-testid="manual-verify-button"
              >
                Manuell verifizieren
              </button>
            </div>

            {/* Error message */}
            {error && (
              <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm" data-testid="error-message">
                {error}
              </div>
            )}

            {/* Auto-poll hint */}
            <p className="text-gray-600 text-xs text-center">
              Automatische Prufung alle 30 Sekunden aktiv
            </p>
          </>
        )}
      </div>
    </main>
  );
}

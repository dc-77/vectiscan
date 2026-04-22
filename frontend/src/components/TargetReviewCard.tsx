'use client';

import { useEffect, useState } from 'react';
import {
  approveTarget, rejectTarget, restartPrecheck, updateTarget,
  ScanTargetDetail, TargetDiscoveryPolicy,
} from '@/lib/api';

const POLICY_LABELS: Record<string, string> = {
  enumerate: 'enumerate (Subdomain-Enumeration)',
  scoped: 'scoped (nur gelistete Hosts)',
  ip_only: 'ip_only (nur IP, kein DNS)',
};

const TARGET_TYPE_LABELS: Record<string, string> = {
  fqdn_root: 'Root-Domain',
  fqdn_specific: 'Subdomain',
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  cidr: 'CIDR',
  url: 'URL',
};

const STATUS_COLORS: Record<string, string> = {
  pending_precheck: 'bg-slate-500/15 text-slate-400',
  precheck_running: 'bg-blue-500/15 text-blue-400',
  precheck_complete: 'bg-cyan-500/15 text-cyan-400',
  precheck_failed: 'bg-orange-500/15 text-orange-400',
  pending_review: 'bg-amber-500/15 text-amber-400',
  approved: 'bg-green-500/15 text-green-400',
  rejected: 'bg-red-500/15 text-red-400',
  removed: 'bg-slate-500/15 text-slate-500',
};

const CLOUD_SAAS = new Set(['azure', 'aws', 'gcp', 'cloudflare', 'oracle_cloud']);

interface Props {
  target: ScanTargetDetail;
  onChanged: () => void;
}

export default function TargetReviewCard({ target, onChanged }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [policy, setPolicy] = useState<string>(target.discovery_policy || 'scoped');
  const [exclusionsText, setExclusionsText] = useState<string>((target.exclusions || []).join('\n'));
  const [notes, setNotes] = useState<string>(target.review_notes || '');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setPolicy(target.discovery_policy || 'scoped');
    setExclusionsText((target.exclusions || []).join('\n'));
    setNotes(target.review_notes || '');
  }, [target.id, target.discovery_policy, target.exclusions, target.review_notes]);

  const isIpOnlyForced = target.target_type === 'cidr'
    || target.target_type === 'ipv4'
    || target.target_type === 'ipv6';

  const isDecided = ['approved', 'rejected', 'removed'].includes(target.status);

  const parseExclusions = (): string[] =>
    exclusionsText.split(/\r?\n/).map(s => s.trim()).filter(Boolean);

  const handleSave = async () => {
    setBusy(true); setErr(null);
    const res = await updateTarget(target.id, {
      discoveryPolicy: policy as TargetDiscoveryPolicy,
      exclusions: parseExclusions(),
    });
    if (!res.success) setErr(res.error || 'Aktualisierung fehlgeschlagen');
    setBusy(false);
    if (res.success) onChanged();
  };

  const handleApprove = async () => {
    setBusy(true); setErr(null);
    const res = await approveTarget(target.id, {
      discoveryPolicy: policy as TargetDiscoveryPolicy,
      exclusions: parseExclusions(),
      notes: notes || undefined,
    });
    if (!res.success) setErr(res.error || 'Approve fehlgeschlagen');
    setBusy(false);
    if (res.success) onChanged();
  };

  const handleReject = async () => {
    const reason = typeof window !== 'undefined' ? window.prompt(`Ablehnungsgrund für ${target.raw_input}:`, notes) : null;
    if (reason === null) return;
    setBusy(true); setErr(null);
    const res = await rejectTarget(target.id, reason);
    if (!res.success) setErr(res.error || 'Reject fehlgeschlagen');
    setBusy(false);
    if (res.success) onChanged();
  };

  const handleRestart = async () => {
    if (typeof window !== 'undefined' && !window.confirm('Pre-Check für dieses Target neu starten?')) return;
    setBusy(true); setErr(null);
    const res = await restartPrecheck(target.id);
    if (!res.success) setErr(res.error || 'Restart fehlgeschlagen');
    setBusy(false);
    if (res.success) onChanged();
  };

  const liveHosts = target.hosts.filter(h => h.is_live);
  const saasHosts = target.hosts.filter(h => h.cloud_provider && CLOUD_SAAS.has(h.cloud_provider.toLowerCase()));

  return (
    <div className={`bg-[#1e293b] rounded-lg border p-4 space-y-3 ${isDecided ? 'border-gray-800 opacity-80' : 'border-gray-800'}`}>
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-sm text-white truncate">{target.raw_input}</span>
            <span className="text-[10px] uppercase bg-gray-800 text-slate-400 px-1.5 py-0.5 rounded">
              {TARGET_TYPE_LABELS[target.target_type] || target.target_type}
            </span>
            <span className={`text-[10px] uppercase px-1.5 py-0.5 rounded ${STATUS_COLORS[target.status] || 'bg-slate-500/15 text-slate-400'}`}>
              {target.status}
            </span>
            {target.canonical && target.canonical !== target.raw_input && (
              <span className="text-[10px] text-slate-500 font-mono">→ {target.canonical}</span>
            )}
          </div>
          <div className="flex items-center gap-3 text-[10px] text-slate-500 mt-1">
            <span>{target.hosts.length} Host{target.hosts.length === 1 ? '' : 's'}</span>
            <span>{liveHosts.length} live</span>
            {target.approved_at && <span>{target.status} am {new Date(target.approved_at).toLocaleString('de-DE')}</span>}
          </div>
        </div>
      </div>

      {saasHosts.length > 0 && (
        <div className="bg-amber-900/20 border border-amber-800/50 rounded-lg px-3 py-2 text-xs text-amber-300">
          <strong>Achtung:</strong> SaaS-Subdomain erkannt bei {saasHosts.length} Host{saasHosts.length === 1 ? '' : 's'}
          {' '}({Array.from(new Set(saasHosts.map(h => h.cloud_provider))).join(', ')}).
          Scan eines Cloud-Providers könnte ToS verletzen — Autorisierung prüfen.
        </div>
      )}

      {/* Collapsible Pre-Check Details */}
      <button
        onClick={() => setExpanded(v => !v)}
        className="text-[11px] text-slate-400 hover:text-slate-200 transition-colors"
      >
        {expanded ? '▼' : '▶'} Pre-Check-Details ({target.hosts.length})
      </button>

      {expanded && target.hosts.length > 0 && (
        <div className="bg-[#0f172a] rounded-lg border border-gray-800 overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-[10px] text-slate-500 uppercase tracking-wider">
              <tr>
                <th className="text-left px-2 py-1.5">IP</th>
                <th className="text-left px-2 py-1.5">Live</th>
                <th className="text-left px-2 py-1.5">HTTP</th>
                <th className="text-left px-2 py-1.5">Titel</th>
                <th className="text-left px-2 py-1.5">Reverse-DNS</th>
                <th className="text-left px-2 py-1.5">Cloud</th>
                <th className="text-left px-2 py-1.5">Parking</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {target.hosts.map((h, i) => (
                <tr key={`${h.ip}-${i}`}>
                  <td className="px-2 py-1.5 font-mono text-slate-300">{h.ip}</td>
                  <td className="px-2 py-1.5">
                    <span className={h.is_live ? 'text-green-400' : 'text-slate-600'}>
                      {h.is_live ? '✓' : '—'}
                    </span>
                  </td>
                  <td className="px-2 py-1.5 font-mono text-slate-400">{h.http_status ?? '—'}</td>
                  <td className="px-2 py-1.5 text-slate-400 truncate max-w-[200px]">{h.http_title || '—'}</td>
                  <td className="px-2 py-1.5 font-mono text-slate-500 truncate max-w-[200px]">{h.reverse_dns || '—'}</td>
                  <td className="px-2 py-1.5 text-slate-400">{h.cloud_provider || '—'}</td>
                  <td className="px-2 py-1.5">
                    {h.parking_page ? <span className="text-amber-400">ja</span> : <span className="text-slate-600">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {expanded && target.hosts.length === 0 && (
        <div className="bg-[#0f172a] rounded-lg border border-gray-800 p-3 text-xs text-slate-500">
          Keine Pre-Check-Hosts gefunden.
        </div>
      )}

      {/* Actions / Form */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <label className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1">Discovery-Policy</label>
          <select
            value={isIpOnlyForced ? 'ip_only' : policy}
            onChange={(e) => setPolicy(e.target.value)}
            disabled={isIpOnlyForced || isDecided}
            className="w-full bg-[#0f172a] border border-gray-800 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:border-blue-500 outline-none disabled:opacity-60"
          >
            <option value="enumerate">{POLICY_LABELS.enumerate}</option>
            <option value="scoped">{POLICY_LABELS.scoped}</option>
            <option value="ip_only">{POLICY_LABELS.ip_only}</option>
          </select>
          {isIpOnlyForced && (
            <p className="text-[10px] text-slate-600 mt-1">IP/CIDR-Target: nur ip_only möglich.</p>
          )}
        </div>

        <div>
          <label className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1">Exclusions (Glob, eine pro Zeile)</label>
          <textarea
            value={exclusionsText}
            onChange={(e) => setExclusionsText(e.target.value)}
            disabled={isDecided}
            rows={3}
            placeholder="*.dev.example.com&#10;10.0.0.0/24"
            className="w-full bg-[#0f172a] border border-gray-800 rounded-lg px-2 py-1.5 text-xs font-mono text-slate-200 focus:border-blue-500 outline-none disabled:opacity-60"
          />
        </div>
      </div>

      <div>
        <label className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1">Review-Notizen</label>
        <textarea
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          disabled={isDecided}
          rows={2}
          placeholder="Interner Kommentar zur Entscheidung"
          className="w-full bg-[#0f172a] border border-gray-800 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:border-blue-500 outline-none disabled:opacity-60"
        />
      </div>

      {err && (
        <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-3 py-2 text-xs">
          {err}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {!isDecided && (
          <>
            <button
              onClick={handleApprove}
              disabled={busy}
              className="text-xs text-green-400 hover:text-green-300 font-medium px-3 py-1.5 bg-green-400/10 rounded-lg transition-colors disabled:opacity-50"
            >
              Freigeben
            </button>
            <button
              onClick={handleReject}
              disabled={busy}
              className="text-xs text-red-400 hover:text-red-300 font-medium px-3 py-1.5 bg-red-400/10 rounded-lg transition-colors disabled:opacity-50"
            >
              Ablehnen
            </button>
            <button
              onClick={handleSave}
              disabled={busy}
              className="text-xs text-slate-300 hover:text-white font-medium px-3 py-1.5 bg-slate-700 rounded-lg transition-colors disabled:opacity-50"
            >
              Änderungen speichern
            </button>
          </>
        )}
        <button
          onClick={handleRestart}
          disabled={busy}
          className="text-xs text-blue-400 hover:text-blue-300 font-medium px-3 py-1.5 bg-blue-400/10 rounded-lg transition-colors disabled:opacity-50"
        >
          Pre-Check neu starten
        </button>
      </div>
    </div>
  );
}

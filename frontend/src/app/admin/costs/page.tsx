'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn, isAdmin } from '@/lib/auth';

interface Totals {
  totalCalls: number;
  totalCostUsd: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  totalCacheReadTokens: number;
  totalCacheCreationTokens: number;
  cacheHits: number;
  cacheHitRate: number;
}
interface ByStep {
  kiStep: string;
  model: string;
  calls: number;
  costUsd: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
}
interface TopOrder {
  orderId: string;
  calls: number;
  costUsd: number;
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

export default function AdminCostsPage() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [period, setPeriod] = useState<'7d' | '30d' | '90d'>('30d');
  const [totals, setTotals] = useState<Totals | null>(null);
  const [byStep, setByStep] = useState<ByStep[]>([]);
  const [topOrders, setTopOrders] = useState<TopOrder[]>([]);

  useEffect(() => {
    if (!isLoggedIn()) { router.replace('/login'); return; }
    if (!isAdmin()) { router.replace('/dashboard'); return; }
    setReady(true);
  }, [router]);

  const load = useCallback(async () => {
    const token = typeof window !== 'undefined' ? window.localStorage.getItem('token') : null;
    const res = await fetch(`${API_URL}/api/admin/cost-overview?period=${period}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    const data = await res.json();
    if (data.success && data.data) {
      setTotals(data.data.totals);
      setByStep(data.data.byStep);
      setTopOrders(data.data.topOrders);
    }
  }, [period]);

  useEffect(() => { if (ready) load(); }, [ready, load]);

  if (!ready || !totals) {
    return <main className="flex-1 px-4 py-6"><div className="max-w-6xl mx-auto text-slate-500">Lade…</div></main>;
  }

  const cachedTokenShare = totals.totalInputTokens > 0
    ? totals.totalCacheReadTokens / (totals.totalInputTokens + totals.totalCacheReadTokens + totals.totalCacheCreationTokens)
    : 0;

  return (
    <main className="flex-1 px-4 py-6 md:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        <Link href="/dashboard" className="text-xs text-slate-500 hover:text-slate-300">← Dashboard</Link>

        <div className="flex items-center justify-between flex-wrap gap-3">
          <h1 className="text-xl font-semibold text-white">KI-Cost-Cockpit</h1>
          <div className="flex gap-1">
            {(['7d', '30d', '90d'] as const).map(p => (
              <button key={p} onClick={() => setPeriod(p)}
                className={`text-xs px-3 py-1 rounded ${period === p ? 'bg-cyan-500/20 text-cyan-200 ring-1 ring-cyan-500/40' : 'bg-slate-800 text-slate-400'}`}>
                {p}
              </button>
            ))}
          </div>
        </div>

        {/* Totals */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="rounded-xl p-4 bg-[#1e293b] border border-slate-700">
            <div className="text-xs text-slate-500 uppercase">Gesamt-Cost</div>
            <div className="text-2xl font-bold text-emerald-300 mt-1">${totals.totalCostUsd.toFixed(2)}</div>
            <div className="text-xs text-slate-500 mt-1">{totals.totalCalls} Calls</div>
          </div>
          <div className="rounded-xl p-4 bg-[#1e293b] border border-slate-700">
            <div className="text-xs text-slate-500 uppercase">Input-Tokens</div>
            <div className="text-xl font-bold text-slate-200 mt-1">{(totals.totalInputTokens / 1000).toFixed(0)}k</div>
            <div className="text-xs text-slate-500 mt-1">{(totals.totalCacheReadTokens / 1000).toFixed(0)}k cached</div>
          </div>
          <div className="rounded-xl p-4 bg-[#1e293b] border border-slate-700">
            <div className="text-xs text-slate-500 uppercase">Output-Tokens</div>
            <div className="text-xl font-bold text-slate-200 mt-1">{(totals.totalOutputTokens / 1000).toFixed(0)}k</div>
          </div>
          <div className="rounded-xl p-4 bg-[#1e293b] border border-slate-700">
            <div className="text-xs text-slate-500 uppercase">Cache-Hit-Rate</div>
            <div className="text-xl font-bold text-cyan-300 mt-1">{Math.round(totals.cacheHitRate * 100)}%</div>
            <div className="text-xs text-slate-500 mt-1">Prompt-Cache: {Math.round(cachedTokenShare * 100)}%</div>
          </div>
        </div>

        {/* By KI-Step */}
        <div className="rounded-xl p-5 bg-[#1e293b] border border-slate-700">
          <h2 className="text-sm font-semibold text-slate-200 mb-3">Cost nach KI-Step</h2>
          <table className="w-full text-xs">
            <thead className="text-slate-500 uppercase">
              <tr>
                <th className="text-left py-1">KI-Step</th>
                <th className="text-left py-1">Model</th>
                <th className="text-right py-1">Calls</th>
                <th className="text-right py-1">Input-Tokens</th>
                <th className="text-right py-1">Cache-Read</th>
                <th className="text-right py-1">Output-Tokens</th>
                <th className="text-right py-1">Cost (USD)</th>
              </tr>
            </thead>
            <tbody>
              {byStep.map(s => (
                <tr key={`${s.kiStep}-${s.model}`} className="border-t border-slate-800">
                  <td className="py-1.5 font-mono text-cyan-300">{s.kiStep}</td>
                  <td className="py-1.5 text-slate-400 text-[10px]">{s.model}</td>
                  <td className="py-1.5 text-right text-slate-300">{s.calls}</td>
                  <td className="py-1.5 text-right text-slate-300">{s.inputTokens.toLocaleString('de-DE')}</td>
                  <td className="py-1.5 text-right text-cyan-300">{s.cacheReadTokens.toLocaleString('de-DE')}</td>
                  <td className="py-1.5 text-right text-slate-300">{s.outputTokens.toLocaleString('de-DE')}</td>
                  <td className="py-1.5 text-right font-mono text-emerald-300">${s.costUsd.toFixed(4)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Top Orders */}
        <div className="rounded-xl p-5 bg-[#1e293b] border border-slate-700">
          <h2 className="text-sm font-semibold text-slate-200 mb-3">Top-Cost Orders</h2>
          <table className="w-full text-xs">
            <thead className="text-slate-500 uppercase">
              <tr>
                <th className="text-left py-1">Order-ID</th>
                <th className="text-right py-1">KI-Calls</th>
                <th className="text-right py-1">Cost (USD)</th>
              </tr>
            </thead>
            <tbody>
              {topOrders.map(o => (
                <tr key={o.orderId} className="border-t border-slate-800">
                  <td className="py-1.5">
                    <Link href={`/scan/${o.orderId}`} className="font-mono text-cyan-300 hover:underline">
                      {o.orderId.slice(0, 8)}…
                    </Link>
                  </td>
                  <td className="py-1.5 text-right text-slate-300">{o.calls}</td>
                  <td className="py-1.5 text-right font-mono text-emerald-300">${o.costUsd.toFixed(4)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  );
}

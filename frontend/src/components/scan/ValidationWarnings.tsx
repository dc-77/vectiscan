'use client';

import { useMemo, useState } from 'react';
import {
  requeueReport,
  type ValidationIssuePayload,
  type ValidationWarningsPayload,
} from '@/lib/api';

interface Props {
  orderId: string;
  orderStatus: string;
  payload: ValidationWarningsPayload | null | undefined;
}

const CHECK_LABELS: Record<string, string> = {
  titles: 'Title-Qualitaet',
  ids: 'Finding-IDs',
  cvss: 'CVSS-Konsistenz',
  consistency: 'Title-Body-Konsistenz',
  tech_table: 'Tech-Tabelle',
  eol: 'End-of-Life-Detection',
  plan: 'Aktionsplan',
};

function groupByCheck(issues: ValidationIssuePayload[]): Record<string, ValidationIssuePayload[]> {
  const out: Record<string, ValidationIssuePayload[]> = {};
  for (const i of issues) {
    (out[i.check] ??= []).push(i);
  }
  return out;
}

function SeverityPill({ severity }: { severity: string }) {
  const isError = severity === 'error';
  return (
    <span
      className={`px-1.5 py-0.5 rounded text-[10px] font-medium uppercase tracking-wide ${
        isError
          ? 'bg-red-500/15 text-red-300 ring-1 ring-red-500/30'
          : 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30'
      }`}
    >
      {severity}
    </span>
  );
}

function IssueRow({ issue }: { issue: ValidationIssuePayload }) {
  const [open, setOpen] = useState(false);
  const hasDetail = issue.detail && Object.keys(issue.detail).length > 0;
  return (
    <li className="border-l-2 border-slate-800 pl-3 py-1.5">
      <div className="flex items-baseline gap-2 flex-wrap text-xs">
        <SeverityPill severity={issue.severity} />
        {issue.finding_id && (
          <span className="font-mono text-[11px] text-slate-400">{issue.finding_id}</span>
        )}
        <span className="text-slate-200 break-words">{issue.message}</span>
        {hasDetail && (
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="ml-auto text-[11px] text-slate-500 hover:text-slate-300"
          >
            {open ? 'Details ▲' : 'Details ▼'}
          </button>
        )}
      </div>
      {open && hasDetail && (
        <pre className="mt-2 text-[11px] text-slate-400 bg-slate-950/60 rounded p-2 overflow-x-auto">
          {JSON.stringify(issue.detail, null, 2)}
        </pre>
      )}
    </li>
  );
}

export default function ValidationWarnings({ orderId, orderStatus, payload }: Props) {
  const [open, setOpen] = useState(false);
  const [requeuing, setRequeuing] = useState(false);
  const [requeueMsg, setRequeueMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const grouped = useMemo(() => {
    if (!payload) return null;
    const all = [...(payload.errors ?? []), ...(payload.warnings ?? [])];
    return groupByCheck(all);
  }, [payload]);

  const errorCount = payload?.error_count ?? 0;
  const warningCount = payload?.warning_count ?? 0;
  const totalCount = errorCount + warningCount;
  const passed = payload?.passed ?? null;

  const isFailedOrderWithoutPayload = !payload && orderStatus === 'failed';
  const showRequeueButton = isFailedOrderWithoutPayload || totalCount > 0 || orderStatus === 'failed';

  const handleRequeue = async () => {
    if (!confirm('Report fuer diesen Scan neu erzeugen? Der Report-Worker baut den PDF anhand der bestehenden Scan-Daten neu.')) {
      return;
    }
    setRequeuing(true);
    setRequeueMsg(null);
    const res = await requeueReport(orderId);
    setRequeuing(false);
    if (res.success) {
      setRequeueMsg({ kind: 'ok', text: 'Report-Job neu in die Queue gestellt. Seite wird in 3s neu geladen…' });
      setTimeout(() => window.location.reload(), 3000);
    } else {
      setRequeueMsg({ kind: 'err', text: res.error || 'Re-Report fehlgeschlagen.' });
    }
  };

  const badgeColor =
    totalCount === 0
      ? 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30'
      : errorCount > 0
        ? 'bg-red-500/15 text-red-300 ring-1 ring-red-500/30'
        : 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30';

  return (
    <section
      id="validation-warnings"
      className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 scroll-mt-32"
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center justify-between w-full text-left"
      >
        <h2 className="text-sm font-medium text-slate-300 flex items-center gap-2 flex-wrap">
          Quality-Check-Warnungen{' '}
          <span className="text-xs text-slate-500 font-normal">(Admin)</span>
          {payload && (
            <span className={`px-2 py-0.5 rounded text-[11px] font-medium ${badgeColor}`}>
              {totalCount === 0
                ? 'sauber'
                : `${errorCount} Fehler · ${warningCount} Warnungen`}
            </span>
          )}
          {!payload && isFailedOrderWithoutPayload && (
            <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-slate-700/40 text-slate-300 ring-1 ring-slate-600/40">
              keine Daten — Scan vor Report-Erzeugung geblockt
            </span>
          )}
          {!payload && !isFailedOrderWithoutPayload && (
            <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-slate-700/40 text-slate-300 ring-1 ring-slate-600/40">
              keine Daten
            </span>
          )}
          {payload?.level && (
            <span className="text-[11px] text-slate-500 font-mono">level={payload.level}</span>
          )}
        </h2>
        <span className="text-xs text-slate-500">{open ? '▲ einklappen' : '▼ ausklappen'}</span>
      </button>

      {open && (
        <div className="mt-4 space-y-4">
          {!payload && (
            <p className="text-xs text-slate-400">
              {isFailedOrderWithoutPayload
                ? 'Fuer diesen Scan wurde kein Report erzeugt — das Validation-Gate hat den Build geblockt, bevor die Defekte in die DB persistiert werden konnten. Klicke unten auf „Report neu erzeugen", um den Report mit dem aktualisierten Code-Stand erneut zu rendern.'
                : 'Keine Validation-Warnungen verfuegbar (z.B. historischer Scan vor Migration 028).'}
            </p>
          )}

          {payload && (
            <div className="flex items-baseline gap-3 text-xs text-slate-400 flex-wrap">
              <span>
                Status:{' '}
                <span className={passed ? 'text-emerald-300' : 'text-red-300'}>
                  {passed ? 'passed' : 'failed'}
                </span>
              </span>
              <span>Checks ausgefuehrt: {payload.checks_run?.join(', ') || '—'}</span>
              {payload.checks_skipped && payload.checks_skipped.length > 0 && (
                <span>uebersprungen: {payload.checks_skipped.join(', ')}</span>
              )}
            </div>
          )}

          {grouped && Object.keys(grouped).length > 0 && (
            <div className="space-y-3">
              {Object.entries(grouped).map(([check, issues]) => (
                <div key={check} className="rounded-lg bg-slate-950/30 p-3">
                  <div className="text-xs font-medium text-slate-300 mb-2 flex items-baseline gap-2">
                    {CHECK_LABELS[check] ?? check}
                    <span className="text-[11px] text-slate-500 font-mono">({check})</span>
                    <span className="text-[11px] text-slate-500">· {issues.length}</span>
                  </div>
                  <ul className="space-y-1.5">
                    {issues.map((i, idx) => (
                      <IssueRow key={`${check}-${idx}`} issue={i} />
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          )}

          {grouped && Object.keys(grouped).length === 0 && (
            <p className="text-xs text-emerald-300">
              Keine Validation-Defekte — alle Checks sauber.
            </p>
          )}

          {showRequeueButton && (
            <div className="border-t border-slate-800 pt-4 flex items-center justify-between gap-3 flex-wrap">
              <p className="text-xs text-slate-400 max-w-md">
                Nach Pruefung der Warnungen kannst du den Report neu erzeugen — der
                Report-Worker baut den PDF mit den persistierten Scan-Daten und dem
                aktuellen Code-Stand neu.
              </p>
              <button
                type="button"
                onClick={handleRequeue}
                disabled={requeuing}
                className="text-xs font-medium px-4 py-2 rounded-lg bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30 hover:bg-cyan-500/25 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {requeuing ? 'Wird gequeued…' : 'Report neu erzeugen'}
              </button>
            </div>
          )}

          {requeueMsg && (
            <div
              className={`text-xs rounded-lg px-3 py-2 ${
                requeueMsg.kind === 'ok'
                  ? 'bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-500/30'
                  : 'bg-red-500/10 text-red-300 ring-1 ring-red-500/30'
              }`}
            >
              {requeueMsg.text}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

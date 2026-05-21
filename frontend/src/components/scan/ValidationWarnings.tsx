'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  requeueReport,
  getFindingOverrides,
  setFindingOverride,
  deleteFindingOverride,
  type FindingOverride,
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

function SeverityPill({ severity, ignored }: { severity: string; ignored?: boolean }) {
  if (ignored) {
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] font-medium uppercase tracking-wide bg-slate-500/15 text-slate-400 ring-1 ring-slate-500/30 line-through">
        {severity}
      </span>
    );
  }
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

interface IssueRowProps {
  orderId: string;
  issue: ValidationIssuePayload;
  overrides: FindingOverride[];           // alle overrides fuer dieses finding_id
  onOverrideChange: () => void;           // parent refresht overrides nach Aktion
}

function IssueRow({ orderId, issue, overrides, onOverrideChange }: IssueRowProps) {
  const [showDetail, setShowDetail] = useState(false);
  const [showOverride, setShowOverride] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [customValue, setCustomValue] = useState<string>('');

  const hasDetail = issue.detail && Object.keys(issue.detail).length > 0;
  const isCvssMismatch = issue.check === 'cvss' && issue.message.includes('weicht von Vektor');
  const ignored = overrides.some((o) => o.field === '_ignored' && o.value === true);

  // Override-Status fuer die cvss_score-Spalte (falls schon gesetzt)
  const scoreOverride = overrides.find((o) => o.field === 'cvss_score');

  // Werte aus dem Issue-Detail (Claude vs Computed)
  const claudeScore = (issue.detail?.cvss_score as number | undefined) ?? null;
  const computedScore = (issue.detail?.computed as number | undefined) ?? null;

  const apply = useCallback(
    async (field: string, value: unknown) => {
      setBusy(true);
      setErr(null);
      const res = await setFindingOverride(orderId, issue.finding_id || '', field, value);
      setBusy(false);
      if (res.success) {
        onOverrideChange();
        setShowOverride(false);
      } else {
        setErr(res.error || 'Override fehlgeschlagen.');
      }
    },
    [orderId, issue.finding_id, onOverrideChange],
  );

  const remove = useCallback(
    async (field: string) => {
      setBusy(true);
      setErr(null);
      const res = await deleteFindingOverride(orderId, issue.finding_id || '', field);
      setBusy(false);
      if (res.success) {
        onOverrideChange();
      } else {
        setErr(res.error || 'Override-Entfernen fehlgeschlagen.');
      }
    },
    [orderId, issue.finding_id, onOverrideChange],
  );

  return (
    <li className={`border-l-2 pl-3 py-1.5 ${ignored ? 'border-slate-700 opacity-60' : 'border-slate-800'}`}>
      <div className="flex items-baseline gap-2 flex-wrap text-xs">
        <SeverityPill severity={issue.severity} ignored={ignored} />
        {issue.finding_id && (
          <span className="font-mono text-[11px] text-slate-400">{issue.finding_id}</span>
        )}
        <span className="text-slate-200 break-words">{issue.message}</span>
        {scoreOverride && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30 uppercase tracking-wide">
            korrigiert: {String(scoreOverride.value)}
          </span>
        )}
        {ignored && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-500/15 text-slate-300 ring-1 ring-slate-500/30 uppercase tracking-wide">
            geprüft
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">
          {issue.finding_id && !ignored && (
            <button
              type="button"
              onClick={() => setShowOverride((v) => !v)}
              className="text-[11px] text-cyan-400 hover:text-cyan-300"
              disabled={busy}
            >
              {showOverride ? '✕ Override schließen' : '⚙ Korrigieren'}
            </button>
          )}
          {issue.finding_id && ignored && (
            <button
              type="button"
              onClick={() => remove('_ignored')}
              className="text-[11px] text-amber-400 hover:text-amber-300"
              disabled={busy}
            >
              Markierung entfernen
            </button>
          )}
          {hasDetail && (
            <button
              type="button"
              onClick={() => setShowDetail((v) => !v)}
              className="text-[11px] text-slate-500 hover:text-slate-300"
            >
              {showDetail ? 'Details ▲' : 'Details ▼'}
            </button>
          )}
        </div>
      </div>

      {showDetail && hasDetail && (
        <pre className="mt-2 text-[11px] text-slate-400 bg-slate-950/60 rounded p-2 overflow-x-auto">
          {JSON.stringify(issue.detail, null, 2)}
        </pre>
      )}

      {showOverride && issue.finding_id && (
        <div className="mt-2 p-3 rounded-lg bg-slate-950/60 ring-1 ring-slate-800 space-y-2">
          {isCvssMismatch && (
            <div>
              <p className="text-[11px] text-slate-400 mb-2">
                CVSS-Score korrigieren — der Vektor-berechnete Wert ist die mathematisch
                korrekte Wahrheit, Claude rundet manchmal. Du kannst aber auch einen
                eigenen Wert setzen.
              </p>
              <div className="flex items-center gap-2 flex-wrap">
                {claudeScore !== null && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => apply('cvss_score', claudeScore)}
                    className="text-xs px-3 py-1.5 rounded-lg bg-slate-700/40 text-slate-200 ring-1 ring-slate-600 hover:bg-slate-700/60 disabled:opacity-50"
                  >
                    Claude: {claudeScore}
                  </button>
                )}
                {computedScore !== null && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => apply('cvss_score', computedScore)}
                    className="text-xs px-3 py-1.5 rounded-lg bg-cyan-500/15 text-cyan-200 ring-1 ring-cyan-500/30 hover:bg-cyan-500/25 disabled:opacity-50"
                  >
                    Computed: {computedScore} (empfohlen)
                  </button>
                )}
                <input
                  type="number"
                  step="0.1"
                  min="0"
                  max="10"
                  value={customValue}
                  onChange={(e) => setCustomValue(e.target.value)}
                  placeholder="eigener Wert (0–10)"
                  className="text-xs px-2 py-1.5 rounded-lg bg-slate-900 text-slate-200 ring-1 ring-slate-700 w-32 placeholder:text-slate-600"
                />
                <button
                  type="button"
                  disabled={busy || !customValue}
                  onClick={() => apply('cvss_score', Number(customValue))}
                  className="text-xs px-3 py-1.5 rounded-lg bg-emerald-500/15 text-emerald-200 ring-1 ring-emerald-500/30 hover:bg-emerald-500/25 disabled:opacity-50"
                >
                  Custom übernehmen
                </button>
                {scoreOverride && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => remove('cvss_score')}
                    className="text-xs px-3 py-1.5 rounded-lg bg-red-500/10 text-red-300 ring-1 ring-red-500/30 hover:bg-red-500/20 disabled:opacity-50"
                  >
                    Override entfernen
                  </button>
                )}
              </div>
            </div>
          )}

          {!isCvssMismatch && (
            <div>
              <p className="text-[11px] text-slate-400 mb-2">
                Diese Warnung lässt sich nicht automatisch korrigieren. Du kannst sie
                aber als „geprüft" markieren — sie verschwindet dann aus der aktiven
                Liste, das Finding bleibt im Report.
              </p>
            </div>
          )}

          <div className="border-t border-slate-800 pt-2 flex items-center gap-2 flex-wrap">
            <button
              type="button"
              disabled={busy}
              onClick={() => apply('_ignored', true)}
              className="text-xs px-3 py-1.5 rounded-lg bg-slate-700/40 text-slate-300 ring-1 ring-slate-600 hover:bg-slate-700/60 disabled:opacity-50"
            >
              ✓ Als geprüft markieren
            </button>
          </div>

          {err && (
            <div className="text-[11px] text-red-300 bg-red-500/10 rounded px-2 py-1 ring-1 ring-red-500/30">
              {err}
            </div>
          )}
        </div>
      )}
    </li>
  );
}

export default function ValidationWarnings({ orderId, orderStatus, payload }: Props) {
  const [open, setOpen] = useState(false);
  const [requeuing, setRequeuing] = useState(false);
  const [requeueMsg, setRequeueMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [overrides, setOverrides] = useState<FindingOverride[]>([]);

  const loadOverrides = useCallback(async () => {
    const res = await getFindingOverrides(orderId);
    if (res.success && res.data) {
      setOverrides(res.data.overrides);
    }
  }, [orderId]);

  useEffect(() => {
    if (open) loadOverrides();
  }, [open, loadOverrides]);

  // Indexiere overrides nach finding_id für schnellen Lookup
  const overridesByFinding = useMemo(() => {
    const m: Record<string, FindingOverride[]> = {};
    for (const o of overrides) {
      (m[o.findingId] ??= []).push(o);
    }
    return m;
  }, [overrides]);

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
    if (!confirm(
      'Report für diesen Scan neu erzeugen? Der Report-Worker baut den PDF anhand der bestehenden Scan-Daten neu — inklusive aller bereits gesetzten Overrides.',
    )) {
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

  const overrideCount = overrides.length;

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
          {overrideCount > 0 && (
            <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30">
              {overrideCount} Override{overrideCount === 1 ? '' : 's'} aktiv
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
                ? 'Für diesen Scan wurde kein Report erzeugt — das Validation-Gate hat den Build geblockt, bevor die Defekte in die DB persistiert werden konnten. Klicke unten auf „Report neu erzeugen", um den Report mit dem aktualisierten Code-Stand erneut zu rendern.'
                : 'Keine Validation-Warnungen verfügbar (z.B. historischer Scan vor Migration 028).'}
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
              <span>Checks ausgeführt: {payload.checks_run?.join(', ') || '—'}</span>
              {payload.checks_skipped && payload.checks_skipped.length > 0 && (
                <span>übersprungen: {payload.checks_skipped.join(', ')}</span>
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
                      <IssueRow
                        key={`${check}-${idx}-${i.finding_id ?? 'none'}`}
                        orderId={orderId}
                        issue={i}
                        overrides={i.finding_id ? overridesByFinding[i.finding_id] ?? [] : []}
                        onOverrideChange={loadOverrides}
                      />
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
                Nach Prüfung der Warnungen den Report neu erzeugen — Overrides werden vor
                Validation-Gate und PDF-Render appliziert.
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

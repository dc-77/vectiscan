'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { validateTargets, TargetValidation } from '@/lib/api';

export type TargetEntry = { raw_input: string; exclusions: string[] };

const MAX_TARGETS = 10;
const MAX_CIDR = 1;

const TYPE_LABELS: Record<string, string> = {
  fqdn_root: 'Root-Domain',
  fqdn_specific: 'Subdomain',
  ipv4: 'IPv4',
  cidr: 'CIDR',
};

const TYPE_COLORS: Record<string, string> = {
  fqdn_root: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  fqdn_specific: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
  ipv4: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  cidr: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
};

function errorMessage(err: string | undefined): string {
  switch (err) {
    case 'empty_input': return '';
    case 'parse_failed': return 'Ungültig — FQDN, IPv4, CIDR oder Subnetzmaske erwartet';
    case 'cidr_too_large': return 'CIDR zu groß — maximal /24 erlaubt';
    default: return err ? `Fehler: ${err}` : '';
  }
}

function warningMessage(w: string): string {
  if (w.startsWith('duplicate_of_row_')) {
    return `Dublette zu Zeile ${w.replace('duplicate_of_row_', '')}`;
  }
  return w;
}

interface TargetInputProps {
  value: TargetEntry[];
  onChange: (entries: TargetEntry[]) => void;
  disabled?: boolean;
}

export default function TargetInput({ value, onChange, disabled = false }: TargetInputProps) {
  const [validations, setValidations] = useState<TargetValidation[]>([]);
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set());
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastKeyRef = useRef<string>('');

  const serialKey = useMemo(
    () => value.map(t => t.raw_input.trim()).join(''),
    [value],
  );

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    const nonEmpty = value.some(t => t.raw_input.trim() !== '');
    if (!nonEmpty) {
      setValidations([]);
      lastKeyRef.current = '';
      return;
    }

    debounceRef.current = setTimeout(async () => {
      if (lastKeyRef.current === serialKey) return;
      lastKeyRef.current = serialKey;
      const payload: TargetEntry[] = value.map(t => ({
        raw_input: t.raw_input.trim(),
        exclusions: t.exclusions,
      }));
      try {
        const res = await validateTargets(payload);
        if (res.success && res.data) {
          setValidations(res.data.targets);
        }
      } catch { /* ignore transient errors */ }
    }, 400);

    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [serialKey, value]);

  const validations_ = validations.length === value.length ? validations : [];
  const cidrCount = validations_.filter(v => v.valid && v.target_type === 'cidr').length;

  const updateEntry = (i: number, patch: Partial<TargetEntry>) => {
    const next = value.map((entry, idx) => idx === i ? { ...entry, ...patch } : entry);
    onChange(next);
  };

  const addRow = () => {
    if (value.length >= MAX_TARGETS || disabled) return;
    onChange([...value, { raw_input: '', exclusions: [] }]);
  };

  const removeRow = (i: number) => {
    if (disabled) return;
    const next = value.filter((_, idx) => idx !== i);
    onChange(next.length === 0 ? [{ raw_input: '', exclusions: [] }] : next);
    setExpandedRows(prev => {
      const nextSet = new Set<number>();
      prev.forEach(idx => {
        if (idx < i) nextSet.add(idx);
        else if (idx > i) nextSet.add(idx - 1);
      });
      return nextSet;
    });
  };

  const toggleExpand = (i: number) => {
    setExpandedRows(prev => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="text-sm text-gray-400">Welche Ziele sollen gescannt werden?</p>
        <div className="flex items-center gap-2 text-[11px] font-mono">
          <span className={`px-2 py-0.5 rounded ${value.length >= MAX_TARGETS ? 'bg-amber-500/20 text-amber-300' : 'bg-[#2DD4BF]/10 text-[#2DD4BF]'}`}>
            {value.length}/{MAX_TARGETS} Zeilen
          </span>
          <span className={`px-2 py-0.5 rounded ${cidrCount > MAX_CIDR ? 'bg-red-500/20 text-red-300' : 'bg-slate-700/50 text-slate-400'}`}>
            {cidrCount}/{MAX_CIDR} CIDR
          </span>
        </div>
      </div>

      <div className="space-y-2">
        {value.map((entry, i) => {
          const v = validations_[i];
          const isExpanded = expandedRows.has(i);
          const hasInput = entry.raw_input.trim() !== '';
          const typeKey = v?.target_type;
          const errMsg = v && !v.valid && hasInput ? errorMessage(v.error) : '';
          const warnings = v?.warnings || [];

          return (
            <div key={i} className="space-y-1.5">
              <div className="flex gap-2 items-start">
                <div className="flex-1 space-y-1.5">
                  <div className="flex gap-2 items-center">
                    <input
                      type="text"
                      value={entry.raw_input}
                      onChange={e => updateEntry(i, { raw_input: e.target.value })}
                      disabled={disabled}
                      placeholder="beispiel.de, 85.22.47.34 oder 85.22.47.0/24"
                      className="flex-1 bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#2DD4BF] focus:ring-1 focus:ring-[#2DD4BF] text-sm font-mono disabled:opacity-50"
                    />
                    {typeKey && v?.valid && (
                      <span className={`text-[10px] font-medium px-2 py-1 rounded border whitespace-nowrap ${TYPE_COLORS[typeKey]}`}>
                        {TYPE_LABELS[typeKey]}
                        {v.expanded_count_estimate && v.expanded_count_estimate > 1
                          ? ` · ~${v.expanded_count_estimate} IPs` : ''}
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => toggleExpand(i)}
                      disabled={disabled}
                      className="text-[10px] text-slate-500 hover:text-slate-300 px-2 py-1 rounded border border-slate-700 hover:border-slate-600 transition-colors disabled:opacity-50"
                      title="Erweiterte Einstellungen"
                    >
                      {isExpanded ? 'Weniger' : 'Erweitert'}
                    </button>
                    {value.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removeRow(i)}
                        disabled={disabled}
                        className="text-red-400 hover:text-red-300 px-2 transition-colors flex-shrink-0 disabled:opacity-50"
                        title="Zeile entfernen"
                      >x</button>
                    )}
                  </div>

                  {errMsg && (
                    <p className="text-[11px] text-red-400">{errMsg}</p>
                  )}
                  {warnings.map((w, wi) => (
                    <p key={wi} className="text-[11px] text-amber-300">{warningMessage(w)}</p>
                  ))}

                  {isExpanded && (
                    <div className="bg-[#0F172A] border border-gray-800 rounded-lg p-3 space-y-2">
                      <label className="block text-[11px] font-medium text-slate-400">
                        Exclusions (Glob-Muster, eine pro Zeile)
                      </label>
                      <textarea
                        value={entry.exclusions.join('\n')}
                        onChange={e => {
                          const lines = e.target.value.split('\n').map(l => l.trim()).filter(Boolean);
                          updateEntry(i, { exclusions: lines });
                        }}
                        disabled={disabled}
                        rows={3}
                        placeholder={'*.dev.example.com\n85.22.47.50\n85.22.47.48/29'}
                        className="w-full bg-[#1e293b] border border-gray-700 rounded px-3 py-2 text-white placeholder-gray-600 focus:outline-none focus:border-[#2DD4BF] text-xs font-mono resize-y disabled:opacity-50"
                      />
                      <p className="text-[10px] text-slate-600">
                        Unterstützt: FQDN-Glob (*.dev.example.com), exakte FQDN, Einzel-IP, Sub-CIDR.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {cidrCount > MAX_CIDR && (
        <p className="text-xs text-red-400">
          Maximal {MAX_CIDR} CIDR-Eintrag pro Auftrag erlaubt.
        </p>
      )}

      {value.length < MAX_TARGETS && (
        <button
          type="button"
          onClick={addRow}
          disabled={disabled}
          className="text-xs font-medium px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
          style={{ color: '#2DD4BF', border: '1px solid rgba(45,212,191,0.25)' }}
        >
          + Target hinzufügen
        </button>
      )}

      <p className="text-xs text-gray-600">
        FQDN (beispiel.de), IPv4 (1.2.3.4), CIDR (1.2.3.0/24) oder Subnetzmaske (1.2.3.4/255.255.255.0).
        Maximal {MAX_TARGETS} Zeilen, höchstens {MAX_CIDR} CIDR, kleinster erlaubter Prefix ist /24.
      </p>
    </div>
  );
}

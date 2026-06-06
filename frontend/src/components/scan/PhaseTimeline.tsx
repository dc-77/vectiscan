'use client';

/**
 * PhaseTimeline — ruhiger Klartext-Phasen-Indikator (VEC-314, §5.3, behebt H8).
 *
 * Zeigt den Live-Fortschritt eines laufenden Scans als kalme vertikale
 * Timeline mit Kunden-Klartext ("Tech-Erkennung läuft") statt roher
 * Queue-/Phasen-Codes. Bewusst zurückhaltend gestaltet: die cinematic
 * Energie (Radar, Terminal) bleibt dem opt-in Live-Terminal vorbehalten.
 *
 * Keine eigenen Animationen außer dem StatusChip-Spinner (der bereits
 * global hinter `prefers-reduced-motion` deaktiviert wird, globals.css).
 */

import StatusChip from '@/components/ds/StatusChip';
import { TONE_COLOR } from '@/lib/status';

interface Phase {
  /** Kanonische Worker-Phasen-Keys, die diesen Schritt markieren. */
  keys: string[];
  /** Kunden-Klartext-Label. */
  label: string;
  /** Status-Key, dessen StatusChip-Klartext im aktiven Zustand gezeigt wird. */
  statusKey: string;
}

// Reihenfolge entspricht der Scan-Pipeline (siehe scan-worker 6-Phasen-Flow).
const PHASES: Phase[] = [
  { keys: ['passive_intel'], label: 'Aufklärung', statusKey: 'passive_intel' },
  { keys: ['dns_recon'], label: 'DNS-Analyse', statusKey: 'dns_recon' },
  { keys: ['scan_phase1'], label: 'Tech-Erkennung', statusKey: 'scan_phase1' },
  { keys: ['scan_phase2'], label: 'Schwachstellen-Scan', statusKey: 'scan_phase2' },
  { keys: ['scan_phase3'], label: 'KI-Korrelation', statusKey: 'scan_phase3' },
  { keys: ['scan_complete', 'report_generating'], label: 'Bericht wird erstellt', statusKey: 'report_generating' },
];

type PhaseState = 'done' | 'active' | 'pending';

export default function PhaseTimeline({
  status,
  phase,
}: {
  /** Order-Status (z.B. 'scanning', 'report_generating'). */
  status: string;
  /** Aktuelle Worker-Phase aus order.progress.phase (kann null sein). */
  phase: string | null;
}) {
  // Aktiven Schritt bestimmen: zuerst über die Worker-Phase, sonst über den
  // groben Order-Status. Default = Schritt 0 (Aufklärung), sobald irgendetwas läuft.
  const marker = phase ?? status;
  let activeIdx = PHASES.findIndex((p) => p.keys.includes(marker));
  if (activeIdx === -1) {
    // report_generating ohne Phase → letzter Schritt; sonst Start.
    activeIdx = status === 'report_generating' ? PHASES.length - 1 : 0;
  }

  return (
    <section
      aria-label="Scan-Fortschritt"
      className="rounded-xl border border-slate-800 bg-slate-900/60 p-5"
    >
      <h2 className="text-sm font-medium text-slate-300 mb-4">Scan-Fortschritt</h2>
      <ol className="space-y-0">
        {PHASES.map((p, i) => {
          const state: PhaseState = i < activeIdx ? 'done' : i === activeIdx ? 'active' : 'pending';
          const isLast = i === PHASES.length - 1;
          const doneColor = TONE_COLOR['success']; // abgeschlossene Phasen → grün (Jakob's Law)
          const dotColor =
            state === 'done' ? doneColor
            : state === 'active' ? TONE_COLOR['active']
            : 'var(--tone-neutral)';
          return (
            <li key={p.label} className="flex gap-3">
              {/* Indikator-Spalte: Punkt + Verbindungslinie */}
              <div className="flex flex-col items-center">
                <span
                  className="mt-1 h-2.5 w-2.5 rounded-full shrink-0"
                  style={{
                    backgroundColor: state === 'pending'
                      ? 'transparent'
                      : `color-mix(in srgb, ${dotColor} 90%, transparent)`,
                    border: `2px solid color-mix(in srgb, ${dotColor} ${state === 'pending' ? 40 : 90}%, transparent)`,
                  }}
                  aria-hidden
                />
                {!isLast && (
                  <span
                    className="w-px flex-1 my-1"
                    style={{
                      minHeight: 18,
                      backgroundColor: i < activeIdx
                        ? `color-mix(in srgb, ${doneColor} 50%, transparent)`
                        : 'var(--border-subtle, rgba(148,163,184,0.18))',
                    }}
                    aria-hidden
                  />
                )}
              </div>
              {/* Label-Spalte */}
              <div className="pb-4 flex items-center gap-2 min-w-0">
                {state === 'active' ? (
                  <StatusChip status={p.statusKey} size="sm" />
                ) : (
                  <span
                    className={`text-sm ${state === 'done' ? 'text-slate-300' : 'text-slate-600'}`}
                  >
                    {p.label}
                  </span>
                )}
                {state === 'done' && (
                  <span className="text-[11px] text-slate-600" aria-label="abgeschlossen">✓</span>
                )}
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}

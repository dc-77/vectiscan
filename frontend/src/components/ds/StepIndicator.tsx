// ── DS-Primitive: StepIndicator (VEC-312, §5.2) ────────────────
// Serial-Position-Fortschritt für den Scan-Wizard (Zeigarnik: der
// Fortschritt bleibt sichtbar). Single-source der Wizard-Schritte.
// Farb-Unabhängigkeit (A11y §8): jeder Schritt trägt Nummer + Label,
// erledigte zusätzlich ein Häkchen-Glyph — die Bedeutung steckt nie
// nur in der Farbe. Aktueller Schritt via aria-current="step".

export interface WizardStep {
  /** stabile Kennung des Schritts (target | package | upgrade | confirm …). */
  id: string;
  /** Klartext-Label (deutsch). */
  label: string;
}

function CheckGlyph() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}

export default function StepIndicator({
  steps,
  current,
  className = '',
}: {
  steps: WizardStep[];
  /** Index (0-basiert) des aktuellen Schritts. */
  current: number;
  className?: string;
}) {
  return (
    <nav aria-label="Fortschritt" className={className}>
      <ol className="flex items-center justify-center gap-1.5 sm:gap-2 flex-wrap">
        {steps.map((s, i) => {
          const done = i < current;
          const active = i === current;
          const tone = done || active ? 'var(--tone-active)' : 'var(--text-dim)';
          return (
            <li key={s.id} className="flex items-center gap-1.5 sm:gap-2">
              <span
                className="flex items-center gap-2"
                aria-current={active ? 'step' : undefined}
              >
                <span
                  className="shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-xs font-semibold transition-colors"
                  style={{
                    color: active ? 'var(--slate)' : tone,
                    backgroundColor: active
                      ? 'var(--tone-active)'
                      : done
                        ? 'color-mix(in srgb, var(--tone-active) 16%, transparent)'
                        : 'transparent',
                    border: `1.5px solid color-mix(in srgb, ${tone} ${active ? 100 : done ? 40 : 36}%, transparent)`,
                  }}
                >
                  <span className="sr-only">{`Schritt ${i + 1}: `}</span>
                  {done ? <CheckGlyph /> : i + 1}
                </span>
                <span
                  className={`text-xs sm:text-sm font-medium whitespace-nowrap ${active ? '' : 'hidden sm:inline'}`}
                  style={{ color: active || done ? 'var(--text)' : 'var(--text-dim)' }}
                >
                  {s.label}
                </span>
              </span>
              {i < steps.length - 1 && (
                <span
                  aria-hidden
                  className="w-4 sm:w-8 h-px"
                  style={{
                    backgroundColor: done
                      ? 'var(--tone-active)'
                      : 'var(--border-muted, rgba(148,163,184,0.25))',
                  }}
                />
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

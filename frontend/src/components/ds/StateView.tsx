import Link from 'next/link';
import type { ReactNode } from 'react';

// ── DS-Primitive: StateView (VEC-306) ───────────────────────────
// Kanonisches Muster für Leer-, Fehler-, Access- und Loading-Lücken.
// Von Onboarding (VEC-293) und Permission-/Abo-Gating (VEC-294)
// mitbenutzt, damit es nur EINE Empty-/Error-Sprache gibt.
// Plain-Language-Texte (A11y §8), Anti-Sackgasse: jeder State trägt
// mindestens eine sinnvolle Aktion.

export type StateVariant = 'empty' | 'error' | 'denied' | 'info';

export interface StateAction {
  label: string;
  href?: string;
  onClick?: () => void;
  /** primary = Teal-Akzent, secondary = Outline. */
  variant?: 'primary' | 'secondary';
}

const VARIANT_TONE: Record<StateVariant, string> = {
  empty:  'var(--tone-active)',
  info:   'var(--tone-info)',
  error:  'var(--tone-danger)',
  denied: 'var(--tone-warn)',
};

function DefaultIcon({ variant }: { variant: StateVariant }) {
  const common = {
    width: 28, height: 28, viewBox: '0 0 24 24', fill: 'none',
    stroke: 'currentColor', strokeWidth: 1.5,
    strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const,
    'aria-hidden': true,
  };
  if (variant === 'error')
    return <svg {...common}><circle cx="12" cy="12" r="9" /><path d="M12 8v4" /><path d="M12 16h.01" /></svg>;
  if (variant === 'denied')
    return <svg {...common}><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></svg>;
  if (variant === 'info')
    return <svg {...common}><circle cx="12" cy="12" r="9" /><path d="M12 11v5" /><path d="M12 8h.01" /></svg>;
  // empty — Schild (Marke)
  return <svg {...common}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>;
}

function ActionButton({ action }: { action: StateAction }) {
  const isPrimary = (action.variant ?? 'primary') === 'primary';
  const cls = 'px-5 py-2.5 rounded-lg text-sm font-semibold transition-all min-h-[44px] inline-flex items-center justify-center';
  const style = isPrimary
    ? { backgroundColor: 'var(--tone-active)', color: 'var(--slate)' }
    : { color: 'var(--text)', border: '1px solid var(--border-subtle)' };
  if (action.href) {
    return <Link href={action.href} className={cls} style={style}>{action.label}</Link>;
  }
  return <button type="button" onClick={action.onClick} className={cls} style={style}>{action.label}</button>;
}

export default function StateView({
  variant = 'empty',
  title,
  description,
  icon,
  actions = [],
  children,
  className = '',
}: {
  variant?: StateVariant;
  title: string;
  description?: ReactNode;
  icon?: ReactNode;
  actions?: StateAction[];
  children?: ReactNode;
  className?: string;
}) {
  const tone = VARIANT_TONE[variant];
  return (
    <div className={`text-center py-14 px-4 ${className}`} role={variant === 'error' ? 'alert' : undefined}>
      <div
        className="w-16 h-16 rounded-full mx-auto mb-4 flex items-center justify-center"
        style={{
          color: tone,
          backgroundColor: `color-mix(in srgb, ${tone} 10%, transparent)`,
          border: `2px solid color-mix(in srgb, ${tone} 24%, transparent)`,
        }}
      >
        {icon ?? <DefaultIcon variant={variant} />}
      </div>
      <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>{title}</h2>
      {description && (
        <p className="text-sm max-w-sm mx-auto mt-2" style={{ color: 'var(--text-muted)' }}>{description}</p>
      )}
      {children && <div className="mt-4">{children}</div>}
      {actions.length > 0 && (
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-5">
          {actions.map((a, i) => <ActionButton key={i} action={a} />)}
        </div>
      )}
    </div>
  );
}

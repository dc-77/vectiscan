'use client';

import { useEffect, useRef, type ReactNode } from 'react';

// ── DS-Primitive: ConfirmDialog (VEC-306, behebt H7) ────────────
// Accessibler Bestätigungs-Modal als Ersatz für natives confirm().
// Fokus-Trap (Escape schließt, Fokus auf Cancel beim Öffnen),
// role=dialog/aria-modal, Klick auf Backdrop schließt. Optionaler
// children-Slot (z. B. Token-Eingabe). Destruktive Aktionen tönen rot.

export default function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = 'Bestätigen',
  cancelLabel = 'Abbrechen',
  destructive = false,
  busy = false,
  confirmDisabled = false,
  onConfirm,
  onCancel,
  children,
}: {
  open: boolean;
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
  busy?: boolean;
  confirmDisabled?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: ReactNode;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !busy) onCancel(); };
    window.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    cancelRef.current?.focus();
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [open, busy, onCancel]);

  if (!open) return null;

  const accent = destructive ? 'var(--tone-danger)' : 'var(--tone-active)';

  return (
    <div
      className="fixed inset-0 z-[110] flex items-center justify-center p-4"
      style={{ backgroundColor: 'rgba(12,18,34,0.7)', backdropFilter: 'blur(4px)' }}
      onClick={() => { if (!busy) onCancel(); }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        className="w-full max-w-md rounded-2xl p-6 shadow-2xl animate-[fadeIn_0.2s_ease-out]"
        style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border-muted)' }}
        onClick={e => e.stopPropagation()}
      >
        <h2 id="confirm-title" className="text-base font-semibold" style={{ color: 'var(--text)' }}>{title}</h2>
        {description && (
          <div className="text-sm mt-2" style={{ color: 'var(--text-muted)' }}>{description}</div>
        )}
        {children && <div className="mt-4">{children}</div>}
        <div className="flex items-center justify-end gap-2 mt-6">
          <button
            ref={cancelRef}
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="px-4 py-2 rounded-lg text-sm font-medium transition-colors min-h-[44px] disabled:opacity-40"
            style={{ color: 'var(--text-muted)', border: '1px solid var(--border-muted)' }}
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={busy || confirmDisabled}
            className="px-4 py-2 rounded-lg text-sm font-semibold transition-all min-h-[44px] disabled:opacity-40"
            style={{ backgroundColor: accent, color: 'var(--slate)' }}
          >
            {busy ? 'Bitte warten…' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

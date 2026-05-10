'use client';

/**
 * ScreenshotLightbox — Full-Screen-Modal fuer Site-Screenshots.
 *
 * Redesign Mai 2026: Persistentes Thumbnail in der Host-Card wurde durch
 * Action-Button ersetzt. Klick oeffnet diesen Modal mit voller Aufloesung.
 */

import { useEffect } from 'react';

import { useDrawerA11y } from '@/hooks/useDrawerA11y';

interface Props {
  url: string;
  hostLabel: string;
  onClose: () => void;
}

export function ScreenshotLightbox({ url, hostLabel, onClose }: Props) {
  const drawerRef = useDrawerA11y(true);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-label={`Screenshot ${hostLabel}`}
    >
      <div className="absolute inset-0 bg-black/80 backdrop-blur-sm" onClick={onClose} />
      <div
        ref={drawerRef}
        className="relative z-10 max-w-5xl max-h-[90vh] flex flex-col"
      >
        <div className="flex items-center justify-between gap-4 mb-2 px-2">
          <h3 className="text-sm font-mono text-slate-300 truncate">{hostLabel}</h3>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 text-xl leading-none px-2"
            aria-label="Schliessen"
          >
            ×
          </button>
        </div>
        <div className="overflow-auto rounded-lg border border-slate-700 bg-slate-950">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src={url}
            alt={`Screenshot ${hostLabel}`}
            className="block max-w-full"
          />
        </div>
        <a
          href={url}
          target="_blank"
          rel="noreferrer"
          className="mt-2 text-center text-xs text-cyan-400 hover:text-cyan-300 hover:underline"
        >
          In neuem Tab oeffnen ↗
        </a>
      </div>
    </div>
  );
}

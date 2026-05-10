'use client';

/**
 * useDrawerA11y — A11y-Helper fuer Modal/Drawer/Sheet-Komponenten.
 *
 * Liefert:
 * - Focus-Trap innerhalb des Drawer-DOM-Trees (Tab cycled)
 * - Body-Scroll-Lock waehrend Drawer offen
 * - Auto-Focus auf erstes focusable Element beim Mount
 *
 * Usage:
 *   const ref = useDrawerA11y(isOpen);
 *   return <div ref={ref}>...</div>;
 */

import { useEffect, useRef } from 'react';

export function useDrawerA11y(isOpen: boolean) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isOpen) return;
    const container = containerRef.current;
    if (!container) return;

    // Auto-Focus auf erstes focusable Element
    const focusables = container.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
    );
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (first) first.focus();

    // Focus-Trap: Tab cycled innerhalb des Drawers
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;
      if (focusables.length === 0) {
        e.preventDefault();
        return;
      }
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last?.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first?.focus();
      }
    };
    document.addEventListener('keydown', onKey);

    // Body-Scroll-Lock
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [isOpen]);

  return containerRef;
}

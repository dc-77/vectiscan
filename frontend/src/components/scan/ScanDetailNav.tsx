'use client';

/**
 * ScanDetailNav — sticky Sub-Nav unter dem Page-Header.
 *
 * Anchor-Links zu allen Sektionen + IntersectionObserver fuer active state.
 * Mobile: horizontal scrollbar.
 */

import { useEffect, useState } from 'react';

interface NavSection {
  id: string;
  label: string;
  count?: number;
}

interface Props {
  sections: NavSection[];
}

export function ScanDetailNav({ sections }: Props) {
  const [activeId, setActiveId] = useState<string | null>(null);

  useEffect(() => {
    const observers: IntersectionObserver[] = [];
    sections.forEach((s) => {
      const el = document.getElementById(s.id);
      if (!el) return;
      const obs = new IntersectionObserver(
        ([entry]) => {
          if (entry.isIntersecting) setActiveId(s.id);
        },
        { rootMargin: '-128px 0px -60% 0px', threshold: 0 },
      );
      obs.observe(el);
      observers.push(obs);
    });
    return () => { observers.forEach((o) => o.disconnect()); };
  }, [sections]);

  const handleClick = (e: React.MouseEvent<HTMLAnchorElement>, id: string) => {
    e.preventDefault();
    const el = document.getElementById(id);
    if (el) {
      const yOffset = -100; // Account for sticky header
      const y = el.getBoundingClientRect().top + window.scrollY + yOffset;
      window.scrollTo({ top: y, behavior: 'smooth' });
    }
  };

  return (
    <nav
      className="sticky top-0 z-30 -mx-4 md:-mx-8 px-4 md:px-8 py-2 bg-slate-950/95 backdrop-blur border-b border-slate-800"
      aria-label="Scan-Detail-Navigation"
    >
      <div className="max-w-6xl mx-auto flex items-center gap-1 overflow-x-auto scrollbar-thin">
        {sections.map((s) => {
          const active = activeId === s.id;
          return (
            <a
              key={s.id}
              href={`#${s.id}`}
              onClick={(e) => handleClick(e, s.id)}
              className={`
                inline-flex items-center gap-1.5 whitespace-nowrap rounded-md px-2.5 py-1 text-xs transition-colors
                ${active
                  ? 'bg-cyan-500/20 text-cyan-200 ring-1 ring-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }
              `}
            >
              {s.label}
              {s.count !== undefined && (
                <span className={`tabular-nums ${active ? 'text-cyan-300' : 'text-slate-500'}`}>
                  {s.count}
                </span>
              )}
            </a>
          );
        })}
      </div>
    </nav>
  );
}

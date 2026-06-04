'use client';

import { useEffect } from 'react';
import Link from 'next/link';
import { track } from '@/lib/analytics';

/** Feuert einmalig das Seitenaufruf-Event der WebCheck-Landingpage. */
export function LpView() {
  useEffect(() => { track('webcheck_lp_view'); }, []);
  return null;
}

/** /pricing-Link mit Sekundär-CTA-Tracking (Zwischenmetrik). */
export function PricingLink({
  href = '/pricing',
  className,
  style,
  children,
}: {
  href?: string;
  className?: string;
  style?: React.CSSProperties;
  children: React.ReactNode;
}) {
  return (
    <Link href={href} className={className} style={style} onClick={() => track('webcheck_pricing_click')}>
      {children}
    </Link>
  );
}

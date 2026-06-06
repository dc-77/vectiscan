'use client';

import { useEffect } from 'react';
import { usePathname, useSearchParams } from 'next/navigation';
import { trackPageview } from '@/lib/analytics';

/**
 * Feuert bei jeder Routen-Aenderung einen anonymen Pageview (VEC-36).
 * Muss in einer <Suspense>-Grenze stehen (useSearchParams).
 */
export default function AnalyticsBeacon() {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  useEffect(() => {
    if (!pathname) return;
    // Bewusst nur der Pfad (ohne Query) -> verhindert, dass beliebige
    // Query-Parameter (evtl. Tokens/PII) in analytics_events.path landen.
    // UTM-Parameter werden in trackPageview separat aus der URL gelesen.
    trackPageview(pathname);
  }, [pathname, searchParams]);

  return null;
}

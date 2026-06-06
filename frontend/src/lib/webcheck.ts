// WebCheck-Publish-Gate (VEC-92 Copy-Sign-off / VEC-117 Tracking / VEC-14 Isolation).
//
// Die /webcheck-Seite ist weiterhin `robots: noindex/nofollow` und nicht in der
// Navigation verlinkt, bis sie scharfgeschaltet ist (siehe src/app/webcheck/page.tsx).
// Die Marketing-CTAs auf Homepage/Pricing zeigen deshalb per Default den Fallback
// auf `/pricing#pakete`. Ein einzelner Build-Time-ENV-Flag schaltet die echten
// Free-WebCheck-Links scharf — reversibel, ohne pro Seite gehardcodete Gate-Logik.
//
// Aktivieren (sobald /webcheck aus noindex raus ist):
//   NEXT_PUBLIC_WEBCHECK_PUBLIC=true
//
// Quelle: VEC-272 Copy-Spec §5 (Gates) — „Carmack baut den Link feature-flag-/env-gated".

const flag = process.env.NEXT_PUBLIC_WEBCHECK_PUBLIC;

/** True, wenn der Free-WebCheck öffentlich verlinkt werden darf. */
export const WEBCHECK_PUBLIC = flag === 'true' || flag === '1';

export const WEBCHECK_HREF = '/webcheck';
export const WEBCHECK_FALLBACK_HREF = '/pricing#pakete';

/** Ziel des primären Free-WebCheck-CTA (gated). */
export function webcheckCtaHref(): string {
  return WEBCHECK_PUBLIC ? WEBCHECK_HREF : WEBCHECK_FALLBACK_HREF;
}

/** Label des primären Free-WebCheck-CTA (gated). */
export function webcheckCtaLabel(): string {
  return WEBCHECK_PUBLIC ? 'Kostenlosen WebCheck starten' : 'Pakete & Preise ansehen';
}

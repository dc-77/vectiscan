/**
 * Tracking-Seam für die Landingpages (VEC-90 / VEC-45 / VEC-117).
 *
 * VEC-45 liefert den consent-gated Analytics-Loader `VectiTrack` als
 * framework-agnostisches Drop-in (`tracking/analytics/analytics.js`). Dieser
 * Loader sendet NICHTS ohne Einwilligung `analytics` — Consent-Gating liegt
 * also bei VectiTrack, nicht hier.
 *
 * Dieses Modul ist die dünne Anbindung der Next.js-Landingpages an genau diesen
 * Seam. Solange VectiTrack (VEC-117 Scharfschalten) noch nicht geladen ist,
 * laufen Events in einen Buffer (`window.__vectiTrackQueue`) + dataLayer-Fallback,
 * gehen also nicht verloren und werden vom Loader beim Init nachgespielt.
 *
 * Event-Taxonomie (mit Greta/VEC-45 abzustimmen — siehe VEC-90-Kommentar):
 *   - webcheck_lp_view           Seitenaufruf der WebCheck-Landingpage
 *   - webcheck_cta_click         Klick auf Primär-CTA above the fold
 *   - webcheck_free_start_submit Absenden Free-Start-Formular (E-Mail+Domain)
 *   - webcheck_pricing_click     Klick auf Sekundär-CTA → /pricing
 */

export type TrackEvent =
  | 'webcheck_lp_view'
  | 'webcheck_cta_click'
  | 'webcheck_free_start_submit'
  | 'webcheck_pricing_click';

type TrackProps = Record<string, string | number | boolean | undefined>;

interface VectiTrackApi {
  track: (event: string, props?: TrackProps) => void;
}

declare global {
  interface Window {
    VectiTrack?: VectiTrackApi;
    __vectiTrackQueue?: Array<{ event: string; props?: TrackProps; ts: number }>;
    dataLayer?: Array<Record<string, unknown>>;
  }
}

/**
 * Feuert ein Tracking-Event über den VEC-45-Seam.
 * No-op auf dem Server; consent-gating übernimmt VectiTrack.
 */
export function track(event: TrackEvent, props?: TrackProps): void {
  if (typeof window === 'undefined') return;
  try {
    if (window.VectiTrack?.track) {
      window.VectiTrack.track(event, props);
      return;
    }
    // VectiTrack noch nicht geladen → puffern (Loader spielt nach) + dataLayer-Fallback.
    (window.__vectiTrackQueue ||= []).push({ event, props, ts: Date.now() });
    (window.dataLayer ||= []).push({ event, ...props });
  } catch {
    /* Tracking darf die Seite nie brechen. */
  }
}

/**
 * Leitet `quelle_kanal` aus UTM-Parametern / Referrer ab (Kanal-Attribution, §3.2).
 * Reine Heuristik im Client; die endgültige CRM-Normalisierung macht der
 * Lead-Router (VEC-45). Werte orientieren sich an der CRM-Spec
 * (SEO-H1/H2/H3, LinkedIn, Fachpartner, Direkt).
 */
export function deriveQuelleKanal(): { quelle_kanal: string; utm: Record<string, string> } {
  const utm: Record<string, string> = {};
  if (typeof window === 'undefined') return { quelle_kanal: 'Direkt', utm };

  const params = new URLSearchParams(window.location.search);
  for (const k of ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term']) {
    const v = params.get(k);
    if (v) utm[k] = v;
  }

  const src = (utm.utm_source || '').toLowerCase();
  const content = (utm.utm_content || '').toLowerCase();
  const ref = (typeof document !== 'undefined' ? document.referrer : '').toLowerCase();

  if (src.includes('linkedin') || ref.includes('linkedin')) return { quelle_kanal: 'LinkedIn', utm };
  if (src.includes('partner') || utm.utm_medium === 'partner') return { quelle_kanal: 'Fachpartner', utm };
  if (src === 'google' || src === 'bing' || utm.utm_medium === 'organic' || /google|bing|duckduckgo/.test(ref)) {
    // SEO-Hero-Asset-Attribution über utm_content (H1/H2/H3), sonst generisch SEO.
    if (content.includes('h1')) return { quelle_kanal: 'SEO-H1', utm };
    if (content.includes('h2')) return { quelle_kanal: 'SEO-H2', utm };
    if (content.includes('h3')) return { quelle_kanal: 'SEO-H3', utm };
    return { quelle_kanal: 'SEO', utm };
  }
  return { quelle_kanal: 'Direkt', utm };
}

/**
 * Cookieloses First-Party-Analytics (VEC-36).
 *
 * Sendet ausschliesslich anonyme Daten an /api/analytics/collect: aufgerufener
 * Pfad, Referrer-Domain und UTM-Parameter. KEINE personenbezogenen Daten, keine
 * Cookies, kein localStorage, kein Besucher-Identifier — daher einwilligungsfrei
 * (vgl. Datenschutzerklaerung Abschnitt 8). Ergaenzt den consent-gated
 * VectiTrack-Seam oben; beide koexistieren bewusst nebeneinander.
 */
const ANALYTICS_API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

export function trackPageview(path: string): void {
  if (typeof window === 'undefined') return;

  let referrer: string | undefined;
  try {
    // Nur Fremd-Referrer melden; interne Navigation hat keinen document.referrer
    // der eigenen Domain im Sinne der Reichweitenmessung.
    if (document.referrer) {
      const refHost = new URL(document.referrer).hostname;
      if (refHost && refHost !== window.location.hostname) {
        referrer = document.referrer;
      }
    }
  } catch {
    // ignore
  }

  let utmSource: string | undefined;
  let utmMedium: string | undefined;
  let utmCampaign: string | undefined;
  try {
    const params = new URLSearchParams(window.location.search);
    utmSource = params.get('utm_source') || undefined;
    utmMedium = params.get('utm_medium') || undefined;
    utmCampaign = params.get('utm_campaign') || undefined;
  } catch {
    // ignore
  }

  const payload = JSON.stringify({
    path,
    referrer,
    utmSource,
    utmMedium,
    utmCampaign,
    eventType: 'pageview',
  });

  // sendBeacon ueberlebt Seitenwechsel; fetch als Fallback. Fehler werden
  // bewusst verschluckt — Analytics darf den Nutzerfluss nie stoeren.
  try {
    const url = `${ANALYTICS_API_URL}/api/analytics/collect`;
    if (navigator.sendBeacon) {
      navigator.sendBeacon(url, new Blob([payload], { type: 'application/json' }));
    } else {
      void fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        keepalive: true,
      }).catch(() => {});
    }
  } catch {
    // ignore
  }
}

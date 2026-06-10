'use client';

// ── /subscriptions — Stripe-Checkout-Ergebnisseite (VEC-350) ─────────
// Ziel der Stripe `success_url`/`cancel_url` (api/src/lib/stripe.ts).
// Vorher zeigte diese Route 404 → Conversion-Killer direkt nach Zahlung.
// Liest den `checkout`-Query-Param (success|cancelled) und zeigt eine
// DS-konforme Bestätigung mit Anti-Sackgassen-Aktion (StateView, VEC-306).

import { Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import StateView from '@/components/ds/StateView';

function CheckoutResult() {
  const params = useSearchParams();
  const checkout = params.get('checkout');

  if (checkout === 'cancelled') {
    return (
      <StateView
        variant="info"
        title="Zahlung abgebrochen"
        description="Es wurde keine Zahlung durchgeführt und kein Abo aktiviert. Sie können den Vorgang jederzeit erneut starten."
        actions={[
          { label: 'Abo erneut starten', href: '/subscribe', variant: 'primary' },
          { label: 'Zum Dashboard', href: '/dashboard', variant: 'secondary' },
        ]}
      />
    );
  }

  // Default-/Erfolgspfad: Stripe leitet nach bestätigter Zahlung hierher.
  // Das Abo ist angelegt; die Aktivierung erfolgt über den
  // checkout.session.completed-Webhook und anschließende Admin-Freigabe.
  return (
    <StateView
      variant="info"
      title="Zahlung erfolgreich"
      description="Vielen Dank! Ihre Zahlung ist eingegangen und Ihr Abo wurde angelegt. Ihre Domains werden jetzt von einem Administrator geprüft und freigegeben. Nach der Freigabe startet der erste Scan automatisch."
      icon={
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <path d="M5 13l4 4L19 7" />
        </svg>
      }
      actions={[
        { label: 'Zum Dashboard', href: '/dashboard', variant: 'primary' },
        { label: 'Meine Abos', href: '/subscribe', variant: 'secondary' },
      ]}
    />
  );
}

export default function SubscriptionsPage() {
  return (
    <div className="flex-1 px-4 py-8 md:px-8">
      <div className="max-w-lg mx-auto">
        <Suspense fallback={null}>
          <CheckoutResult />
        </Suspense>
      </div>
    </div>
  );
}

import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import WebCheckFreeForm from '@/components/WebCheckFreeForm';

// Analytics-Seam stummschalten (kein window.VectiTrack im Test).
jest.mock('@/lib/analytics', () => ({
  track: jest.fn(),
  deriveQuelleKanal: jest.fn(() => ({ quelle_kanal: 'Direkt', utm: {} })),
}));

const API = 'http://localhost:4000';

function mockFetchOnce(status: number, body: unknown) {
  (global.fetch as jest.Mock).mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
}

beforeEach(() => {
  global.fetch = jest.fn();
});
afterEach(() => {
  jest.clearAllMocks();
});

describe('WebCheckFreeForm', () => {
  it('rendert das Start-Formular mit E-Mail + Domain', () => {
    render(<WebCheckFreeForm />);
    expect(screen.getByLabelText('E-Mail-Adresse')).toBeInTheDocument();
    expect(screen.getByLabelText('Ihre Domain')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Kostenlosen WebCheck starten/ })).toBeInTheDocument();
  });

  it('Marketing-Consent ist freiwillig und standardmäßig NICHT angekreuzt (Kopplungsverbot)', () => {
    render(<WebCheckFreeForm />);
    const checkbox = screen.getByRole('checkbox') as HTMLInputElement;
    expect(checkbox.checked).toBe(false);
    expect(checkbox.required).toBe(false); // entkoppelt: Report unabhängig von Einwilligung
  });

  it('validiert ungültige Domain ohne Netzwerk-Call', () => {
    render(<WebCheckFreeForm />);
    fireEvent.change(screen.getByLabelText('E-Mail-Adresse'), { target: { value: 'a@b.de' } });
    fireEvent.change(screen.getByLabelText('Ihre Domain'), { target: { value: 'nichtvalide' } });
    fireEvent.click(screen.getByRole('button', { name: /Kostenlosen WebCheck starten/ }));
    expect(screen.getByRole('alert')).toHaveTextContent(/gültige Domain/);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('postet an /api/webcheck/start mit marketing_consent=false und consent_text_version, zeigt dann die Verifizierung', async () => {
    mockFetchOnce(201, {
      success: true,
      data: {
        leadId: '11111111-1111-1111-1111-111111111111',
        domain: 'firma.de',
        verification: {
          token: 'tok123',
          methods: [
            { type: 'dns_txt', record: '_vectiscan-verify.firma.de', value: 'tok123' },
            { type: 'file', path: 'https://firma.de/.well-known/vectiscan-verify.txt', value: 'tok123' },
            { type: 'meta_tag', value: '<meta name="vectiscan-verify" content="tok123">' },
          ],
        },
      },
    });

    render(<WebCheckFreeForm />);
    fireEvent.change(screen.getByLabelText('E-Mail-Adresse'), { target: { value: 'kontakt@firma.de' } });
    fireEvent.change(screen.getByLabelText('Ihre Domain'), { target: { value: 'https://www.firma.de/pfad' } });
    fireEvent.click(screen.getByRole('button', { name: /Kostenlosen WebCheck starten/ }));

    await waitFor(() => expect(screen.getByText('Domain-Kontrolle nachweisen')).toBeInTheDocument());

    // URL + entkoppelte Consent-Felder im Payload prüfen
    const [url, opts] = (global.fetch as jest.Mock).mock.calls[0];
    expect(url).toBe(`${API}/api/webcheck/start`);
    const payload = JSON.parse((opts as RequestInit).body as string);
    expect(payload.email).toBe('kontakt@firma.de');
    expect(payload.domain).toBe('firma.de'); // normalisiert (protocol/www/pfad entfernt)
    expect(payload.marketing_consent).toBe(false);
    expect(payload.consent_text_version).toBe('v1.0');

    // Verifizierungs-Anleitung (DNS-TXT) sichtbar
    expect(screen.getByText('_vectiscan-verify.firma.de')).toBeInTheDocument();
  });

  it('Verify-Erfolg → Scan-gestartet-Bestätigung', async () => {
    mockFetchOnce(201, {
      success: true,
      data: { leadId: '22222222-2222-2222-2222-222222222222', domain: 'firma.de', verification: { token: 't', methods: [] } },
    });
    render(<WebCheckFreeForm />);
    fireEvent.change(screen.getByLabelText('E-Mail-Adresse'), { target: { value: 'k@firma.de' } });
    fireEvent.change(screen.getByLabelText('Ihre Domain'), { target: { value: 'firma.de' } });
    fireEvent.click(screen.getByRole('button', { name: /Kostenlosen WebCheck starten/ }));
    await waitFor(() => expect(screen.getByText('Domain-Kontrolle nachweisen')).toBeInTheDocument());

    mockFetchOnce(200, { success: true, data: { verified: true, scanStarted: true, orderId: 'ord-1' } });
    fireEvent.click(screen.getByRole('button', { name: /Verifizierung prüfen/ }));

    await waitFor(() => expect(screen.getByText(/Ihr WebCheck läuft/)).toBeInTheDocument());
    const [vurl] = (global.fetch as jest.Mock).mock.calls[1];
    expect(vurl).toBe(`${API}/api/webcheck/verify`);
  });

  it('Verify ohne Domain-Nachweis → Hinweis erneut versuchen (AC2)', async () => {
    mockFetchOnce(201, {
      success: true,
      data: { leadId: '33333333-3333-3333-3333-333333333333', domain: 'firma.de', verification: { token: 't', methods: [] } },
    });
    render(<WebCheckFreeForm />);
    fireEvent.change(screen.getByLabelText('E-Mail-Adresse'), { target: { value: 'k@firma.de' } });
    fireEvent.change(screen.getByLabelText('Ihre Domain'), { target: { value: 'firma.de' } });
    fireEvent.click(screen.getByRole('button', { name: /Kostenlosen WebCheck starten/ }));
    await waitFor(() => expect(screen.getByText('Domain-Kontrolle nachweisen')).toBeInTheDocument());

    mockFetchOnce(200, { success: true, data: { verified: false, scanStarted: false } });
    fireEvent.click(screen.getByRole('button', { name: /Verifizierung prüfen/ }));
    await waitFor(() => expect(screen.getByText(/noch nicht bestätigen/)).toBeInTheDocument());
  });

  it('Rate-Limit beim Start → Edge-Copy (AC4)', async () => {
    mockFetchOnce(429, { success: false, error: 'rate_limited' });
    render(<WebCheckFreeForm />);
    fireEvent.change(screen.getByLabelText('E-Mail-Adresse'), { target: { value: 'k@firma.de' } });
    fireEvent.change(screen.getByLabelText('Ihre Domain'), { target: { value: 'firma.de' } });
    fireEvent.click(screen.getByRole('button', { name: /Kostenlosen WebCheck starten/ }));
    await waitFor(() => expect(screen.getByText(/aktueller\s+WebCheck vor/)).toBeInTheDocument());
  });

  it('ohne Site-Key wird KEIN Turnstile-Widget gerendert (graceful, AC: inert)', () => {
    render(<WebCheckFreeForm />);
    expect(screen.queryByTestId('turnstile-widget')).not.toBeInTheDocument();
  });
});

// ── VEC-189: Turnstile aktiv (Site-Key konfiguriert) ─────────────────────────
describe('WebCheckFreeForm — Turnstile aktiv (VEC-189)', () => {
  const SITE_KEY = '1x00000000000000000000AA'; // Cloudflare-Test-Site-Key
  let renderedOpts: Record<string, (token?: string) => void> & { sitekey?: string };

  beforeEach(() => {
    global.fetch = jest.fn();
    process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY = SITE_KEY;
    renderedOpts = {} as typeof renderedOpts;
    (window as unknown as { turnstile: unknown }).turnstile = {
      render: jest.fn((_el: HTMLElement, opts: Record<string, unknown>) => {
        renderedOpts = opts as typeof renderedOpts;
        return 'wid-1';
      }),
      reset: jest.fn(),
      remove: jest.fn(),
    };
  });
  afterEach(() => {
    delete process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;
    delete (window as unknown as { turnstile?: unknown }).turnstile;
    jest.clearAllMocks();
  });

  function turnstile() {
    return (window as unknown as { turnstile: { render: jest.Mock; reset: jest.Mock } }).turnstile;
  }

  it('rendert das Widget mit dem konfigurierten Site-Key', async () => {
    render(<WebCheckFreeForm />);
    expect(screen.getByTestId('turnstile-widget')).toBeInTheDocument();
    await waitFor(() => expect(turnstile().render).toHaveBeenCalled());
    expect(renderedOpts.sitekey).toBe(SITE_KEY);
  });

  it('blockt Submit ohne Token (kein Netzwerk-Call) und zeigt Hinweis', async () => {
    render(<WebCheckFreeForm />);
    await waitFor(() => expect(turnstile().render).toHaveBeenCalled());
    fireEvent.change(screen.getByLabelText('E-Mail-Adresse'), { target: { value: 'k@firma.de' } });
    fireEvent.change(screen.getByLabelText('Ihre Domain'), { target: { value: 'firma.de' } });
    fireEvent.click(screen.getByRole('button', { name: /Kostenlosen WebCheck starten/ }));
    expect(screen.getByRole('alert')).toHaveTextContent(/kein Roboter/);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('sendet captchaToken im Start-Payload nach Turnstile-Callback', async () => {
    mockFetchOnce(201, {
      success: true,
      data: { leadId: 'id-1', domain: 'firma.de', verification: { token: 't', methods: [] } },
    });
    render(<WebCheckFreeForm />);
    await waitFor(() => expect(turnstile().render).toHaveBeenCalled());
    act(() => { renderedOpts.callback('captcha-xyz'); });

    fireEvent.change(screen.getByLabelText('E-Mail-Adresse'), { target: { value: 'k@firma.de' } });
    fireEvent.change(screen.getByLabelText('Ihre Domain'), { target: { value: 'firma.de' } });
    fireEvent.click(screen.getByRole('button', { name: /Kostenlosen WebCheck starten/ }));

    await waitFor(() => expect(screen.getByText('Domain-Kontrolle nachweisen')).toBeInTheDocument());
    const [, opts] = (global.fetch as jest.Mock).mock.calls[0];
    const payload = JSON.parse((opts as RequestInit).body as string);
    expect(payload.captchaToken).toBe('captcha-xyz');
  });

  it('403 captcha_failed → Widget-Reset + erneute Aufforderung', async () => {
    mockFetchOnce(403, { success: false, error: 'captcha_failed' });
    render(<WebCheckFreeForm />);
    await waitFor(() => expect(turnstile().render).toHaveBeenCalled());
    act(() => { renderedOpts.callback('stale-token'); });

    fireEvent.change(screen.getByLabelText('E-Mail-Adresse'), { target: { value: 'k@firma.de' } });
    fireEvent.change(screen.getByLabelText('Ihre Domain'), { target: { value: 'firma.de' } });
    fireEvent.click(screen.getByRole('button', { name: /Kostenlosen WebCheck starten/ }));

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/Sicherheitsprüfung fehlgeschlagen/));
    expect(turnstile().reset).toHaveBeenCalledWith('wid-1');
  });
});

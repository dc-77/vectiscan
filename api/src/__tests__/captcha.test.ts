/**
 * CAPTCHA-Verifikation (VEC-173, F2 aus VEC-169).
 *
 * Sicherheitskritisch ist das Fail-Modell:
 *   - kein Secret konfiguriert  => disabled, fail-OPEN (ok:true)
 *   - Secret gesetzt + Token gut => ok spiegelt Cloudflares `success`
 *   - Secret gesetzt + Fehler/leer/zu lang => fail-CLOSED (ok:false)
 */
import { captchaConfigured, verifyCaptcha } from '../lib/captcha';

const ENV_KEY = 'WEBCHECK_TURNSTILE_SECRET';
const origSecret = process.env[ENV_KEY];
const origFetch = globalThis.fetch;

afterEach(() => {
  if (origSecret === undefined) delete process.env[ENV_KEY];
  else process.env[ENV_KEY] = origSecret;
  globalThis.fetch = origFetch;
});

describe('captchaConfigured', () => {
  it('false ohne Secret, true mit Secret', () => {
    delete process.env[ENV_KEY];
    expect(captchaConfigured()).toBe(false);
    process.env[ENV_KEY] = 'sekret';
    expect(captchaConfigured()).toBe(true);
  });
});

describe('verifyCaptcha', () => {
  it('disabled (fail-open) wenn kein Secret gesetzt ist — kein Netzaufruf', async () => {
    delete process.env[ENV_KEY];
    const spy = jest.fn();
    globalThis.fetch = spy as unknown as typeof fetch;
    const r = await verifyCaptcha('irgendein-token', '1.2.3.4');
    expect(r).toEqual({ ok: true, disabled: true });
    expect(spy).not.toHaveBeenCalled();
  });

  it('fail-closed bei leerem/zu langem/nicht-String-Token (Secret gesetzt)', async () => {
    process.env[ENV_KEY] = 'sekret';
    const spy = jest.fn();
    globalThis.fetch = spy as unknown as typeof fetch;
    expect(await verifyCaptcha('')).toEqual({ ok: false, disabled: false });
    expect(await verifyCaptcha(undefined)).toEqual({ ok: false, disabled: false });
    expect(await verifyCaptcha('x'.repeat(5000))).toEqual({ ok: false, disabled: false });
    expect(spy).not.toHaveBeenCalled();
  });

  it('ok:true wenn Cloudflare success:true meldet', async () => {
    process.env[ENV_KEY] = 'sekret';
    globalThis.fetch = jest.fn().mockResolvedValue({
      json: async () => ({ success: true }),
    }) as unknown as typeof fetch;
    const r = await verifyCaptcha('gutes-token', '1.2.3.4');
    expect(r).toEqual({ ok: true, disabled: false });
  });

  it('ok:false wenn Cloudflare success:false meldet', async () => {
    process.env[ENV_KEY] = 'sekret';
    globalThis.fetch = jest.fn().mockResolvedValue({
      json: async () => ({ success: false, 'error-codes': ['invalid-input-response'] }),
    }) as unknown as typeof fetch;
    expect(await verifyCaptcha('schlechtes-token')).toEqual({ ok: false, disabled: false });
  });

  it('fail-closed bei Netz-/Parsefehler (Secret gesetzt)', async () => {
    process.env[ENV_KEY] = 'sekret';
    globalThis.fetch = jest.fn().mockRejectedValue(new Error('network down')) as unknown as typeof fetch;
    expect(await verifyCaptcha('token')).toEqual({ ok: false, disabled: false });
  });
});

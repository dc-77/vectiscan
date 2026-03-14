import dns from 'dns/promises';
import crypto from 'crypto';

export interface VerificationResult {
  verified: boolean;
  method: 'dns_txt' | 'file' | 'meta_tag' | null;
}

export function generateToken(): string {
  return `vectiscan-verify-${crypto.randomUUID().slice(0, 12)}`;
}

export async function verifyDnsTxt(domain: string, token: string): Promise<VerificationResult> {
  try {
    const records = await dns.resolveTxt(`_vectiscan-verify.${domain}`);
    const found = records.some((record) =>
      record.some((entry) => entry === token)
    );
    return { verified: found, method: 'dns_txt' };
  } catch {
    return { verified: false, method: 'dns_txt' };
  }
}

export async function verifyFile(domain: string, token: string): Promise<VerificationResult> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    try {
      const response = await fetch(
        `https://${domain}/.well-known/vectiscan-verify.txt`,
        { signal: controller.signal }
      );
      const body = await response.text();
      const verified = body.trim() === token;
      return { verified, method: 'file' };
    } finally {
      clearTimeout(timeout);
    }
  } catch {
    return { verified: false, method: 'file' };
  }
}

export async function verifyMetaTag(domain: string, token: string): Promise<VerificationResult> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    try {
      const response = await fetch(`https://${domain}`, {
        signal: controller.signal,
      });
      const body = await response.text();
      const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(
        `<meta\\s+name\\s*=\\s*['"]vectiscan-verify['"]\\s+content\\s*=\\s*['"]${escaped}['"]\\s*/?>`,
        'i'
      );
      const verified = regex.test(body);
      return { verified, method: 'meta_tag' };
    } finally {
      clearTimeout(timeout);
    }
  } catch {
    return { verified: false, method: 'meta_tag' };
  }
}

export async function verifyAll(domain: string, token: string): Promise<VerificationResult> {
  const results = await Promise.allSettled([
    verifyDnsTxt(domain, token),
    verifyFile(domain, token),
    verifyMetaTag(domain, token),
  ]);

  for (const result of results) {
    if (result.status === 'fulfilled' && result.value.verified) {
      return result.value;
    }
  }

  return { verified: false, method: null };
}

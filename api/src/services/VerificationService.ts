import dns from 'dns/promises';
import crypto from 'crypto';
import { safeFetch } from '../lib/ssrf-guard.js';

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
    // safeFetch pinnt auf eine validierte öffentliche IP (Resolve-and-Pin) und
    // blockt private/link-local/loopback/metadata-Ziele — Schutz gegen
    // DNS-Rebinding (VEC-175). Bei geblocktem Ziel wirft safeFetch → catch unten.
    const response = await safeFetch(
      `https://${domain}/.well-known/vectiscan-verify.txt`,
    );
    const body = await response.text();
    const verified = body.trim() === token;
    return { verified, method: 'file' };
  } catch {
    return { verified: false, method: 'file' };
  }
}

export async function verifyMetaTag(domain: string, token: string): Promise<VerificationResult> {
  try {
    const response = await safeFetch(`https://${domain}`);
    const body = await response.text();
    const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(
      `<meta\\s+name\\s*=\\s*['"]vectiscan-verify['"]\\s+content\\s*=\\s*['"]${escaped}['"]\\s*/?>`,
      'i'
    );
    const verified = regex.test(body);
    return { verified, method: 'meta_tag' };
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

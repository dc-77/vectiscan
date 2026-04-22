const DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const IPV4_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

// Valid subnet masks in dotted-decimal notation → CIDR prefix length
const DOTTED_MASKS: Record<string, number> = {
  '255.255.255.255': 32, '255.255.255.254': 31, '255.255.255.252': 30,
  '255.255.255.248': 29, '255.255.255.240': 28, '255.255.255.224': 27,
  '255.255.255.192': 26, '255.255.255.128': 25, '255.255.255.0': 24,
  '255.255.254.0': 23, '255.255.252.0': 22, '255.255.248.0': 21,
  '255.255.240.0': 20, '255.255.224.0': 19, '255.255.192.0': 18,
  '255.255.128.0': 17, '255.255.0.0': 16, '255.254.0.0': 15,
  '255.252.0.0': 14, '255.248.0.0': 13, '255.240.0.0': 12,
  '255.224.0.0': 11, '255.192.0.0': 10, '255.128.0.0': 9, '255.0.0.0': 8,
};

export function isValidDomain(domain: unknown): domain is string {
  if (typeof domain !== 'string') return false;
  if (domain.length > 255) return false;
  return DOMAIN_REGEX.test(domain);
}

function isValidIPv4(ip: string): boolean {
  const match = IPV4_REGEX.exec(ip);
  if (!match) return false;
  return match.slice(1).every(octet => {
    const n = parseInt(octet, 10);
    return n >= 0 && n <= 255;
  });
}

/**
 * Validate a scan target: FQDN, IPv4, CIDR, or dotted-decimal subnet notation.
 * Returns the normalized form (dotted-decimal converted to CIDR) or null if invalid.
 */
export function isValidTarget(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (!trimmed || trimmed.length > 255) return null;

  // Reject inputs with protocol — user should provide clean targets
  if (/^[a-z]+:\/\//i.test(trimmed)) return null;

  // FQDN
  if (DOMAIN_REGEX.test(trimmed)) {
    return trimmed.toLowerCase();
  }

  // Check for slash (CIDR or dotted-decimal)
  if (trimmed.includes('/')) {
    const [ipPart, maskPart] = trimmed.split('/', 2);
    if (!isValidIPv4(ipPart)) return null;

    // CIDR notation: /8 to /32
    if (/^\d{1,2}$/.test(maskPart)) {
      const prefix = parseInt(maskPart, 10);
      if (prefix >= 8 && prefix <= 32) {
        return `${ipPart}/${prefix}`;
      }
      return null;
    }

    // Dotted-decimal notation: /255.255.255.224
    if (isValidIPv4(maskPart)) {
      const cidrPrefix = DOTTED_MASKS[maskPart];
      if (cidrPrefix !== undefined) {
        return `${ipPart}/${cidrPrefix}`;
      }
      return null; // Invalid subnet mask
    }

    return null;
  }

  // Plain IPv4
  if (isValidIPv4(trimmed)) {
    return trimmed;
  }

  return null;
}

// ---------------------------------------------------------------------------
// Multi-Target-Validierung
// ---------------------------------------------------------------------------

export type TargetType = 'fqdn_root' | 'fqdn_specific' | 'ipv4' | 'cidr';
export type DiscoveryPolicy = 'enumerate' | 'scoped' | 'ip_only';

export interface TargetValidation {
  raw_input: string;
  valid: boolean;
  canonical?: string;
  target_type?: TargetType;
  policy_default?: DiscoveryPolicy;
  expanded_count_estimate?: number;
  warnings: string[];
  error?: string;
}

// Haeufige Multi-Label-TLDs. Keine vollstaendige Public-Suffix-List — deckt
// die wichtigsten Faelle ab, ohne eine neue Dependency einzufuehren.
const MULTI_LABEL_TLDS = new Set<string>([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br',
  'co.in', 'net.in', 'org.in',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.nz', 'net.nz', 'org.nz',
  'co.za', 'net.za', 'org.za',
  'com.mx', 'com.ar', 'com.co', 'com.tr', 'com.sg', 'com.hk',
]);

function classifyFqdn(fqdn: string): 'fqdn_root' | 'fqdn_specific' {
  const labels = fqdn.split('.');
  if (labels.length <= 2) return 'fqdn_root';
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_TLDS.has(lastTwo) && labels.length === 3) {
    return 'fqdn_root';
  }
  return 'fqdn_specific';
}

function cidrPrefix(canonical: string): number | null {
  const m = /^\d{1,3}(?:\.\d{1,3}){3}\/(\d{1,2})$/.exec(canonical);
  if (!m) return null;
  const p = parseInt(m[1], 10);
  return p >= 0 && p <= 32 ? p : null;
}

export function validateTarget(rawInput: unknown): TargetValidation {
  if (typeof rawInput !== 'string' || rawInput.trim() === '') {
    return { raw_input: String(rawInput ?? ''), valid: false, warnings: [], error: 'empty_input' };
  }
  const raw = rawInput.trim();
  const canonical = isValidTarget(raw);
  if (!canonical) {
    return { raw_input: raw, valid: false, warnings: [], error: 'parse_failed' };
  }

  const warnings: string[] = [];

  // CIDR / dotted-mask erkennt man am "/"
  if (canonical.includes('/')) {
    const prefix = cidrPrefix(canonical);
    if (prefix === null) {
      return { raw_input: raw, valid: false, warnings, error: 'parse_failed' };
    }
    // Haertelimit: /24 oder kleiner ist ok, groesser (kleinere Zahl) verwerfen
    if (prefix < 24) {
      return {
        raw_input: raw, valid: false, warnings,
        canonical, target_type: 'cidr', policy_default: 'ip_only',
        expanded_count_estimate: 2 ** (32 - prefix) - 2,
        error: 'cidr_too_large',
      };
    }
    const count = prefix === 32 ? 1 : (prefix === 31 ? 2 : 2 ** (32 - prefix) - 2);
    if (prefix === 32) {
      // /32 ist eine einzelne IP — auf ipv4 zurueckstufen
      return {
        raw_input: raw, valid: true, warnings,
        canonical: canonical.split('/')[0],
        target_type: 'ipv4', policy_default: 'ip_only',
        expanded_count_estimate: 1,
      };
    }
    return {
      raw_input: raw, valid: true, warnings,
      canonical, target_type: 'cidr', policy_default: 'ip_only',
      expanded_count_estimate: count,
    };
  }

  // Plain IPv4
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(canonical)) {
    return {
      raw_input: raw, valid: true, warnings,
      canonical, target_type: 'ipv4', policy_default: 'ip_only',
      expanded_count_estimate: 1,
    };
  }

  // FQDN
  const targetType = classifyFqdn(canonical);
  const policyDefault: DiscoveryPolicy = targetType === 'fqdn_root' ? 'enumerate' : 'scoped';
  return {
    raw_input: raw, valid: true, warnings,
    canonical, target_type: targetType, policy_default: policyDefault,
  };
}

export interface TargetBatchValidation {
  targets: TargetValidation[];
  errors: string[];
}

export const MAX_TARGETS_PER_ORDER = 10;
export const MAX_CIDR_PER_ORDER = 1;
export const MIN_CIDR_PREFIX = 24;

export function validateTargetBatch(inputs: Array<{ raw_input?: unknown }>): TargetBatchValidation {
  const errors: string[] = [];
  if (!Array.isArray(inputs) || inputs.length === 0) {
    return { targets: [], errors: ['no_targets'] };
  }
  if (inputs.length > MAX_TARGETS_PER_ORDER) {
    errors.push('too_many_targets');
  }

  const targets = inputs.map(i => validateTarget(i?.raw_input));

  const cidrCount = targets.filter(t => t.valid && t.target_type === 'cidr').length;
  if (cidrCount > MAX_CIDR_PER_ORDER) {
    errors.push('too_many_cidrs');
  }

  // Dubletten markieren
  const seen = new Map<string, number>();
  targets.forEach((t, idx) => {
    if (!t.valid || !t.canonical) return;
    const prev = seen.get(t.canonical);
    if (prev !== undefined) {
      t.warnings.push(`duplicate_of_row_${prev + 1}`);
    } else {
      seen.set(t.canonical, idx);
    }
  });

  return { targets, errors };
}

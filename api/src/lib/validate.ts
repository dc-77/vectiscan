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

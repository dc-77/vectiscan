const DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export function isValidDomain(domain: unknown): domain is string {
  if (typeof domain !== 'string') return false;
  if (domain.length > 255) return false;
  return DOMAIN_REGEX.test(domain);
}

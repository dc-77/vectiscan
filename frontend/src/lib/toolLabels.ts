/**
 * Cinematic tool label mapping.
 *
 * Maps backend tool identifiers to human-readable English descriptions.
 * No real tool names are exposed to the user — only functional descriptions.
 */

export const TOOL_LABELS: Record<string, string> = {
  // Phase 0a — Passive Intelligence
  shodan:           'QUERY GLOBAL SENSOR NETWORK',
  abuseipdb:        'CHECK THREAT REPUTATION DATABASE',
  securitytrails:   'RETRIEVE HISTORICAL DNS RECORDS',
  whois:            'LOOKUP DOMAIN REGISTRATION',
  dns_security:     'EVALUATE DNS SECURITY POSTURE',
  dnssec:           'VALIDATE DNSSEC CHAIN',
  caa:              'CHECK CERTIFICATE AUTHORITY POLICY',
  mta_sts:          'INSPECT MAIL TRANSPORT SECURITY',
  dane_tlsa:        'VERIFY DANE/TLSA RECORDS',

  // Phase 0b — Active Discovery
  crtsh:            'SCAN CERTIFICATE TRANSPARENCY LOGS',
  subfinder:        'ENUMERATE SUBDOMAINS',
  amass:            'DEEP OSINT SUBDOMAIN DISCOVERY',
  gobuster_dns:     'BRUTE-FORCE DNS NAMESPACE',
  axfr:             'ATTEMPT DNS ZONE TRANSFER',
  dnsx:             'RESOLVE AND VALIDATE HOSTNAMES',

  // Phase 1 — Technology Fingerprinting
  nmap:             'IDENTIFY OPEN PORTS AND SERVICES',
  webtech:          'FINGERPRINT TECHNOLOGY STACK',
  wafw00f:          'DETECT WEB APPLICATION FIREWALL',
  cms_fingerprint:  'IDENTIFY CONTENT MANAGEMENT SYSTEM',

  // Phase 2 — Deep Scan
  testssl:          'ANALYZE ENCRYPTION STRENGTH',
  zap_spider:       'CRAWL APPLICATION STRUCTURE',
  zap_ajax_spider:  'CRAWL DYNAMIC JAVASCRIPT CONTENT',
  zap_active:       'PROBE FOR APPLICATION VULNERABILITIES',
  zap_passive:      'ANALYZE CAPTURED TRAFFIC PATTERNS',
  nuclei:           'SCAN FOR KNOWN VULNERABILITIES',
  gowitness:        'CAPTURE VISUAL SNAPSHOT',
  header_check:     'AUDIT SECURITY HEADERS',
  headers:          'AUDIT SECURITY HEADERS',
  httpx:            'PROBE HTTP ENDPOINTS',
  wpscan:           'ANALYZE WORDPRESS SECURITY',
  nikto:            'SCAN WEB SERVER CONFIGURATION',
  gobuster_dir:     'DISCOVER HIDDEN DIRECTORIES',
  ffuf:             'FUZZ APPLICATION PARAMETERS',
  ffuf_dir:         'BRUTE-FORCE FILE PATHS',
  ffuf_fuzz:        'FUZZ APPLICATION PARAMETERS',
  feroxbuster:      'RECURSIVE DIRECTORY ENUMERATION',
  katana:           'CRAWL AND EXTRACT ENDPOINTS',
  dalfox:           'TEST FOR CROSS-SITE SCRIPTING',

  // Phase 3 — Correlation & Enrichment
  nvd:              'QUERY NATIONAL VULNERABILITY DATABASE',
  epss:             'CALCULATE EXPLOIT PROBABILITY',
  cisa_kev:         'CHECK KNOWN EXPLOITED VULNERABILITIES',
  exploitdb:        'SEARCH PUBLIC EXPLOIT DATABASE',
  correlator:       'CROSS-REFERENCE TOOL FINDINGS',
  fp_filter:        'FILTER FALSE POSITIVES',
  business_impact:  'CALCULATE BUSINESS IMPACT SCORE',
};

/** Host lane colors for parallel scanning visualization. */
export const HOST_COLORS = ['#38BDF8', '#A78BFA', '#34D399'] as const;

/** Get cinematic label for a tool. Falls back to uppercased tool name. */
export function getToolLabel(tool: string): string {
  return TOOL_LABELS[tool] || tool.toUpperCase().replace(/_/g, ' ');
}

/** Assign a lane color to a host based on its index. */
export function getHostColor(index: number): string {
  return HOST_COLORS[index % HOST_COLORS.length];
}

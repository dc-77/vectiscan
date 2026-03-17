"""CMS-Fingerprinting-Engine — detects CMS type and version via 5 complementary methods.

Replaces the simple CMS-Fallback-Probe in phase1.py with a full detection pipeline.
DACH-market-optimized: Shopware 5/6, TYPO3, Contao alongside global CMS systems.

All probes use HEAD/GET requests with User-Agent "VectiScan/1.0" and 5s timeout.
Max 20 requests per host (early-exit when high-confidence match found).
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from typing import Any, Optional

import structlog

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CMSCandidate:
    """A CMS detection from a single method."""
    cms: str
    version: Optional[str] = None
    confidence: float = 0.0
    method: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class CMSResult:
    """Final merged CMS detection result."""
    cms: Optional[str] = None
    version: Optional[str] = None
    confidence: float = 0.0
    detection_methods: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cms": self.cms,
            "version": self.version,
            "confidence": round(self.confidence, 2),
            "detection_methods": self.detection_methods,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Probe Matrix — CMS-specific paths and response patterns
# ---------------------------------------------------------------------------

PROBE_MATRIX: list[dict[str, Any]] = [
    {
        "cms": "WordPress",
        "probes": ["/wp-login.php", "/wp-admin/", "/wp-content/"],
        "body_patterns": [r"wp-", r"wordpress"],
        "confidence": 0.95,
    },
    {
        "cms": "Shopware",
        "version_hint": "5",
        "probes": ["/backend/admin", "/web/css/"],
        "body_patterns": [r"(?i)shopware"],
        "confidence": 0.90,
    },
    {
        "cms": "Shopware",
        "version_hint": "6",
        "probes": ["/admin", "/api/_info/config"],
        "body_patterns": [r"(?i)shopware"],
        "confidence": 0.90,
    },
    {
        "cms": "TYPO3",
        "probes": ["/typo3/", "/typo3conf/"],
        "body_patterns": [r"(?i)typo3"],
        "confidence": 0.90,
    },
    {
        "cms": "Joomla",
        "probes": ["/administrator/"],
        "body_patterns": [r"(?i)joomla"],
        "confidence": 0.90,
    },
    {
        "cms": "Contao",
        "probes": ["/contao/"],
        "body_patterns": [r"(?i)contao"],
        "confidence": 0.85,
    },
    {
        "cms": "Drupal",
        "probes": ["/user/login", "/core/misc/drupal.js"],
        "body_patterns": [r"(?i)drupal"],
        "confidence": 0.90,
    },
    {
        "cms": "Magento",
        "probes": ["/admin/", "/checkout/cart/"],
        "body_patterns": [r"(?i)magento", r"(?i)mage"],
        "confidence": 0.85,
    },
    {
        "cms": "NEOS",
        "probes": ["/neos/"],
        "body_patterns": [r"neos-"],
        "confidence": 0.80,
    },
    {
        "cms": "Craft CMS",
        "probes": ["/admin/login"],
        "body_patterns": [r"(?i)craft"],
        "confidence": 0.85,
    },
    {
        "cms": "Strapi",
        "probes": ["/admin/", "/_health"],
        "body_patterns": [r"(?i)strapi"],
        "confidence": 0.80,
    },
    {
        "cms": "Ghost",
        "probes": ["/ghost/"],
        "body_patterns": [r"ghost-"],
        "confidence": 0.85,
    },
    {
        "cms": "PrestaShop",
        "probes": ["/admin/login", "/modules/"],
        "body_patterns": [r"(?i)prestashop"],
        "confidence": 0.80,
    },
]

# Cookie patterns → CMS mapping
COOKIE_CMS_MAP: list[tuple[str, str, Optional[str]]] = [
    # (cookie_pattern, cms_name, version_hint)
    (r"wordpress_logged_in", "WordPress", None),
    (r"wp-settings", "WordPress", None),
    (r"sw-states", "Shopware", "6"),
    (r"sw-context-token", "Shopware", "6"),
    (r"session-", "Shopware", "5"),  # Shopware 5 generic session
    (r"fe_typo_user", "TYPO3", None),
    (r"mosvisitor", "Joomla", None),
    (r"joomla_", "Joomla", None),
    (r"contao_", "Contao", None),
    (r"SSESS", "Drupal", None),
    (r"Drupal\.visitor", "Drupal", None),
    (r"CraftSessionId", "Craft CMS", None),
    (r"ghost-admin", "Ghost", None),
    (r"PrestaShop", "PrestaShop", None),
]

# Meta-generator patterns → CMS + version extraction
META_GENERATOR_PATTERNS: list[tuple[str, str, Optional[str]]] = [
    # (regex_pattern, cms_name, version_group — group name in regex or None)
    (r"WordPress\s*([\d.]+)?", "WordPress", None),
    (r"TYPO3\s*CMS?\s*([\d.]+)?", "TYPO3", None),
    (r"Joomla[!]?\s*([\d.]+)?", "Joomla", None),
    (r"Drupal\s*([\d.]+)?", "Drupal", None),
    (r"Contao\s*([\d.]+)?", "Contao", None),
    (r"Shopware\s*([\d.]+)?", "Shopware", None),
    (r"Ghost\s*([\d.]+)?", "Ghost", None),
    (r"PrestaShop\s*([\d.]+)?", "PrestaShop", None),
    (r"NEOS\s*([\d.]+)?", "NEOS", None),
    (r"Craft\s*CMS\s*([\d.]+)?", "Craft CMS", None),
]

# Header patterns for CMS detection
HEADER_CMS_PATTERNS: list[tuple[str, str, str]] = [
    # (header_name_lower, value_pattern, cms_name)
    ("x-generator", r"(?i)drupal", "Drupal"),
    ("x-generator", r"(?i)wordpress", "WordPress"),
    ("x-generator", r"(?i)typo3", "TYPO3"),
    ("x-powered-by", r"(?i)shopware", "Shopware"),
    ("x-content-powered-by", r"(?i)strapi", "Strapi"),
]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

_SSL_CTX: ssl.SSLContext | None = None


def _get_ssl_ctx() -> ssl.SSLContext:
    """Reusable SSL context that skips certificate verification (scan targets may have self-signed certs)."""
    global _SSL_CTX
    if _SSL_CTX is None:
        _SSL_CTX = ssl.create_default_context()
        _SSL_CTX.check_hostname = False
        _SSL_CTX.verify_mode = ssl.CERT_NONE
    return _SSL_CTX


def _fetch(url: str, method: str = "HEAD", read_body: bool = False,
           timeout: int = 5) -> tuple[int, dict[str, str], str, list[tuple[str, str]]]:
    """Fetch a URL and return (status, headers_dict, body, cookies).

    Returns (0, {}, "", []) on any failure.
    """
    try:
        cj = CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj),
            urllib.request.HTTPSHandler(context=_get_ssl_ctx()),
        )
        req = urllib.request.Request(
            url,
            method=method if not read_body else "GET",
            headers={"User-Agent": "VectiScan/1.0"},
        )
        resp = opener.open(req, timeout=timeout)
        status = resp.status
        headers = {k.lower(): v for k, v in resp.getheaders()}
        body = ""
        if read_body:
            raw = resp.read(65536)  # max 64KB
            body = raw.decode("utf-8", errors="replace")
        cookies = [(c.name, c.value or "") for c in cj]
        return status, headers, body, cookies
    except urllib.error.HTTPError as e:
        # HTTP errors still have status codes and headers
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        cookies_from_headers: list[tuple[str, str]] = []
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            # Extract cookie name from Set-Cookie header
            name = set_cookie.split("=", 1)[0].strip()
            cookies_from_headers.append((name, ""))
        return e.code, headers, "", cookies_from_headers
    except Exception:
        return 0, {}, "", []


# ---------------------------------------------------------------------------
# CMSFingerprinter
# ---------------------------------------------------------------------------

class CMSFingerprinter:
    """Detects CMS type and estimated version via 5 complementary methods.

    Each method returns a CMSCandidate. Results are merged: matching detections
    across methods boost overall confidence.
    """

    def __init__(self, max_requests: int = 20):
        self.max_requests = max_requests
        self._request_count = 0

    def _can_request(self) -> bool:
        return self._request_count < self.max_requests

    def _count_request(self) -> None:
        self._request_count += 1

    # -- Method 1: webtech data (already available from Phase 1) -----------

    def check_webtech(self, webtech_result: Any) -> list[CMSCandidate]:
        """Extract CMS from existing webtech Phase 1 output."""
        candidates: list[CMSCandidate] = []
        cms_names = {
            "wordpress", "joomla", "drupal", "typo3", "magento", "shopify",
            "shopware", "wix", "prestashop", "contao", "neos", "craft", "strapi", "ghost",
        }

        techs: list[Any] = []
        if isinstance(webtech_result, dict):
            techs = webtech_result.get("tech", [])
        elif isinstance(webtech_result, list):
            techs = webtech_result

        for tech in techs:
            if isinstance(tech, dict):
                name = tech.get("name", "")
                if name.lower() in cms_names:
                    candidates.append(CMSCandidate(
                        cms=name,
                        version=tech.get("version"),
                        confidence=0.80,
                        method="webtech",
                        details={"source": "webtech", "raw": tech},
                    ))
            elif isinstance(tech, str) and tech.lower() in cms_names:
                candidates.append(CMSCandidate(
                    cms=tech,
                    confidence=0.70,
                    method="webtech",
                ))
        return candidates

    # -- Method 2: Meta-Tag analysis --------------------------------------

    def check_meta_tags(self, fqdn: str) -> list[CMSCandidate]:
        """Fetch homepage and parse <meta name="generator"> tag."""
        candidates: list[CMSCandidate] = []
        if not self._can_request():
            return candidates

        for scheme in ("https", "http"):
            if not self._can_request():
                break
            self._count_request()
            status, headers, body, cookies = _fetch(
                f"{scheme}://{fqdn}/", read_body=True, timeout=5,
            )
            if status == 0 or not body:
                continue

            # Parse meta generator
            gen_match = re.search(
                r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
                body, re.IGNORECASE,
            )
            if gen_match:
                generator = gen_match.group(1)
                for pattern, cms_name, _ in META_GENERATOR_PATTERNS:
                    m = re.search(pattern, generator, re.IGNORECASE)
                    if m:
                        version = m.group(1) if m.lastindex and m.group(1) else None
                        candidates.append(CMSCandidate(
                            cms=cms_name,
                            version=version,
                            confidence=0.90,
                            method="meta_tag",
                            details={"meta_generator": generator},
                        ))
                        break

            # Also check X-Powered-By in page headers (method 5 piggybacks here)
            for header_name, value_pattern, cms_name in HEADER_CMS_PATTERNS:
                header_val = headers.get(header_name, "")
                if header_val and re.search(value_pattern, header_val):
                    candidates.append(CMSCandidate(
                        cms=cms_name,
                        confidence=0.75,
                        method="response_header",
                        details={"header": header_name, "value": header_val},
                    ))

            # Check cookies from homepage (method 4 piggybacks here)
            if cookies:
                cookie_candidates = self._match_cookies(cookies)
                candidates.extend(cookie_candidates)

            if candidates:
                break  # Got results from first scheme, no need to retry

        return candidates

    # -- Method 3: Probe Matrix -------------------------------------------

    def run_probe_matrix(self, fqdn: str, early_cms: Optional[str] = None) -> list[CMSCandidate]:
        """Probe CMS-specific paths and check response patterns.

        If early_cms is set (from meta-tag or webtech), only probe that CMS
        to save requests.
        """
        candidates: list[CMSCandidate] = []

        probes_to_run = PROBE_MATRIX
        if early_cms:
            # Only probe the already-detected CMS for confirmation
            early_lower = early_cms.lower()
            probes_to_run = [p for p in PROBE_MATRIX if p["cms"].lower() == early_lower]
            if not probes_to_run:
                probes_to_run = PROBE_MATRIX  # fallback to all

        for probe_def in probes_to_run:
            if not self._can_request():
                break

            cms_name = probe_def["cms"]
            hits: list[str] = []

            for path in probe_def["probes"]:
                if not self._can_request():
                    break
                self._count_request()

                for scheme in ("https", "http"):
                    url = f"{scheme}://{fqdn}{path}"
                    status, headers, body, cookies = _fetch(url, method="GET", read_body=True)

                    if status in (200, 301, 302, 303, 307, 308):
                        hits.append(f"{path} → {status}")

                        # Check body patterns
                        if body:
                            for bp in probe_def.get("body_patterns", []):
                                if re.search(bp, body):
                                    hits.append(f"{path} body match: {bp}")
                                    break

                        # Check cookies
                        if cookies:
                            cookie_candidates = self._match_cookies(cookies)
                            for cc in cookie_candidates:
                                if cc.cms.lower() == cms_name.lower():
                                    hits.append(f"cookie: {cc.details.get('cookie_name', '')}")

                        break  # Got response from this scheme, skip other
                    elif status == 0:
                        continue  # Try other scheme
                    else:
                        break  # Got a response (404 etc.), no need to try HTTP

            if hits:
                version_hint = probe_def.get("version_hint")
                candidates.append(CMSCandidate(
                    cms=cms_name,
                    version=version_hint,
                    confidence=probe_def["confidence"],
                    method="probe_matrix",
                    details={"probe_hits": hits},
                ))

        return candidates

    # -- Method 4: Cookie analysis ----------------------------------------

    def check_cookies(self, fqdn: str) -> list[CMSCandidate]:
        """Fetch homepage and analyze Set-Cookie headers."""
        # Cookies are already collected in check_meta_tags (piggyback).
        # This method is only called standalone if meta_tags wasn't run.
        candidates: list[CMSCandidate] = []
        if not self._can_request():
            return candidates

        self._count_request()
        status, headers, _, cookies = _fetch(f"https://{fqdn}/")
        if cookies:
            candidates = self._match_cookies(cookies)
        return candidates

    # -- Method 5: Response-Header analysis --------------------------------

    def check_headers(self, fqdn: str) -> list[CMSCandidate]:
        """Check response headers for CMS indicators."""
        # Headers are already collected in check_meta_tags (piggyback).
        # This method is only called standalone if meta_tags wasn't run.
        candidates: list[CMSCandidate] = []
        if not self._can_request():
            return candidates

        self._count_request()
        status, headers, _, _ = _fetch(f"https://{fqdn}/")
        if status == 0:
            return candidates

        for header_name, value_pattern, cms_name in HEADER_CMS_PATTERNS:
            header_val = headers.get(header_name, "")
            if header_val and re.search(value_pattern, header_val):
                candidates.append(CMSCandidate(
                    cms=cms_name,
                    confidence=0.75,
                    method="response_header",
                    details={"header": header_name, "value": header_val},
                ))

        return candidates

    # -- Cookie matching helper -------------------------------------------

    def _match_cookies(self, cookies: list[tuple[str, str]]) -> list[CMSCandidate]:
        candidates: list[CMSCandidate] = []
        for cookie_name, cookie_value in cookies:
            for pattern, cms_name, version_hint in COOKIE_CMS_MAP:
                if re.search(pattern, cookie_name, re.IGNORECASE):
                    candidates.append(CMSCandidate(
                        cms=cms_name,
                        version=version_hint,
                        confidence=0.80,
                        method="cookie_analysis",
                        details={"cookie_name": cookie_name},
                    ))
                    break  # One match per cookie is enough
        return candidates

    # -- Merge results ----------------------------------------------------

    def _merge_results(self, all_candidates: list[CMSCandidate]) -> CMSResult:
        """Merge candidates from all methods into a single CMSResult.

        When multiple methods agree on the same CMS, confidence is boosted.
        """
        if not all_candidates:
            return CMSResult()

        # Group by CMS name (case-insensitive)
        cms_groups: dict[str, list[CMSCandidate]] = {}
        for c in all_candidates:
            key = c.cms.lower()
            cms_groups.setdefault(key, []).append(c)

        # Score each group: base confidence + boost per additional method
        best_cms: Optional[str] = None
        best_score: float = 0.0
        best_group: list[CMSCandidate] = []

        for cms_key, group in cms_groups.items():
            # Take the highest confidence as base
            base = max(c.confidence for c in group)
            # Unique methods that detected this CMS
            methods = list({c.method for c in group})
            # +0.05 per additional confirming method (capped at 0.99)
            boost = min(0.05 * (len(methods) - 1), 0.15)
            score = min(base + boost, 0.99)

            if score > best_score:
                best_score = score
                best_cms = cms_key
                best_group = group

        if not best_cms or not best_group:
            return CMSResult()

        # Determine version (prefer most specific)
        version: Optional[str] = None
        for c in sorted(best_group, key=lambda x: -x.confidence):
            if c.version:
                version = c.version
                break

        # Use the display name from the highest-confidence candidate
        display_name = max(best_group, key=lambda c: c.confidence).cms

        # Collect details
        methods = sorted({c.method for c in best_group})
        details: dict[str, Any] = {}
        for c in best_group:
            for k, v in c.details.items():
                if k not in details:
                    details[k] = v
                elif isinstance(details[k], list) and isinstance(v, list):
                    details[k].extend(v)

        return CMSResult(
            cms=display_name,
            version=version,
            confidence=best_score,
            detection_methods=methods,
            details=details,
        )

    # -- Main entry point --------------------------------------------------

    def fingerprint(self, fqdn: str, webtech_result: Any = None) -> CMSResult:
        """Run the full CMS fingerprinting pipeline.

        Args:
            fqdn: Fully qualified domain name to probe.
            webtech_result: Existing webtech Phase 1 output (avoids re-running).

        Returns:
            CMSResult with detected CMS, version, confidence, and details.
        """
        self._request_count = 0
        all_candidates: list[CMSCandidate] = []

        # 1. webtech (from existing Phase 1 data)
        if webtech_result:
            wt_candidates = self.check_webtech(webtech_result)
            all_candidates.extend(wt_candidates)

        # 2 + 4 + 5. Meta-tags (also collects cookies + headers from homepage)
        meta_candidates = self.check_meta_tags(fqdn)
        all_candidates.extend(meta_candidates)

        # Determine if we have an early CMS match (for targeted probing)
        early_cms: Optional[str] = None
        if all_candidates:
            best = max(all_candidates, key=lambda c: c.confidence)
            if best.confidence >= 0.70:
                early_cms = best.cms

        # 3. Probe matrix (targeted if early_cms found)
        probe_candidates = self.run_probe_matrix(fqdn, early_cms=early_cms)
        all_candidates.extend(probe_candidates)

        result = self._merge_results(all_candidates)

        log.info(
            "cms_fingerprint_complete",
            fqdn=fqdn,
            cms=result.cms,
            version=result.version,
            confidence=result.confidence,
            methods=result.detection_methods,
            requests_made=self._request_count,
        )

        return result

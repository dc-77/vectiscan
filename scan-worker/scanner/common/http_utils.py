"""HTTP probe helpers with parking-page heuristic.

Gleiche Logik für Precheck und Scan-Worker.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import requests


DEFAULT_TIMEOUT = 5.0
USER_AGENT = "VectiScan-Precheck/1.0"

_PARKING_PATTERNS = [
    # Englische Marker (bestehend)
    r"this\s+domain\s+is\s+for\s+sale",
    r"buy\s+this\s+domain",
    r"domain\s+parking",
    r"parkingcrew",
    r"sedoparking",
    r"dan\.com",
    r"afternic",
    r"godaddy\s+parking",
    r"coming\s+soon",
    r"under\s+construction",
    r"default\s+(web\s+)?page",
    r"apache2?\s+default\s+page",
    r"welcome\s+to\s+nginx",
    r"it\s+works!",
    # F-PRE-001: deutsche Marker (DACH-Kundenbasis)
    r"diese\s+domain\s+steht\s+zum\s+verkauf",
    r"diese\s+domain\s+ist\s+(reserviert|geparkt)",
    r"diese\s+seite\s+befindet\s+sich\s+im\s+aufbau",
    r"wartungsarbeiten",
    r"in\s+wartung",
    # F-PRE-001: zusaetzliche englische Marker
    r"under\s+maintenance",
    r"this\s+domain\s+(has\s+)?expired",
    r"domain\s+expired",
    r"this\s+domain\s+is\s+(parked|reserved)",
    # F-PRE-001: weitere Provider-Marker
    r"namecheap",
    r"bodis",
    r"epik",
    r"sav\.com",
    r"uniregistry",
    r"buydomains",
    r"perfectdomain",
]
_PARKING_RE = re.compile("|".join(_PARKING_PATTERNS), re.IGNORECASE)

# F-PRE-001: Allowlist von Hosts, die als Parking-/Domain-Sale-Landing-Pages
# bekannt sind. Wird in is_parking_page geprueft, falls ein Redirect dorthin
# erfolgt (status==200, final_url-Hostname matcht) — fangt die
# Redirect-zu-Landing-Page-Variante ohne Body-Match.
_PARKING_REDIRECT_HOSTS = frozenset({
    "sedoparking.com",
    "parkingcrew.net",
    "dan.com",
    "afternic.com",
    "bodis.com",
    "parkingpage.namecheap.com",
    "epik.com",
    "uniregistry.com",
    "sav.com",
    "buydomains.com",
})

_TITLE_RE = re.compile(r"<title[^>]*>([^<]*)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class HttpProbe:
    url: str
    status: Optional[int]
    title: Optional[str]
    final_url: Optional[str]
    parking: bool
    error: Optional[str]


def probe(url: str, timeout: float = DEFAULT_TIMEOUT) -> HttpProbe:
    """GET a URL, follow redirects, extract title + parking heuristic."""
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
            verify=False,
        )
    except requests.exceptions.RequestException as exc:
        return HttpProbe(url=url, status=None, title=None,
                         final_url=None, parking=False, error=str(exc))

    body = resp.text or ""
    title_match = _TITLE_RE.search(body)
    title = title_match.group(1).strip() if title_match else None
    parking = is_parking_page(title, body, final_url=resp.url or "")
    return HttpProbe(
        url=url,
        status=resp.status_code,
        title=title,
        final_url=resp.url,
        parking=parking,
        error=None,
    )


def probe_both_schemes(fqdn_or_ip: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Probe http:// and https://. Returns combined dict with best result."""
    http = probe(f"http://{fqdn_or_ip}", timeout)
    https = probe(f"https://{fqdn_or_ip}", timeout)
    best = https if (https.status and https.status < 500) else http
    return {
        "http": http.__dict__,
        "https": https.__dict__,
        "status": best.status,
        "title": best.title,
        "final_url": best.final_url,
        "parking": best.parking,
        "reachable": best.status is not None,
    }


def is_parking_page(
    title: Optional[str],
    body: str,
    final_url: str = "",
) -> bool:
    """Heuristik: erkennt Parking-/Maintenance-/Default-Pages.

    Pruefreihenfolge (erste Trefferregel gewinnt):
    1. Title-Pattern-Match
    2. Body-Pattern-Match (erste 4000 Zeichen)
    3. final_url-Hostname in _PARKING_REDIRECT_HOSTS (fangt
       Redirect-zu-Landing-Page-Variante, F-PRE-001)
    """
    if title and _PARKING_RE.search(title):
        return True
    snippet = (body or "")[:4000]
    if _PARKING_RE.search(snippet):
        return True
    if final_url:
        try:
            host = (urlparse(final_url).hostname or "").lower()
        except (ValueError, AttributeError):
            host = ""
        if host and host in _PARKING_REDIRECT_HOSTS:
            return True
    return False

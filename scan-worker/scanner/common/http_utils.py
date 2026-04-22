"""HTTP probe helpers with parking-page heuristic.

Gleiche Logik für Precheck und Scan-Worker.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

import requests


DEFAULT_TIMEOUT = 5.0
USER_AGENT = "VectiScan-Precheck/1.0"

_PARKING_PATTERNS = [
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
]
_PARKING_RE = re.compile("|".join(_PARKING_PATTERNS), re.IGNORECASE)

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
    parking = is_parking_page(title, body)
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


def is_parking_page(title: Optional[str], body: str) -> bool:
    if title and _PARKING_RE.search(title):
        return True
    snippet = (body or "")[:4000]
    return bool(_PARKING_RE.search(snippet))

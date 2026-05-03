"""WAF-Block-Detector (PR-VPN, 2026-05-03).

Erkennt anhand der letzten Tool-Responses pro Host, ob das Target uns
gerade aktiv blockiert (CloudFlare/Akamai/Imperva/Sucuri-Pattern).
Entscheidung dient als Trigger fuer den optionalen VPN-Switch.

Schwellen sind konservativ — wir wollen NICHT bei jedem 429 sofort VPN
aktivieren, sondern nur wenn das Pattern "geblockt" eindeutig ist.

Heuristik (mind. 2 Signale ODER 1 starker WAF-Marker im Body):
  - >=3 HTTP 429 in 60s
  - >=10 HTTP 403 in 60s (wo vorher 200er kamen)
  - >=5 Timeouts in 60s
  - 1x CloudFlare-Challenge-Body-Marker
  - 1x Akamai/Imperva/Sucuri-Body-Marker
  - 1x Burst von Mini-Responses (<500 Byte) nachdem vorher 5KB+ kamen
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Optional

import structlog

log = structlog.get_logger()

# WAF-Body-Signaturen (case-insensitive Substring-Suche im ersten 500-Byte-Excerpt)
_HARD_BLOCK_MARKERS = [
    # CloudFlare
    "__cf_chl",
    "cf-mitigated",
    "just a moment",
    "checking your browser",
    "cf-ray",  # alleine nicht hart, aber im Body deutet auf Challenge-Page
    # Akamai
    "/_incapsula_resource",
    "incapsula",
    "akamai",
    # Imperva
    "imperva",
    "_imperva_",
    # Sucuri
    "access-denied-sucuri",
    "sucuri website firewall",
    # AWS WAF / Generic
    "request blocked",
    "blocked by aws waf",
    # F5 BIG-IP ASM
    "the requested url was rejected",
]

# Zeitfenster fuer alle Counters
_WINDOW_SECONDS = 60.0
_MIN_429_FOR_BLOCK = 3
_MIN_403_FOR_BLOCK = 10
_MIN_TIMEOUTS_FOR_BLOCK = 5
# Body-Drop-Heuristik
_TINY_RESPONSE_BYTES = 500
_PRIOR_LARGE_RESPONSE_BYTES = 5000
_TINY_BURST_COUNT = 5


@dataclass
class _HostStats:
    """Sliding-Window-Counter pro Host."""

    # Liste von (timestamp, status_code, body_size, body_excerpt_lower)
    events: Deque[tuple[float, int, int, str]] = field(default_factory=deque)
    # Saw-Marker: bleibt True ab Erstmal-Erkennung, blockiert NICHT spaeter zurueck
    hard_marker_hit: bool = False
    block_decided_at: Optional[float] = None  # cooldown nach Block-Entscheidung

    def prune(self, now: float) -> None:
        """Entferne Events aelter als Window."""
        cutoff = now - _WINDOW_SECONDS
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()


class BlockDetector:
    """Hauptklasse — pro Order eine Instanz, Hosts werden intern gemanagt."""

    def __init__(self):
        self._hosts: dict[str, _HostStats] = {}

    def report_response(
        self,
        host: str,
        status_code: int,
        body_size: int,
        body_excerpt: str = "",
        is_timeout: bool = False,
    ) -> None:
        """Tool meldet eine Response. Body-Excerpt erste 500 Bytes reichen."""
        if not host:
            return
        stats = self._hosts.setdefault(host, _HostStats())
        now = time.monotonic()
        stats.prune(now)

        # Status -1 = Timeout (von tools/__init__.py konventioniert)
        effective_status = -1 if is_timeout else int(status_code or 0)
        excerpt_lower = (body_excerpt or "")[:500].lower()
        stats.events.append((now, effective_status, int(body_size or 0), excerpt_lower))

        # Hard-Marker einmalig pruefen
        if not stats.hard_marker_hit and excerpt_lower:
            for marker in _HARD_BLOCK_MARKERS:
                if marker in excerpt_lower:
                    stats.hard_marker_hit = True
                    log.warning(
                        "waf_hard_marker_detected",
                        host=host, marker=marker,
                    )
                    break

    def is_blocked(self, host: str) -> tuple[bool, str]:
        """Prueft Heuristik. Returns (blocked, reason)."""
        stats = self._hosts.get(host)
        if not stats:
            return False, "no_data"
        now = time.monotonic()
        stats.prune(now)

        # Hard-Marker = sofort True
        if stats.hard_marker_hit:
            return True, "waf_body_marker"

        if not stats.events:
            return False, "empty_window"

        signals: list[str] = []
        hard_signals: list[str] = []
        n_429 = sum(1 for _, s, _, _ in stats.events if s == 429)
        n_403 = sum(1 for _, s, _, _ in stats.events if s == 403)
        n_timeout = sum(1 for _, s, _, _ in stats.events if s == -1)
        n_2xx = sum(1 for _, s, _, _ in stats.events if 200 <= s < 300)

        # HARD-SIGNALE: jedes alleine reicht fuer Block-Entscheidung
        if n_429 >= _MIN_429_FOR_BLOCK:
            hard_signals.append(f"429_burst({n_429})")
        if n_timeout >= _MIN_TIMEOUTS_FOR_BLOCK:
            hard_signals.append(f"timeout_burst({n_timeout})")

        # WEICHE SIGNALE: brauchen Kombination (mit hard ODER mit anderem soft)
        # 403 nur als Signal wenn auch echte 200er existierten — sonst ist es ein
        # immer-403-Backend ohne Block-Charakter.
        if n_403 >= _MIN_403_FOR_BLOCK and n_2xx > 0:
            signals.append(f"403_burst_after_2xx({n_403})")
        # Body-Drop: in den letzten N Events alle <500 Byte, vorher >=1 mit >5KB
        if len(stats.events) >= _TINY_BURST_COUNT + 1:
            recent = list(stats.events)[-_TINY_BURST_COUNT:]
            prior = list(stats.events)[:-_TINY_BURST_COUNT]
            recent_all_tiny = all(sz < _TINY_RESPONSE_BYTES for _, _, sz, _ in recent)
            prior_had_large = any(sz >= _PRIOR_LARGE_RESPONSE_BYTES for _, _, sz, _ in prior)
            if recent_all_tiny and prior_had_large:
                signals.append("body_size_drop")

        all_signals = hard_signals + signals
        # Block-Entscheidung: 1 Hard ODER 2 weiche
        if hard_signals or len(signals) >= 2:
            return True, "+".join(all_signals)
        return False, "below_threshold" if signals else "no_signals"

    def reset_host(self, host: str) -> None:
        """Cleanup fuer einen Host (z.B. nach erfolgreichem VPN-Switch)."""
        self._hosts.pop(host, None)

    def stats_summary(self) -> dict[str, dict]:
        """Fuer Audit-Trail: was wurde pro Host gemessen."""
        out: dict[str, dict] = {}
        now = time.monotonic()
        for host, stats in self._hosts.items():
            stats.prune(now)
            out[host] = {
                "events_in_window": len(stats.events),
                "hard_marker_hit": stats.hard_marker_hit,
            }
        return out


__all__ = ["BlockDetector"]

"""VPN-Switch (PR-VPN, 2026-05-03).

Adaptive VPN-Aktivierung bei WAF-Block-Detection.

Architektur (Variante C aus Plan):
- Separater Container `vpn-gw` mit ExpressVPN-CLI + Tinyproxy
- Default OFF (Traffic geht direkt)
- Bei Block-Detection: scan-worker setzt HTTPS_PROXY=http://vpn-gw:3128
  via env-Injection in run_tool() → nachfolgende Tools gehen durch VPN
- Tinyproxy auf vpn-gw nimmt HTTP-Requests an, leitet via System-Routing
  durch den ExpressVPN-Tunnel raus

Diese Datei abstrahiert den State; die eigentliche VPN-Activation passiert
im vpn-gw-Container via interner HTTP-API (`POST /vpn/connect?location=DE`).

Fallback bei fehlendem Token / disabled Feature:
- VPN_ENABLED-ENV nicht gesetzt → VpnSwitch.is_available() = False
- Alle Methoden no-op, Tools laufen direkt
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import structlog

log = structlog.get_logger()

# ENV-Konfiguration
ENV_VPN_ENABLED = "VPN_ENABLED"  # "true"/"false" — globaler Killswitch
ENV_VPN_GATEWAY_URL = "VPN_GATEWAY_URL"  # z.B. http://vpn-gw:8080
ENV_VPN_PROXY_URL = "VPN_PROXY_URL"  # z.B. http://vpn-gw:3128 (was HTTPS_PROXY-ENV bekommt)
ENV_VPN_TOKEN = "EXPRESSVPN_ACCESS_TOKEN"  # Token im vpn-gw-Container, hier nur Marker

# Locations fuer Round-Robin (ExpressVPN-Notation)
DEFAULT_LOCATIONS = [
    "germany",
    "switzerland",
    "netherlands",
    "austria",
    "sweden",
]


@dataclass
class _VpnState:
    active: bool = False
    location: Optional[str] = None
    activated_at: Optional[float] = None
    activations: list[dict] = field(default_factory=list)  # Audit-Trail


class VpnSwitch:
    """State-Machine fuer VPN-Aktivierung.

    Thread-safe. Eine Instanz pro Order — bei Order-Ende disconnect.
    """

    def __init__(self, order_id: str = "", subscription_strategy: str = "auto_on_block"):
        self.order_id = order_id
        self.subscription_strategy = subscription_strategy  # never|auto_on_block|always
        self._state = _VpnState()
        self._lock = threading.Lock()
        self._location_idx = 0

    # ------------------------------------------------------------------
    # Verfuegbarkeits-Check (Fallback wenn nichts konfiguriert)
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """True wenn VPN-Feature ueberhaupt nutzbar ist.

        Bedingungen:
        - Subscription-Strategy ist nicht 'never'
        - VPN_ENABLED=true im ENV
        - VPN_GATEWAY_URL gesetzt
        - VPN_PROXY_URL gesetzt
        """
        if self.subscription_strategy == "never":
            return False
        if os.environ.get(ENV_VPN_ENABLED, "").lower() not in ("1", "true", "yes"):
            return False
        if not os.environ.get(ENV_VPN_GATEWAY_URL):
            return False
        if not os.environ.get(ENV_VPN_PROXY_URL):
            return False
        return True

    def is_active(self) -> bool:
        with self._lock:
            return self._state.active

    def current_proxy_url(self) -> Optional[str]:
        """Wenn VPN aktiv → die HTTPS_PROXY-URL fuer Tools. Sonst None."""
        with self._lock:
            if not self._state.active:
                return None
            return os.environ.get(ENV_VPN_PROXY_URL)

    # ------------------------------------------------------------------
    # Activation
    # ------------------------------------------------------------------

    def should_activate(self, host: str, block_reason: str) -> bool:
        """Entscheidung: VPN einschalten?"""
        if not self.is_available():
            return False
        if self.subscription_strategy == "always":
            return True
        if self.subscription_strategy == "auto_on_block":
            # Nur bei klarem Block-Signal, nicht bei jedem 403
            return bool(block_reason and block_reason not in ("no_data", "below_threshold", "no_signals"))
        return False

    def enable(self, reason: str = "auto_on_block", host: str = "") -> bool:
        """Aktiviere VPN. Returns True bei Erfolg.

        Idempotent — wenn schon aktiv, neue Location wird gewaehlt
        (Rotation, falls erste Location auch geblockt ist).
        """
        if not self.is_available():
            log.info("vpn_skip_unavailable", reason="not_configured")
            return False
        location = self._next_location()
        ok = self._gateway_connect(location)
        with self._lock:
            self._state.active = ok
            self._state.location = location if ok else None
            self._state.activated_at = time.time() if ok else None
            self._state.activations.append({
                "host": host,
                "reason": reason,
                "location": location,
                "success": ok,
                "ts": time.time(),
            })
        log.info("vpn_activation_attempt", location=location, success=ok,
                 reason=reason, host=host, order_id=self.order_id)
        return ok

    def rotate(self, host: str = "") -> bool:
        """Wechsel Location (Block trotz VPN — IP der ersten Location auch geblockt)."""
        return self.enable(reason="rotation", host=host)

    def disable(self) -> None:
        """Deaktiviere VPN (z.B. am Order-Ende)."""
        with self._lock:
            if not self._state.active:
                return
        if self.is_available():
            self._gateway_disconnect()
        with self._lock:
            self._state.active = False
            self._state.location = None
            self._state.activated_at = None
        log.info("vpn_disabled", order_id=self.order_id)

    def _next_location(self) -> str:
        """Round-Robin durch DEFAULT_LOCATIONS."""
        loc = DEFAULT_LOCATIONS[self._location_idx % len(DEFAULT_LOCATIONS)]
        self._location_idx += 1
        return loc

    # ------------------------------------------------------------------
    # Gateway-API (HTTP zu vpn-gw-Container)
    # ------------------------------------------------------------------

    def _gateway_connect(self, location: str) -> bool:
        """Sage vpn-gw an: connect zur Location. Wartet auf 'connected'."""
        url = os.environ.get(ENV_VPN_GATEWAY_URL)
        if not url:
            return False
        try:
            import requests
            resp = requests.post(
                f"{url.rstrip('/')}/vpn/connect",
                json={"location": location},
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                return bool(data.get("connected"))
            log.warning("vpn_gateway_connect_failed",
                        status=resp.status_code, body=resp.text[:200])
        except Exception as e:
            log.warning("vpn_gateway_unreachable", error=str(e))
        return False

    def _gateway_disconnect(self) -> None:
        url = os.environ.get(ENV_VPN_GATEWAY_URL)
        if not url:
            return
        try:
            import requests
            requests.post(f"{url.rstrip('/')}/vpn/disconnect", timeout=10)
        except Exception as e:
            log.warning("vpn_gateway_disconnect_error", error=str(e))

    # ------------------------------------------------------------------
    # Audit-Trail
    # ------------------------------------------------------------------

    def get_activations(self) -> list[dict]:
        """Fuer orders.vpn_activations JSONB-Persistierung."""
        with self._lock:
            return list(self._state.activations)


# ----------------------------------------------------------------------
# Per-Order Singleton (eine VpnSwitch-Instanz pro Order)
# ----------------------------------------------------------------------

_switches: dict[str, VpnSwitch] = {}
_switches_lock = threading.Lock()


def get_switch(order_id: str, subscription_strategy: str = "auto_on_block") -> VpnSwitch:
    """Hole oder erzeuge VpnSwitch fuer order_id."""
    with _switches_lock:
        if order_id not in _switches:
            _switches[order_id] = VpnSwitch(order_id, subscription_strategy)
        return _switches[order_id]


def cleanup_switch(order_id: str) -> Optional[list[dict]]:
    """Disconnect + remove. Returns Activations-Audit-Trail."""
    with _switches_lock:
        sw = _switches.pop(order_id, None)
    if sw:
        sw.disable()
        return sw.get_activations()
    return None


__all__ = ["VpnSwitch", "get_switch", "cleanup_switch", "DEFAULT_LOCATIONS"]

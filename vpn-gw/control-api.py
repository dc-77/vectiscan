"""vpn-gw Control-API (PR-VPN, 2026-05-03).

Kleine FastAPI auf Port 8080 fuer Steuerung des ExpressVPN-CLI durch
den scan-worker. POST-Endpoints connect/disconnect/status.

Fallback: wenn ExpressVPN-CLI nicht installiert (kein .deb im Build-
Context) ODER Token nicht aktiviert, antwortet API mit
{"connected": False, "vpn_available": False}, damit scan-worker
sauber im "kein VPN"-Mode weiterlaeuft.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="vpn-gw control")


class ConnectRequest(BaseModel):
    location: str = "germany"


def _expressvpn_available() -> bool:
    return shutil.which("expressvpn") is not None


def _get_token() -> Optional[str]:
    return os.environ.get("EXPRESSVPN_ACCESS_TOKEN")


def _ensure_activated() -> bool:
    """ExpressVPN-Account einmalig aktivieren falls noch nicht.

    Aktivierung passiert via `expressvpn activate <code>` interaktiv —
    wir nutzen `expect` um das durchzusteuern, falls Token vorhanden.
    """
    if not _expressvpn_available() or not _get_token():
        return False
    try:
        # Status checken
        r = subprocess.run(
            ["expressvpn", "status"],
            capture_output=True, text=True, timeout=5,
        )
        if "Not Activated" not in r.stdout and "Not Activated" not in r.stderr:
            return True
        # Aktivieren via expect-Skript
        token = _get_token()
        expect_script = f"""
spawn expressvpn activate
expect "code:"
send "{token}\\r"
expect "share anonymous"
send "n\\r"
expect eof
"""
        subprocess.run(
            ["expect", "-c", expect_script],
            capture_output=True, text=True, timeout=30,
        )
        return True
    except Exception:
        return False


@app.get("/vpn/status")
def status():
    if not _expressvpn_available():
        return {"vpn_available": False, "connected": False, "reason": "expressvpn-cli not installed"}
    if not _get_token():
        return {"vpn_available": False, "connected": False, "reason": "EXPRESSVPN_ACCESS_TOKEN not set"}
    try:
        r = subprocess.run(
            ["expressvpn", "status"],
            capture_output=True, text=True, timeout=5,
        )
        out = r.stdout + r.stderr
        connected = "Connected to" in out
        location = None
        for line in out.splitlines():
            if "Connected to" in line:
                location = line.replace("Connected to", "").strip().strip(":").strip()
                break
        return {"vpn_available": True, "connected": connected, "location": location}
    except Exception as e:
        return {"vpn_available": True, "connected": False, "error": str(e)}


@app.post("/vpn/connect")
def connect(req: ConnectRequest):
    if not _expressvpn_available():
        return {"connected": False, "vpn_available": False, "reason": "expressvpn-cli not installed"}
    if not _get_token():
        return {"connected": False, "vpn_available": False, "reason": "EXPRESSVPN_ACCESS_TOKEN not set"}
    if not _ensure_activated():
        return {"connected": False, "vpn_available": True, "reason": "activation_failed"}
    try:
        # Disconnect first (clean state)
        subprocess.run(["expressvpn", "disconnect"], capture_output=True, timeout=10)
        # Connect
        r = subprocess.run(
            ["expressvpn", "connect", req.location],
            capture_output=True, text=True, timeout=30,
        )
        out = r.stdout + r.stderr
        connected = "Connected to" in out
        return {
            "connected": connected,
            "vpn_available": True,
            "location": req.location,
            "stdout": r.stdout[:500],
        }
    except subprocess.TimeoutExpired:
        return {"connected": False, "error": "timeout"}
    except Exception as e:
        return {"connected": False, "error": str(e)}


@app.post("/vpn/disconnect")
def disconnect():
    if not _expressvpn_available():
        return {"disconnected": True, "vpn_available": False}
    try:
        subprocess.run(["expressvpn", "disconnect"], capture_output=True, timeout=10)
        return {"disconnected": True, "vpn_available": True}
    except Exception as e:
        return {"disconnected": False, "error": str(e)}


@app.get("/health")
def health():
    return {"status": "ok"}

"""Tests fuer scanner.common.http_utils.is_parking_page (F-PRE-001).

Coverage:
- Deutsche Parking-Marker (DACH-Kundenbasis)
- Maintenance-Marker (DE + EN)
- Redirect-zu-Parking-Host (final_url-Allowlist)
- Regression: bestehende englische Patterns weiter aktiv
"""

from __future__ import annotations

import pytest


def test_parking_pattern_german_marker() -> None:
    """Deutsche Verkaufs-Marker werden erkannt."""
    from scanner.common.http_utils import is_parking_page

    body = (
        "<html><body><h1>Diese Domain steht zum Verkauf</h1>"
        "<p>Bitte kontaktieren Sie uns.</p></body></html>"
    )
    assert is_parking_page(title=None, body=body) is True


def test_parking_pattern_german_marker_reserviert() -> None:
    """Variante 'Diese Domain ist reserviert' wird erkannt."""
    from scanner.common.http_utils import is_parking_page

    body = "<html><body>Diese Domain ist reserviert</body></html>"
    assert is_parking_page(title=None, body=body) is True


def test_parking_pattern_maintenance_german() -> None:
    """Wartungsarbeiten / 'in Wartung' werden erkannt."""
    from scanner.common.http_utils import is_parking_page

    body_a = "<html><body><h1>Wartungsarbeiten</h1></body></html>"
    body_b = "<html><body><h1>Server in Wartung</h1></body></html>"
    assert is_parking_page(title=None, body=body_a) is True
    assert is_parking_page(title=None, body=body_b) is True


def test_parking_pattern_under_maintenance_english() -> None:
    """Englischer Maintenance-Marker wird erkannt."""
    from scanner.common.http_utils import is_parking_page

    body = "<html><body><h1>Site under maintenance</h1></body></html>"
    assert is_parking_page(title=None, body=body) is True


def test_parking_redirect_to_namecheap_parking_page() -> None:
    """Redirect auf parkingpage.namecheap.com loest parking=True ohne Body-Match."""
    from scanner.common.http_utils import is_parking_page

    body = "<html><body>Welcome</body></html>"  # Kein Body-Marker
    final = "https://parkingpage.namecheap.com/?d=example.com"
    assert is_parking_page(title=None, body=body, final_url=final) is True


def test_parking_redirect_to_sedoparking() -> None:
    """sedoparking.com-Redirect wird via Allowlist erkannt."""
    from scanner.common.http_utils import is_parking_page

    final = "https://sedoparking.com/example.de"
    assert is_parking_page(title=None, body="", final_url=final) is True


def test_parking_redirect_unbekannter_host_kein_match() -> None:
    """Final-URL auf nicht-allowlisteten Host triggert NICHT (kein FP)."""
    from scanner.common.http_utils import is_parking_page

    body = "<html><body>Ganz normaler Inhalt</body></html>"
    final = "https://www.example.com/landing"
    assert is_parking_page(title=None, body=body, final_url=final) is False


def test_parking_pattern_old_english_still_works() -> None:
    """Regression: bestehendes 'this domain is for sale' weiter aktiv."""
    from scanner.common.http_utils import is_parking_page

    body = "<html><body>This domain is for sale</body></html>"
    assert is_parking_page(title=None, body=body) is True


def test_parking_pattern_namecheap_in_body() -> None:
    """Provider-Token 'namecheap' im Body trigger Parking-Erkennung."""
    from scanner.common.http_utils import is_parking_page

    body = '<html><body><a href="https://namecheap.com">Buy</a></body></html>'
    assert is_parking_page(title=None, body=body) is True


def test_parking_signature_backwards_compatible() -> None:
    """is_parking_page funktioniert weiter ohne final_url-Argument (2-arg call)."""
    from scanner.common.http_utils import is_parking_page

    body = "Welcome to nginx!"
    assert is_parking_page(None, body) is True

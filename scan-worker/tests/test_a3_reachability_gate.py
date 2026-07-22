"""Tests fuer A3 (Jul 2026): Reachability-Vorcheck raus.

Der TCP-Socket-Vorcheck (_is_host_reachable, 443/80) vor Phase 1 ist
entfernt — nmap deckt Reachability mit `-Pn` selbst ab. Ein Host ohne
TCP-443/80-Antwort landet NICHT mehr im pauschalen host_unreachable-Skip,
sondern geht in Phase 1. Die Funktion selbst bleibt erhalten (Rule 1).
"""

import inspect

from scanner import worker


def test_is_host_reachable_function_still_exists():
    """Rule 1: die Funktion bleibt (nur der Aufruf/Gate entfiel)."""
    assert callable(worker._is_host_reachable)


def test_phase1_path_no_longer_gates_on_reachability():
    """Der Host-Skip-Gate mit host_unreachable ist aus dem Phase-1-Pfad raus."""
    src = inspect.getsource(worker._process_job)
    # Gate-Aufruf entfernt
    assert "_is_host_reachable(ip)" not in src
    # Der pauschale host_unreachable-Skip (record_host_outage-Aufruf) ist weg
    assert '_record_host_outage(ip, 1, "skipped", "host_unreachable")' not in src
    assert '_record_host_outage(ip, 2, "skipped", "host_unreachable")' not in src
    # ...und auch der log.warning fuer den Gate-Skip
    assert 'log.warning("host_unreachable"' not in src
    # Host geht stattdessen direkt in Phase 1
    assert "run_phase1(" in src


def test_scannable_filter_only_reacts_to_real_skips():
    """Der scannable-Filter kippt Hosts nur noch bei echtem skipped-Flag,
    nicht mehr wegen des alten Vorchecks."""
    src = inspect.getsource(worker._process_job)
    # Filter existiert weiterhin und liest das profile-skipped-Flag
    assert 'p.get("skipped")' in src
    # Es gibt keinen 'reason": "unreachable"'-Rueckgabewert mehr aus dem Gate
    assert '"reason": "unreachable"' not in src

"""Tests fuer _enforce_scan_for_live_web_hosts (KI #1 Skip-Override).

Override greift wenn KI 'skip' sagt aber mindestens 1 primary VHost
live ist. Verhindert False-Negatives bei Cloudflare-WAF-403, Title="
Redirector", etc.
"""

from scanner.ai_strategy import _enforce_scan_for_live_web_hosts


def test_override_with_vhosts_one_live():
    """Multi-VHost-Probe: 1 primary mit 200 → Override greift.

    vhosts kommen aus Phase 0b schon nach Status sortiert (200 zuerst).
    """
    hosts = [{"ip": "1.1.1.1", "vhosts": [
        {"fqdn": "b.x.com", "status": 200, "title": "Login", "final_url": "https://b.x.com/"},
        {"fqdn": "a.x.com", "status": 403, "title": "WAF", "final_url": "https://a.x.com/"},
    ]}]
    strat = {"hosts": [{"ip": "1.1.1.1", "action": "skip", "reasoning": "WAF only"}]}
    n = _enforce_scan_for_live_web_hosts(strat, hosts, "x.com")
    assert n == 1
    assert strat["hosts"][0]["action"] == "scan"
    # b.x.com (erster live = 200) → genannt in reasoning
    assert "b.x.com" in strat["hosts"][0]["reasoning"]


def test_override_legacy_web_probe_fallback():
    """Hosts ohne vhosts (Legacy): web_probe-Pfad greift."""
    hosts = [{"ip": "2.2.2.2", "web_probe": {
        "has_web": True, "status": 200, "title": "X",
        "final_url": "https://x.com/", "web_fqdn": "x.com",
    }}]
    strat = {"hosts": [{"ip": "2.2.2.2", "action": "skip", "reasoning": "legacy"}]}
    n = _enforce_scan_for_live_web_hosts(strat, hosts, "x.com")
    assert n == 1


def test_no_override_when_no_live_vhost():
    """Kein primary VHost live → kein Override."""
    hosts = [{"ip": "3.3.3.3", "vhosts": []}]
    strat = {"hosts": [{"ip": "3.3.3.3", "action": "skip", "reasoning": "parking"}]}
    n = _enforce_scan_for_live_web_hosts(strat, hosts, "x.com")
    assert n == 0
    assert strat["hosts"][0]["action"] == "skip"


def test_no_override_for_action_scan():
    """Hosts die schon scan sind werden nicht angefasst."""
    hosts = [{"ip": "4.4.4.4", "vhosts": [{"fqdn": "x.com", "status": 200}]}]
    strat = {"hosts": [{"ip": "4.4.4.4", "action": "scan", "reasoning": "ok"}]}
    n = _enforce_scan_for_live_web_hosts(strat, hosts, "x.com")
    assert n == 0


def test_override_with_cloudflare_403():
    """Cloudflare-WAF-403 wird trotz Skip-KI als live erkannt."""
    hosts = [{"ip": "5.5.5.5", "vhosts": [
        {"fqdn": "online.x.com", "status": 403, "title": "Just a moment...",
         "final_url": "https://online.x.com/"},
    ]}]
    strat = {"hosts": [{"ip": "5.5.5.5", "action": "skip", "reasoning": "CF CDN"}]}
    n = _enforce_scan_for_live_web_hosts(strat, hosts, "x.com")
    assert n == 1

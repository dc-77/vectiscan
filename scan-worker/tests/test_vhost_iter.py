"""Tests fuer scanner.vhost_iter — primary VHost-Iteration."""

from scanner.vhost_iter import iter_primary_vhosts, primary_vhost


def test_iter_uses_vhosts_when_present():
    host = {"fqdns": ["a.x.com", "b.x.com"],
            "vhosts": [{"fqdn": "b.x.com"}, {"fqdn": "a.x.com"}]}
    # vhosts gewinnen vor fqdns; Reihenfolge wie in vhosts
    assert iter_primary_vhosts(host) == ["b.x.com", "a.x.com"]


def test_iter_legacy_fqdns_when_no_vhosts():
    host = {"fqdns": ["a.x.com", "b.x.com", "c.x.com"]}
    assert iter_primary_vhosts(host, cap=2) == ["a.x.com", "b.x.com"]


def test_iter_empty_host_returns_empty():
    assert iter_primary_vhosts({}) == []


def test_primary_vhost_first_element():
    host = {"vhosts": [{"fqdn": "a.x.com"}, {"fqdn": "b.x.com"}]}
    assert primary_vhost(host) == "a.x.com"


def test_primary_vhost_legacy_fallback():
    host = {"fqdns": ["a.x.com", "b.x.com"]}
    assert primary_vhost(host) == "a.x.com"


def test_primary_vhost_none_when_empty():
    assert primary_vhost({}) is None

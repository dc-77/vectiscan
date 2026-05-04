"""Tests fuer reporter.ai_cache (A2 — content_hash Sekundaer-Cache)."""

from reporter.ai_cache import cache_key, compute_content_hash


def test_compute_content_hash_deterministic():
    h1 = compute_content_hash("a", "b", "c")
    h2 = compute_content_hash("a", "b", "c")
    assert h1 == h2


def test_compute_content_hash_different_input():
    h1 = compute_content_hash("a", "b", "c")
    h2 = compute_content_hash("a", "b", "d")
    assert h1 != h2


def test_compute_content_hash_handles_none():
    """None-Pieces werden uebersprungen, kein Crash."""
    h1 = compute_content_hash("a", None, "c")
    h2 = compute_content_hash("a", "c")
    assert h1 == h2


def test_cache_key_3_modes_distinct():
    h = compute_content_hash("x")
    k_content = cache_key(model="m", system="", messages=[],
                           namespace="n", content_hash=h)
    k_order = cache_key(model="m", system="", messages=[],
                         namespace="n", order_scope="ord-1")
    k_input = cache_key(model="m", system="sys", messages=[{"role": "user", "content": "x"}],
                         namespace="n")
    assert len({k_content, k_order, k_input}) == 3


def test_cache_key_content_hash_takes_precedence():
    """Wenn content_hash UND order_scope: content_hash gewinnt."""
    h = compute_content_hash("x")
    k1 = cache_key(model="m", system="", messages=[], namespace="n",
                    content_hash=h, order_scope="ord-1")
    k2 = cache_key(model="m", system="", messages=[], namespace="n",
                    content_hash=h)  # ohne order_scope
    assert k1 == k2  # order_scope wird ignoriert wenn content_hash da


def test_cache_key_content_hash_independent_of_order():
    """Gleicher content_hash bei 2 verschiedenen order_ids → gleicher Key."""
    h = compute_content_hash("x")
    k1 = cache_key(model="m", system="", messages=[], namespace="n",
                    content_hash=h, order_scope="ord-A")
    k2 = cache_key(model="m", system="", messages=[], namespace="n",
                    content_hash=h, order_scope="ord-B")
    assert k1 == k2  # Order-uebergreifend reproduzierbar

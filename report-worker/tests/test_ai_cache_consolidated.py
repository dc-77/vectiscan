"""Tests fuer reporter.ai_cache (A2 — content_hash Sekundaer-Cache)."""

from unittest.mock import patch

import reporter.ai_cache as ai_cache
from reporter.ai_cache import CACHE_VERSION, cache_key, compute_content_hash


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


# --- C2 (21.07.2026): Cache-Invalidierung bei Prompt-Aenderungen ---------------


def test_content_hash_key_changes_with_system_prompt():
    """Der content_hash-Modus invalidiert bei Prompt-Aenderung automatisch —
    claude_client baut den content_hash aus (system_prompt, host_inventory,
    tech_profiles, consolidated_findings)."""
    h_alt = compute_content_hash("SYSTEM-PROMPT-ALT", "inventory", "findings")
    h_neu = compute_content_hash("SYSTEM-PROMPT-NEU", "inventory", "findings")
    k_alt = cache_key(model="m", system="", messages=[], namespace="reporter_v1",
                      content_hash=h_alt, order_scope="ord-1")
    k_neu = cache_key(model="m", system="", messages=[], namespace="reporter_v1",
                      content_hash=h_neu, order_scope="ord-1")
    assert k_alt != k_neu


def test_order_scope_key_is_prompt_independent():
    """Dokumentiert die Luecke: der order_scope-Key kennt den Prompt nicht.
    Deshalb braucht jede Prompt-Aenderung einen CACHE_VERSION-Bump."""
    k_alt = cache_key(model="m", system="SYSTEM-PROMPT-ALT", messages=[],
                      namespace="reporter_v1", order_scope="ord-1")
    k_neu = cache_key(model="m", system="SYSTEM-PROMPT-NEU", messages=[],
                      namespace="reporter_v1", order_scope="ord-1")
    assert k_alt == k_neu


def test_order_scope_key_changes_with_cache_version():
    """CACHE_VERSION ist der einzige chirurgische Hebel gegen den
    prompt-unabhaengigen order_scope-Key."""
    k_v2 = cache_key(model="m", system="", messages=[], namespace="reporter_v1",
                     order_scope="ord-1")
    with patch.object(ai_cache, "CACHE_VERSION", "v1"):
        k_v1 = cache_key(model="m", system="", messages=[], namespace="reporter_v1",
                         order_scope="ord-1")
    assert k_v1 != k_v2


def test_order_scope_key_changes_with_policy_version():
    k_a = cache_key(model="m", system="", messages=[], namespace="reporter_v1",
                    order_scope="ord-1")
    with patch.object(ai_cache, "POLICY_VERSION", "1999-01-01.0"):
        k_b = cache_key(model="m", system="", messages=[], namespace="reporter_v1",
                        order_scope="ord-1")
    assert k_a != k_b


def test_cache_version_is_current():
    """Regression: jede Prompt-Aenderung braucht einen CACHE_VERSION-Bump, sonst
    liefert regenerate-report die alte Antwort aus dem order_scope-Key.
    Bump-Historie: v1->v2 Atomaritaets-Prompt (C2), v2->v3 Stichtag/Datums-Block
    im Reporter-Prompt (Juli 2026)."""
    assert CACHE_VERSION == "v3"

"""Pruefung tls_weak_ciphers: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "tls_weak_ciphers"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_tls_weak_ciphers(kind):
    run_fixture(CHECK_ID, kind)

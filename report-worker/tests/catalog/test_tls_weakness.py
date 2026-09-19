"""Pruefung tls_weakness: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "tls_weakness"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_tls_weakness(kind):
    run_fixture(CHECK_ID, kind)

"""Pruefung hsts_short: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "hsts_short"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_hsts_short(kind):
    run_fixture(CHECK_ID, kind)

"""Pruefung cookie_flags: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "cookie_flags"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_cookie_flags(kind):
    run_fixture(CHECK_ID, kind)

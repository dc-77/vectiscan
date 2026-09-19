"""Pruefung session_in_url: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "session_in_url"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_session_in_url(kind):
    run_fixture(CHECK_ID, kind)

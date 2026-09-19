"""Pruefung js_library_outdated: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "js_library_outdated"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_js_library_outdated(kind):
    run_fixture(CHECK_ID, kind)

"""Pruefung directory_listing: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "directory_listing"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_directory_listing(kind):
    run_fixture(CHECK_ID, kind)

"""Pruefung header_duplicate: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "header_duplicate"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_header_duplicate(kind):
    run_fixture(CHECK_ID, kind)

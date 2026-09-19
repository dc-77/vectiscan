"""Pruefung db_exposed: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "db_exposed"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_db_exposed(kind):
    run_fixture(CHECK_ID, kind)

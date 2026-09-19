"""Pruefung dane_missing: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "dane_missing"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_dane_missing(kind):
    run_fixture(CHECK_ID, kind)

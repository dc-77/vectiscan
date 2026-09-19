"""Pruefung sri_missing: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "sri_missing"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_sri_missing(kind):
    run_fixture(CHECK_ID, kind)

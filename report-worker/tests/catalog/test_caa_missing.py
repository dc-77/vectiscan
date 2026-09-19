"""Pruefung caa_missing: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "caa_missing"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_caa_missing(kind):
    run_fixture(CHECK_ID, kind)

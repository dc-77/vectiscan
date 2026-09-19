"""Pruefung mta_sts_missing: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "mta_sts_missing"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_mta_sts_missing(kind):
    run_fixture(CHECK_ID, kind)

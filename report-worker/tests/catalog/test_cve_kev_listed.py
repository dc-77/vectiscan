"""Pruefung cve_kev_listed: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "cve_kev_listed"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_cve_kev_listed(kind):
    run_fixture(CHECK_ID, kind)

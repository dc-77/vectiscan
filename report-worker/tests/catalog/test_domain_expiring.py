"""Pruefung domain_expiring: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "domain_expiring"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_domain_expiring(kind):
    run_fixture(CHECK_ID, kind)

"""Pruefung dns_zone_transfer: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "dns_zone_transfer"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_dns_zone_transfer(kind):
    run_fixture(CHECK_ID, kind)

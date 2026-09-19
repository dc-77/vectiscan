"""Pruefung ip_reputation: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "ip_reputation"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_ip_reputation(kind):
    run_fixture(CHECK_ID, kind)

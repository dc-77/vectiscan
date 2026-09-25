"""Pruefung admin_service_unconfirmed: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "admin_service_unconfirmed"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_admin_service_unconfirmed(kind):
    run_fixture(CHECK_ID, kind)

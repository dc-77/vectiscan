"""Pruefung admin_port_passive_unidentified: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "admin_port_passive_unidentified"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_admin_port_passive_unidentified(kind):
    run_fixture(CHECK_ID, kind)

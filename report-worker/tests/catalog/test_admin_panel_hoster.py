"""Pruefung admin_panel_hoster: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "admin_panel_hoster"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_admin_panel_hoster(kind):
    run_fixture(CHECK_ID, kind)

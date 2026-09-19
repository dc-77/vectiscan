"""Pruefung wordpress_plugin_vulnerable: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "wordpress_plugin_vulnerable"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_wordpress_plugin_vulnerable(kind):
    run_fixture(CHECK_ID, kind)

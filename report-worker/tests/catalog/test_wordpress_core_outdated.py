"""Pruefung wordpress_core_outdated: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "wordpress_core_outdated"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_wordpress_core_outdated(kind):
    run_fixture(CHECK_ID, kind)

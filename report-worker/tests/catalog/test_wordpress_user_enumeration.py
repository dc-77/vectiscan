"""Pruefung wordpress_user_enumeration: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "wordpress_user_enumeration"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_wordpress_user_enumeration(kind):
    run_fixture(CHECK_ID, kind)

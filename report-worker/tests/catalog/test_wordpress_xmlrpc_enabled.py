"""Pruefung wordpress_xmlrpc_enabled: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "wordpress_xmlrpc_enabled"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_wordpress_xmlrpc_enabled(kind):
    run_fixture(CHECK_ID, kind)

"""Pruefung http_alt_port: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "http_alt_port"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_http_alt_port(kind):
    run_fixture(CHECK_ID, kind)

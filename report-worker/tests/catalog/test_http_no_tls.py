"""Pruefung http_no_tls: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "http_no_tls"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_http_no_tls(kind):
    run_fixture(CHECK_ID, kind)

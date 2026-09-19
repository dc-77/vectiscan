"""Pruefung http_header_disclosure: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "http_header_disclosure"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_http_header_disclosure(kind):
    run_fixture(CHECK_ID, kind)

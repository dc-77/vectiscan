"""Pruefung security_headers_incomplete: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "security_headers_incomplete"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_security_headers_incomplete(kind):
    run_fixture(CHECK_ID, kind)

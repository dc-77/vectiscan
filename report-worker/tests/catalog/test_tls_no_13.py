"""Pruefung tls_no_13: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "tls_no_13"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_tls_no_13(kind):
    run_fixture(CHECK_ID, kind)

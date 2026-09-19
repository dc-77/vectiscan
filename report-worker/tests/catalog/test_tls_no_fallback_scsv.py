"""Pruefung tls_no_fallback_scsv: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "tls_no_fallback_scsv"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_tls_no_fallback_scsv(kind):
    run_fixture(CHECK_ID, kind)

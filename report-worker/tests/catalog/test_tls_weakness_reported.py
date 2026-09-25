"""Pruefung tls_weakness_reported: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "tls_weakness_reported"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_tls_weakness_reported(kind):
    run_fixture(CHECK_ID, kind)

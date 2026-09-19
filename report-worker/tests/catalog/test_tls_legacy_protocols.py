"""Pruefung tls_legacy_protocols: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "tls_legacy_protocols"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_tls_legacy_protocols(kind):
    run_fixture(CHECK_ID, kind)

"""Pruefung legacy_protocols_present: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "legacy_protocols_present"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_legacy_protocols_present(kind):
    run_fixture(CHECK_ID, kind)

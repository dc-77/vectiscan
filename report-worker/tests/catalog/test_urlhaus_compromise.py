"""Pruefung urlhaus_compromise: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "urlhaus_compromise"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_urlhaus_compromise(kind):
    run_fixture(CHECK_ID, kind)

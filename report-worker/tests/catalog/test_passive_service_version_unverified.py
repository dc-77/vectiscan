"""Pruefung passive_service_version_unverified: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "passive_service_version_unverified"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_passive_service_version_unverified(kind):
    run_fixture(CHECK_ID, kind)

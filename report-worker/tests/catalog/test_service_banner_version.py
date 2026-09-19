"""Pruefung service_banner_version: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "service_banner_version"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_service_banner_version(kind):
    run_fixture(CHECK_ID, kind)

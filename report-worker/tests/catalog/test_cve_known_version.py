"""Pruefung cve_known_version: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "cve_known_version"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_cve_known_version(kind):
    run_fixture(CHECK_ID, kind)

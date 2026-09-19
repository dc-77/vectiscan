"""Pruefung cors_misconfiguration: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "cors_misconfiguration"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_cors_misconfiguration(kind):
    run_fixture(CHECK_ID, kind)

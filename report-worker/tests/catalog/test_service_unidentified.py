"""Pruefung service_unidentified: ein Test je Fixture (pass, pass_cert, fail)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "service_unidentified"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_service_unidentified(kind):
    run_fixture(CHECK_ID, kind)

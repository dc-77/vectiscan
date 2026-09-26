"""Pruefung service_cert_expired: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "service_cert_expired"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_service_cert_expired(kind):
    run_fixture(CHECK_ID, kind)

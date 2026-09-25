"""Pruefung cert_expiring_later: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "cert_expiring_later"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_cert_expiring_later(kind):
    run_fixture(CHECK_ID, kind)

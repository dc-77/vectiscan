"""Pruefung cert_hostname_mismatch: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "cert_hostname_mismatch"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_cert_hostname_mismatch(kind):
    run_fixture(CHECK_ID, kind)

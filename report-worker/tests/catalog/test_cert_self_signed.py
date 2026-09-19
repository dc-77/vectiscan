"""Pruefung cert_self_signed: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "cert_self_signed"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_cert_self_signed(kind):
    run_fixture(CHECK_ID, kind)

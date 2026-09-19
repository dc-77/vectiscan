"""Pruefung cert_chain_incomplete: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "cert_chain_incomplete"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_cert_chain_incomplete(kind):
    run_fixture(CHECK_ID, kind)

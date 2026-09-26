"""Pruefung spf_authorizes_shared_host: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "spf_authorizes_shared_host"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_spf_authorizes_shared_host(kind):
    run_fixture(CHECK_ID, kind)

"""Pruefung spf_softfail: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "spf_softfail"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_spf_softfail(kind):
    run_fixture(CHECK_ID, kind)

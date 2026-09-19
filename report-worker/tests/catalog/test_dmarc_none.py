"""Pruefung dmarc_none: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "dmarc_none"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_dmarc_none(kind):
    run_fixture(CHECK_ID, kind)

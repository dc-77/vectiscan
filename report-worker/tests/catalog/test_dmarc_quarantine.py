"""Pruefung dmarc_quarantine: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "dmarc_quarantine"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_dmarc_quarantine(kind):
    run_fixture(CHECK_ID, kind)

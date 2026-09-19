"""Pruefung smb_exposed: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "smb_exposed"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_smb_exposed(kind):
    run_fixture(CHECK_ID, kind)

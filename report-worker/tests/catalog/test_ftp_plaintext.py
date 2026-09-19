"""Pruefung ftp_plaintext: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "ftp_plaintext"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_ftp_plaintext(kind):
    run_fixture(CHECK_ID, kind)

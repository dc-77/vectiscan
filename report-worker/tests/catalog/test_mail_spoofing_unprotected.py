"""Pruefung mail_spoofing_unprotected: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "mail_spoofing_unprotected"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_mail_spoofing_unprotected(kind):
    run_fixture(CHECK_ID, kind)

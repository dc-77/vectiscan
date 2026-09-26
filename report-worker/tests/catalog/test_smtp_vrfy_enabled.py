"""Pruefung smtp_vrfy_enabled: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "smtp_vrfy_enabled"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_smtp_vrfy_enabled(kind):
    run_fixture(CHECK_ID, kind)

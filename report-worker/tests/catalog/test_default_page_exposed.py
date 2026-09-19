"""Pruefung default_page_exposed: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "default_page_exposed"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_default_page_exposed(kind):
    run_fixture(CHECK_ID, kind)

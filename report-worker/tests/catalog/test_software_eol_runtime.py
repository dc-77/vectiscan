"""Pruefung software_eol_runtime: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "software_eol_runtime"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_software_eol_runtime(kind):
    run_fixture(CHECK_ID, kind)

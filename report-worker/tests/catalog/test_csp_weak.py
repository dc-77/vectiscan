"""Pruefung csp_weak: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "csp_weak"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_csp_weak(kind):
    run_fixture(CHECK_ID, kind)

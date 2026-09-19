"""Pruefung software_lifecycle_hint: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "software_lifecycle_hint"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_software_lifecycle_hint(kind):
    run_fixture(CHECK_ID, kind)

"""Pruefung dev_host_public: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "dev_host_public"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_dev_host_public(kind):
    run_fixture(CHECK_ID, kind)

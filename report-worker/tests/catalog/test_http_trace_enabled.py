"""Pruefung http_trace_enabled: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "http_trace_enabled"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_http_trace_enabled(kind):
    run_fixture(CHECK_ID, kind)

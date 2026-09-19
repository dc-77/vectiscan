"""Pruefung dns_dangling_cname: ein Test je Fixture (pass, fail, nt, na)."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "dns_dangling_cname"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_dns_dangling_cname(kind):
    run_fixture(CHECK_ID, kind)

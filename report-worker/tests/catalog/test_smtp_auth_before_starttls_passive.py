"""Pruefung smtp_auth_before_starttls_passive: ein Test je Fixture (pass, fail, nt, na).

Fixtures (S6d A4): bergersysteme 92.205.224.174:25 laut Shodan (68d59573) als fail, castenow
195.50.179.4:25 ohne AUTH vor STARTTLS laut Shodan als pass."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "smtp_auth_before_starttls_passive"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_smtp_auth_before_starttls_passive(kind):
    run_fixture(CHECK_ID, kind)

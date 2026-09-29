"""Pruefung smtp_auth_before_starttls: ein Test je Fixture (pass, fail, nt, na).

Fixtures (S6d A4): dortmund-beach 88.99.35.112:587 laut nmap smtp-commands (1fbc92b9, 4394b0b7) als
fail, junkerwerk 188.40.3.130:587 (f9a2a2f6, AUTH erst nach STARTTLS) als pass."""
import pytest

from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "smtp_auth_before_starttls"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_smtp_auth_before_starttls(kind):
    run_fixture(CHECK_ID, kind)

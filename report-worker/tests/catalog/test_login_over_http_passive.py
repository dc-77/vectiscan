import pytest
from tests.catalog.conftest import fixture_kinds, run_fixture

CHECK_ID = "login_over_http_passive"


@pytest.mark.parametrize("kind", fixture_kinds(CHECK_ID))
def test_login_over_http_passive(kind):
    run_fixture(CHECK_ID, kind)

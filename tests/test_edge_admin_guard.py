"""Edge admin-guard regression gate (VEC-160 / VEC-143 / VEC-167 — SICHERHEITSKRITISCH).

Vuln class — *unguarded admin surface via host alias*:
  A `Host(...)` is added to a public Traefik router (e.g. `vectiscan-web`) but
  NOT to the matching `/admin` guard router (`vectiscan-web-admin`). The new host
  then serves `/admin` (or `/api/admin`) WITHOUT the intended auth gate —
  the admin UI/API is reachable from the public internet.

This is exactly the regression VEC-160 introduced and fixed: extending
`vectiscan-web` to `vectiscan.de` + `www.vectiscan.de` without mirroring the
admin guard would have left `https://vectiscan.de/admin` open. VEC-269 brings
this gate onto `main` alongside the live alias rollout.

The admin matcher itself is `PathRegexp((?i)^/admin)` since VEC-167 (case-
insensitive — `/ADMIN` must not bypass the gate). The tests below therefore
accept both `PathPrefix` and `PathRegexp` as the path matcher.

Auth architecture split (VEC-370):
  - Frontend admin (`/admin`):  protected by `internal-auth@file` (HTTP Basic via
    Traefik) — correct for a server-rendered/redirect admin UI.
  - API admin (`/api/admin`):  protected by app-level JWT `requireAdmin` — correct
    for a SPA calling the API via fetch() with Bearer tokens. basicAuth was
    functionally broken here: browsers never attach Basic credentials to XHR/fetch
    calls, causing every real admin API call to receive a 401 from Traefik before
    reaching the app. The `/api/admin` routes are fully covered by
    `admin_edge_invariant.test.ts` and `admin_route_invariant.test.ts` (jest).

These tests are intentionally self-contained (no shared conftest, only stdlib +
PyYAML) so the suite is green today and can gate CI on its own — independent of
the broader, currently-stale `test_docker_compose.py`.

Each tuple: (service, public_router, admin_router, admin_path_prefix, requires_basic_auth)
"""

import re
import yaml
import pytest
from pathlib import Path

COMPOSE_PATH = Path(__file__).parent.parent / "docker-compose.yml"

# requires_basic_auth=True  → internal-auth@file must be present (Frontend admin UI)
# requires_basic_auth=False → internal-auth@file must NOT be present (API; JWT covers it)
ADMIN_GUARD_PAIRS = [
    ("frontend", "vectiscan-web", "vectiscan-web-admin", "/admin", True),
    ("api", "vectiscan-api", "vectiscan-api-admin", "/api/admin", False),
]


@pytest.fixture(scope="module")
def labels_by_service():
    with open(COMPOSE_PATH) as f:
        compose = yaml.safe_load(f)
    out = {}
    for svc, spec in compose["services"].items():
        raw = spec.get("labels", [])
        if isinstance(raw, dict):
            out[svc] = raw
            continue
        d = {}
        for item in raw:
            k, v = item.split("=", 1)
            d[k] = v
        out[svc] = d
    return out


def _hosts_in_rule(rule):
    """Extract every Host(`...`) value from a Traefik router rule."""
    return [m.group(1) for m in re.finditer(r"Host\(`([^`]+)`\)", rule)]


@pytest.mark.parametrize("svc,public_router,admin_router,prefix,_", ADMIN_GUARD_PAIRS)
def test_every_public_host_is_admin_guarded(
    labels_by_service, svc, public_router, admin_router, prefix, _
):
    """Every Host() on the public router must also be on the admin-guard router."""
    labels = labels_by_service[svc]
    public_hosts = set(_hosts_in_rule(labels[f"traefik.http.routers.{public_router}.rule"]))
    admin_hosts = set(_hosts_in_rule(labels[f"traefik.http.routers.{admin_router}.rule"]))

    unguarded = public_hosts - admin_hosts
    assert not unguarded, (
        f"{svc}: host(s) {sorted(unguarded)} are served by '{public_router}' but "
        f"NOT covered by the '{admin_router}' guard → {prefix} would be reachable "
        f"without the admin auth gate."
    )


@pytest.mark.parametrize("svc,public_router,admin_router,prefix,_", ADMIN_GUARD_PAIRS)
def test_admin_rule_group_parenthesized_before_path_matcher(
    labels_by_service, svc, public_router, admin_router, prefix, _
):
    """A multi-host admin rule must be `(Host(..)||..) && Path{Prefix,Regexp}(..)`.

    Without the parentheses, `&&` binds tighter than `||` in Traefik v3, so only
    the LAST host would be restricted to the admin path; the other hosts would
    leave /admin to fall through to the unauthenticated public router.

    A single-host rule (`Host(a) && Path...(..)`, no `||`) is unambiguous and
    needs no parentheses — only enforce grouping once a disjunction exists.
    The path matcher may be PathPrefix or PathRegexp (VEC-167 case-insensitive).
    """
    admin_rule = labels_by_service[svc][f"traefik.http.routers.{admin_router}.rule"]
    if "||" not in admin_rule:
        pytest.skip(f"{svc}: single-host admin rule, no precedence trap to guard")
    assert re.match(r"^\(\s*Host\(.*\)\s*&&\s*Path(Prefix|Regexp)", admin_rule), (
        f"{svc}: multi-host admin rule must wrap the Host group in parentheses "
        f"before '&& PathPrefix/PathRegexp' (operator-precedence trap) — got: {admin_rule}"
    )


@pytest.mark.parametrize("svc,public_router,admin_router,prefix,requires_basic_auth", ADMIN_GUARD_PAIRS)
def test_admin_router_auth_gate(
    labels_by_service, svc, public_router, admin_router, prefix, requires_basic_auth
):
    """Admin guard must use the correct auth mechanism and outrank the public router.

    Auth split (VEC-370):
    - Frontend /admin: Traefik internal-auth@file (HTTP Basic) required.
    - API /api/admin:  internal-auth@file must NOT be present — auth is handled by
      app-level JWT requireAdmin. basicAuth breaks SPA fetch() calls.
      JWT coverage is enforced by admin_edge_invariant.test.ts (jest).
    """
    labels = labels_by_service[svc]
    admin_mw = labels[f"traefik.http.routers.{admin_router}.middlewares"]

    if requires_basic_auth:
        assert "internal-auth@file" in admin_mw, (
            f"{svc}: frontend admin router must enforce internal-auth@file, got '{admin_mw}'"
        )
    else:
        assert "internal-auth@file" not in admin_mw, (
            f"{svc}: API admin router must NOT carry internal-auth@file (breaks SPA Bearer "
            f"auth — VEC-370). JWT requireAdmin coverage is in admin_edge_invariant.test.ts. "
            f"Got: '{admin_mw}'"
        )

    # Admin router must win path resolution for the admin prefix. Traefik's
    # default router priority == rule length; the admin router sets an explicit
    # priority that must exceed the public router's rule length, else the admin
    # path could resolve to the unauthenticated public router.
    public_rule = labels[f"traefik.http.routers.{public_router}.rule"]
    admin_priority = int(labels[f"traefik.http.routers.{admin_router}.priority"])
    assert admin_priority > len(public_rule), (
        f"{svc}: admin router priority ({admin_priority}) must exceed the public "
        f"router's default priority (rule length {len(public_rule)}), else "
        f"{prefix} could resolve to the unauthenticated public router."
    )

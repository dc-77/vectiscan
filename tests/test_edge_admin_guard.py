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

Auth architecture (VEC-370 / VEC-439 / Auth-Konsolidierung Juli 2026):
  Both admin surfaces are guarded by app-level JWT — NOT by a Traefik-level auth gate.
  - Frontend admin (`/admin`):  App-JWT via `useAdminGuard`. The oauth2-proxy/Keycloak
    edge gate (VEC-439 C3) was removed in the July-2026 auth consolidation because it
    forced a second, separate Keycloak login on top of the app login. The `/admin` HTML
    shell is a data-less SPA; real authorization happens in the app + `/api/admin`.
  - API admin (`/api/admin`):  App-JWT `requireAdmin` — correct for a SPA calling the API
    via fetch() with Bearer tokens. Neither basicAuth nor oauth2-proxy forwardAuth may
    appear here: both would intercept SPA fetch() calls before the app can handle them.
  JWT coverage for /api/admin is enforced by `admin_edge_invariant.test.ts` and
  `admin_route_invariant.test.ts` (jest). Keycloak/oauth2-proxy remain only for the
  infra tools (Grafana logs., Uptime-Kuma status.).

These tests are intentionally self-contained (no shared conftest, only stdlib +
PyYAML) so the suite is green today and can gate CI on its own — independent of
the broader, currently-stale `test_docker_compose.py`.

Each tuple: (service, public_router, admin_router, admin_path_prefix, requires_traefik_auth)
"""

import re
import yaml
import pytest
from pathlib import Path

COMPOSE_PATH = Path(__file__).parent.parent / "docker-compose.yml"

# Auth-Konsolidierung (Juli 2026): Das oauth2-proxy-Edge-Gate vor /admin wurde entfernt
# (es erzwang eine zweite, separate Keycloak-Anmeldung ueber dem App-Login). Seitdem tragen
# BEIDE Admin-Router KEIN Traefik-Auth-Gate mehr — die Autorisierung laeuft ausschliesslich
# ueber App-JWT (Frontend: useAdminGuard; API: requireAdmin). Keycloak/oauth2-proxy schuetzen
# nur noch die Infra-Tools (Grafana logs., Uptime-Kuma status.).
# requires_traefik_auth=False → weder oauth2-proxy-redirect@file noch internal-auth@file.
ADMIN_GUARD_PAIRS = [
    ("frontend", "vectiscan-web", "vectiscan-web-admin", "/admin", False),
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


@pytest.mark.parametrize("svc,public_router,admin_router,prefix,requires_traefik_auth", ADMIN_GUARD_PAIRS)
def test_admin_router_auth_gate(
    labels_by_service, svc, public_router, admin_router, prefix, requires_traefik_auth
):
    """Admin routers must NOT carry a Traefik-level auth gate and must outrank the public router.

    Auth-Konsolidierung (Juli 2026): both /admin and /api/admin are guarded by app-level
    JWT (useAdminGuard / requireAdmin), NOT by internal-auth@file or oauth2-proxy-redirect@file.
    A Traefik forwardAuth/basicAuth gate on either would break SPA fetch() (VEC-370) or force
    a second, separate login. The admin router must still exist + outrank the public router so
    /admin resolves to it (own middleware set, e.g. no rate-limit) rather than the public router.
    """
    labels = labels_by_service[svc]
    admin_mw = labels[f"traefik.http.routers.{admin_router}.middlewares"]

    if requires_traefik_auth:
        assert "oauth2-proxy-redirect@file" in admin_mw, (
            f"{svc}: admin router must enforce oauth2-proxy-redirect@file (SSO gate), got '{admin_mw}'"
        )
    else:
        assert "internal-auth@file" not in admin_mw, (
            f"{svc}: admin router must NOT carry internal-auth@file (breaks SPA Bearer auth — "
            f"VEC-370). App-level JWT covers admin auth. Got: '{admin_mw}'"
        )
        assert "oauth2-proxy-redirect@file" not in admin_mw, (
            f"{svc}: admin router must NOT carry oauth2-proxy-redirect@file. Since the July-2026 "
            f"auth consolidation /admin uses app-level JWT (useAdminGuard); a Traefik forwardAuth "
            f"gate would force a second, separate login. Got: '{admin_mw}'"
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

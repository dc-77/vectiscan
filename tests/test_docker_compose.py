"""Tests for production docker-compose.yml."""

import yaml
import pytest
from pathlib import Path

COMPOSE_PATH = Path(__file__).parent.parent / "docker-compose.yml"


@pytest.fixture(scope="module")
def compose():
    with open(COMPOSE_PATH) as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def services(compose):
    return compose["services"]


# --- Service existence ---

EXPECTED_SERVICES = [
    "frontend",
    "api",
    "scan-worker",
    "report-worker",
    "postgres",
    "redis",
    "minio",
]


def test_all_seven_services_defined(services):
    for svc in EXPECTED_SERVICES:
        assert svc in services, f"Service '{svc}' missing from docker-compose.yml"


def test_no_extra_services(services):
    assert set(services.keys()) == set(EXPECTED_SERVICES)


# --- Network assignments ---

PROXY_AND_INTERNAL = {"proxy-net", "vectiscan-internal"}
INTERNAL_ONLY = {"vectiscan-internal"}


@pytest.mark.parametrize("svc", ["frontend", "api"])
def test_external_services_in_both_networks(services, svc):
    nets = set(services[svc]["networks"])
    assert nets == PROXY_AND_INTERNAL, (
        f"{svc} should be in proxy-net + vectiscan-internal, got {nets}"
    )


@pytest.mark.parametrize("svc", ["postgres", "redis", "minio", "scan-worker", "report-worker"])
def test_internal_services_only_in_internal_network(services, svc):
    nets = set(services[svc]["networks"])
    assert nets == INTERNAL_ONLY, (
        f"{svc} should only be in vectiscan-internal, got {nets}"
    )


# --- Network definitions ---

def test_proxy_net_is_external(compose):
    networks = compose["networks"]
    assert "proxy-net" in networks
    assert networks["proxy-net"]["external"] is True


def test_vectiscan_internal_exists(compose):
    assert "vectiscan-internal" in compose["networks"]


# --- Traefik labels ---

def test_frontend_traefik_labels(services):
    labels = services["frontend"]["labels"]
    if isinstance(labels, list):
        labels_dict = {}
        for item in labels:
            k, v = item.split("=", 1)
            labels_dict[k] = v
        labels = labels_dict

    assert labels["traefik.enable"] in (True, "true")
    assert "scan.vectigal.tech" in labels["traefik.http.routers.vectiscan-web.rule"]
    assert "internal-only@file" in labels[
        "traefik.http.routers.vectiscan-web.middlewares"
    ]
    assert labels["traefik.http.services.vectiscan-web.loadbalancer.server.port"] in (
        3000,
        "3000",
    )


def test_api_traefik_labels(services):
    labels = services["api"]["labels"]
    if isinstance(labels, list):
        labels_dict = {}
        for item in labels:
            k, v = item.split("=", 1)
            labels_dict[k] = v
        labels = labels_dict

    assert labels["traefik.enable"] in (True, "true")
    assert "scan-api.vectigal.tech" in labels["traefik.http.routers.vectiscan-api.rule"]
    assert "internal-only@file" in labels[
        "traefik.http.routers.vectiscan-api.middlewares"
    ]
    assert labels["traefik.http.services.vectiscan-api.loadbalancer.server.port"] in (
        4000,
        "4000",
    )
    assert (
        labels["traefik.http.services.vectiscan-api.loadbalancer.healthcheck.path"]
        == "/health"
    )


def test_no_certresolver_labels(services):
    """No certresolver labels — LE HTTP-01 is Traefik default."""
    for svc_name in ["frontend", "api"]:
        labels = services[svc_name].get("labels", {})
        if isinstance(labels, list):
            combined = " ".join(labels)
        else:
            combined = " ".join(str(v) for v in labels.values())
        assert "certresolver" not in combined.lower(), (
            f"{svc_name} should not have certresolver labels"
        )


# --- Resource limits ---

EXPECTED_LIMITS = {
    "frontend": {"cpus": "1", "memory": "512M"},
    "api": {"cpus": "1", "memory": "512M"},
    "scan-worker": {"cpus": "2", "memory": "2G"},
    "report-worker": {"cpus": "1", "memory": "1G"},
    "postgres": {"cpus": "1", "memory": "1G"},
    "redis": {"cpus": "0.5", "memory": "512M"},
    "minio": {"cpus": "0.5", "memory": "512M"},
}


@pytest.mark.parametrize("svc", EXPECTED_SERVICES)
def test_resource_limits_set(services, svc):
    deploy = services[svc].get("deploy", {})
    limits = deploy.get("resources", {}).get("limits", {})
    expected = EXPECTED_LIMITS[svc]
    assert str(limits.get("cpus", "")) == expected["cpus"], (
        f"{svc} cpus should be {expected['cpus']}"
    )
    assert limits.get("memory") == expected["memory"], (
        f"{svc} memory should be {expected['memory']}"
    )


# --- Healthchecks ---

def test_api_healthcheck(services):
    hc = services["api"]["healthcheck"]
    test_cmd = hc["test"]
    if isinstance(test_cmd, list):
        test_cmd = " ".join(test_cmd)
    assert "/health" in test_cmd


def test_postgres_healthcheck(services):
    hc = services["postgres"]["healthcheck"]
    test_cmd = hc["test"]
    if isinstance(test_cmd, list):
        test_cmd = " ".join(test_cmd)
    assert "pg_isready" in test_cmd


# --- Volumes ---

def test_named_volumes_defined(compose):
    volumes = compose.get("volumes", {})
    for vol in ["vectiscan-pg-data", "vectiscan-redis-data", "vectiscan-minio-data"]:
        assert vol in volumes, f"Volume '{vol}' not defined"


# --- Images ---

REGISTRY = "git-extern.bergersysteme.com:5050/team/vectiscan"


@pytest.mark.parametrize(
    "svc,name",
    [
        ("frontend", "frontend"),
        ("api", "api"),
        ("scan-worker", "scan-worker"),
        ("report-worker", "report-worker"),
    ],
)
def test_service_uses_registry_image(services, svc, name):
    image = services[svc]["image"]
    assert REGISTRY in image, f"{svc} image should reference registry"
    assert name in image


# --- depends_on ---

def test_api_depends_on_postgres_healthy(services):
    deps = services["api"]["depends_on"]
    assert "postgres" in deps
    if isinstance(deps, dict):
        assert deps["postgres"]["condition"] == "service_healthy"


def test_api_depends_on_redis(services):
    deps = services["api"]["depends_on"]
    assert "redis" in deps


def test_scan_worker_depends_on(services):
    deps = services["scan-worker"]["depends_on"]
    assert "redis" in deps
    assert "minio" in deps


def test_report_worker_depends_on(services):
    deps = services["report-worker"]["depends_on"]
    assert "redis" in deps
    assert "minio" in deps
    assert "postgres" in deps

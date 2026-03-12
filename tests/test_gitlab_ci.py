"""Tests for .gitlab-ci.yml pipeline configuration."""

import yaml
import pytest
from pathlib import Path

CI_PATH = Path(__file__).parent.parent / ".gitlab-ci.yml"


@pytest.fixture(scope="module")
def ci():
    with open(CI_PATH) as f:
        return yaml.safe_load(f)


# --- Stages ---

def test_stages_defined(ci):
    assert ci["stages"] == ["build", "scan", "test", "deploy"]


# --- Variables ---

def test_registry_variable(ci):
    variables = ci["variables"]
    assert variables["REGISTRY"] == "git-extern.bergersysteme.com:5050"


def test_base_image_variable(ci):
    variables = ci["variables"]
    assert "${REGISTRY}" in variables["BASE_IMAGE"]
    assert "${CI_PROJECT_PATH}" in variables["BASE_IMAGE"]


def test_app_name_variable(ci):
    assert ci["variables"]["APP_NAME"] == "vectiscan"


def test_deploy_path_variable(ci):
    assert "${APP_NAME}" in ci["variables"]["DEPLOY_PATH"] or "vectiscan" in ci["variables"]["DEPLOY_PATH"]


# --- Build jobs ---

BUILD_JOBS = ["build-frontend", "build-api", "build-scan-worker", "build-report-worker"]


@pytest.mark.parametrize("job", BUILD_JOBS)
def test_build_job_exists(ci, job):
    assert job in ci, f"Build job '{job}' missing"


@pytest.mark.parametrize("job", BUILD_JOBS)
def test_build_job_stage(ci, job):
    stage = ci[job].get("stage", ci.get(".build-base", {}).get("stage"))
    assert stage == "build"


@pytest.mark.parametrize("job", BUILD_JOBS)
def test_build_job_has_vectigal_tag(ci, job):
    tags = ci[job].get("tags") or ci.get(".build-base", {}).get("tags", [])
    assert "vectigal" in tags


@pytest.mark.parametrize(
    "job,service",
    [
        ("build-frontend", "frontend"),
        ("build-api", "api"),
        ("build-scan-worker", "scan-worker"),
        ("build-report-worker", "report-worker"),
    ],
)
def test_build_job_builds_correct_service(ci, job, service):
    """Build job script or variables should reference the correct Dockerfile."""
    job_cfg = ci[job]
    # Check in variables or script
    variables = job_cfg.get("variables", {})
    script = " ".join(job_cfg.get("script", []))

    # Service could be in a SERVICE variable or directly in the script
    has_service_ref = (
        variables.get("SERVICE") == service
        or f"{service}/Dockerfile" in script
        or f"/{service}:" in script
    )
    assert has_service_ref, f"{job} should reference {service}"


# --- Trivy scan jobs ---

TRIVY_JOBS = ["trivy-frontend", "trivy-api", "trivy-scan-worker", "trivy-report-worker"]


@pytest.mark.parametrize("job", TRIVY_JOBS)
def test_trivy_job_exists(ci, job):
    assert job in ci, f"Trivy job '{job}' missing"


@pytest.mark.parametrize("job", TRIVY_JOBS)
def test_trivy_job_stage(ci, job):
    stage = ci[job].get("stage", ci.get(".trivy-base", {}).get("stage"))
    assert stage == "scan"


@pytest.mark.parametrize("job", TRIVY_JOBS)
def test_trivy_job_exit_code(ci, job):
    """Trivy should use --exit-code 1 to fail on findings."""
    job_cfg = ci[job]
    script = " ".join(job_cfg.get("script", []))
    base_script = " ".join(ci.get(".trivy-base", {}).get("script", []))
    combined = script + " " + base_script
    assert "--exit-code 1" in combined or "--exit-code=1" in combined


@pytest.mark.parametrize("job", TRIVY_JOBS)
def test_trivy_severity_critical(ci, job):
    job_cfg = ci[job]
    script = " ".join(job_cfg.get("script", []))
    base_script = " ".join(ci.get(".trivy-base", {}).get("script", []))
    combined = script + " " + base_script
    assert "CRITICAL" in combined


# --- Test jobs ---

TEST_JOBS = ["test-api", "test-scan-worker", "test-report-worker"]


@pytest.mark.parametrize("job", TEST_JOBS)
def test_test_job_exists(ci, job):
    assert job in ci, f"Test job '{job}' missing"


@pytest.mark.parametrize("job", TEST_JOBS)
def test_test_job_stage(ci, job):
    stage = ci[job].get("stage", ci.get(".test-base", {}).get("stage"))
    assert stage == "test"


def test_test_api_runs_npm_test(ci):
    script = " ".join(ci["test-api"].get("script", []))
    assert "npm test" in script


def test_test_scan_worker_runs_pytest(ci):
    script = " ".join(ci["test-scan-worker"].get("script", []))
    assert "pytest" in script


def test_test_report_worker_runs_pytest(ci):
    script = " ".join(ci["test-report-worker"].get("script", []))
    assert "pytest" in script


# --- Deploy jobs ---

DEPLOY_JOBS = ["deploy-auto", "deploy-manual"]


@pytest.mark.parametrize("job", DEPLOY_JOBS)
def test_deploy_job_exists(ci, job):
    assert job in ci, f"Deploy job '{job}' missing"


@pytest.mark.parametrize("job", DEPLOY_JOBS)
def test_deploy_job_stage(ci, job):
    stage = ci[job].get("stage", ci.get(".deploy-base", {}).get("stage"))
    assert stage == "deploy"


def test_deploy_manual_is_manual(ci):
    job = ci["deploy-manual"]
    rules = job.get("rules", [])
    has_manual = any(r.get("when") == "manual" for r in rules)
    assert has_manual, "deploy-manual should have when: manual"


def test_deploy_auto_environment_url(ci):
    job = ci["deploy-auto"]
    env = job.get("environment", ci.get(".deploy-base", {}).get("environment", {}))
    assert env.get("url") == "https://scan.vectigal.tech"


# --- Rollback job ---

def test_rollback_job_exists(ci):
    assert "rollback" in ci, "Rollback job missing"


def test_rollback_is_manual(ci):
    job = ci["rollback"]
    assert job.get("when") == "manual" or any(
        r.get("when") == "manual" for r in job.get("rules", [])
    )


def test_rollback_restores_backup(ci):
    job = ci["rollback"]
    script = " ".join(job.get("script", []))
    assert "docker-compose.yml.bak" in script
    assert ".env.bak" in script

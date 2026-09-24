"""Alle Abbilder kommen aus der eigenen Registry, Fremdabbilder per Digest.

Entscheidung DC (24.09.2026, S6a2): Am 24.09. lieferte quay.io minio/minio nur
noch mit Anmeldung (401), und das pauschale `docker compose pull` riss den Deploy
mit (Pipeline 3181). Seitdem gilt:

- Jedes Abbild in den Compose-Dateien liegt unter ghcr.io/dc-77/vectiscan/.
- Fremdabbilder sind dorthin gespiegelt (scripts/ops/mirror-images.sh, Job
  ops-mirror-images) und per Digest gepinnt; ein Tag allein kann sich aendern.
- Deploy und Rollback ziehen nur ueber scripts/ops/pull-own-images.sh, nie
  pauschal und nie mit --ignore-pull-failures.

Laeuft im CI-Job test-edge (pyyaml, pytest).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "ghcr.io/dc-77/vectiscan/"
OWN = ("frontend", "api", "scan-worker", "report-worker")
COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.dev.yml",
    "scan-worker/tests/integration/docker-compose.zap-it.yml",
)
PINNED_RE = re.compile(r"^ghcr\.io/dc-77/vectiscan/([a-z0-9._-]+):([A-Za-z0-9._-]+)@sha256:[0-9a-f]{64}$")
OWN_RE = re.compile(r"^ghcr\.io/dc-77/vectiscan/(frontend|api|scan-worker|report-worker):\$\{TAG:-latest\}$")


def _images() -> list[tuple[str, str, str]]:
    out = []
    for rel in COMPOSE_FILES:
        data = yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))
        for name, service in (data.get("services") or {}).items():
            if isinstance(service, dict) and service.get("image"):
                out.append((rel, name, str(service["image"])))
    return out


IMAGES = _images()


def _id(case: tuple[str, str, str]) -> str:
    return f"{case[0]}:{case[1]}"


def _mirror_targets() -> set[str]:
    text = (ROOT / "scripts" / "ops" / "mirror-images.sh").read_text(encoding="utf-8")
    block = text.split('MIRRORS="', 1)[1].split('"', 1)[0]
    return {line.split("|", 1)[1].strip() for line in block.splitlines() if "|" in line}


def test_compose_dateien_haben_abbilder():
    assert len(IMAGES) > 20


@pytest.mark.parametrize("case", IMAGES, ids=_id)
def test_abbild_aus_der_eigenen_registry(case):
    rel, name, image = case
    assert image.startswith(PREFIX), f"{rel} {name}: {image} liegt nicht unter {PREFIX}"


@pytest.mark.parametrize("case", IMAGES, ids=_id)
def test_fremdabbild_per_digest_gepinnt_und_gespiegelt(case):
    rel, name, image = case
    if OWN_RE.match(image):
        return
    m = PINNED_RE.match(image)
    assert m, f"{rel} {name}: {image} ist weder eigenes Abbild mit TAG noch per Digest gepinnt"
    assert m.group(1) not in OWN, f"{rel} {name}: eigenes Abbild darf nicht per Digest stehen"
    assert f"{m.group(1)}:{m.group(2)}" in _mirror_targets(), (
        f"{rel} {name}: {m.group(1)}:{m.group(2)} fehlt in scripts/ops/mirror-images.sh")


def test_gleiches_abbild_gleicher_digest():
    """Ein Name mit Tag hat in allen Dateien denselben Digest."""
    seen: dict[str, str] = {}
    for rel, name, image in IMAGES:
        if "@sha256:" not in image:
            continue
        ref, digest = image.split("@", 1)
        assert seen.setdefault(ref, digest) == digest, f"{rel} {name}: {ref} mit abweichendem Digest"


def _ci() -> dict:
    return yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8"))


@pytest.mark.parametrize("job", [".deploy-base", "rollback"])
def test_deploy_und_rollback_ziehen_nur_eigene_abbilder(job):
    script = [str(line) for line in _ci()[job]["script"]]
    assert not any("docker compose pull" in line for line in script), (
        f"{job}: pauschales `docker compose pull`; nur ueber scripts/ops/pull-own-images.sh")
    assert any("scripts/ops/pull-own-images.sh" in line for line in script), job


def test_nirgends_ignore_pull_failures():
    ci = (ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
    skript = (ROOT / "scripts" / "ops" / "pull-own-images.sh").read_text(encoding="utf-8")
    code = [line for line in (ci + "\n" + skript).splitlines() if not line.strip().startswith("#")]
    assert not any("--ignore-pull-failures" in line for line in code)

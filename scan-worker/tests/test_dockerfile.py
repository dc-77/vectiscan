"""Tests for scan-worker Dockerfile correctness."""

from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"

EXPECTED_TOOLS: dict[str, str] = {
    "nmap": "nmap",
    "nuclei": "nuclei",
    "subfinder": "subfinder",
    "dnsx": "dnsx",
    "gobuster": "gobuster",
    "gowitness": "gowitness",
    # amass entfernt (F-P0B-003, 2026-05-07).
    "testssl.sh": "testssl.sh",
    "nikto": "nikto",
    "wafw00f": "wafw00f",
    "webtech": "webtech",
}


def _read_dockerfile() -> str:
    assert DOCKERFILE.exists(), f"Dockerfile not found at {DOCKERFILE}"
    return DOCKERFILE.read_text()


def test_dockerfile_syntax() -> None:
    """Dockerfile must start with FROM and contain required directives."""
    content = _read_dockerfile()
    lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]

    assert lines[0].startswith("FROM "), "Dockerfile must start with a FROM instruction"
    assert "debian:bookworm-slim" in lines[0], "Base image must be debian:bookworm-slim"

    directives_found = {d for l in lines for d in ("RUN", "COPY", "USER", "ENTRYPOINT", "WORKDIR") if l.startswith(d)}
    assert "RUN" in directives_found, "Dockerfile must contain RUN instructions"
    assert "COPY" in directives_found, "Dockerfile must contain COPY instructions"
    assert "USER" in directives_found, "Dockerfile must set a USER"
    assert "ENTRYPOINT" in directives_found, "Dockerfile must define an ENTRYPOINT"
    assert "WORKDIR" in directives_found, "Dockerfile must set WORKDIR"


def test_non_root_user() -> None:
    """Dockerfile must create and switch to a non-root user."""
    content = _read_dockerfile()
    assert "useradd" in content, "Dockerfile must create a non-root user"
    assert "USER scanner" in content, "Dockerfile must switch to scanner user"


def test_expected_tools_referenced() -> None:
    """All expected scan tool binaries must be referenced in the Dockerfile."""
    content = _read_dockerfile()
    missing = [name for name, ref in EXPECTED_TOOLS.items() if ref not in content]
    assert not missing, f"Tools not referenced in Dockerfile: {missing}"


def test_wordlists() -> None:
    """Dockerfile must download required wordlists."""
    content = _read_dockerfile()
    assert "subdomains-top5000.txt" in content
    assert "common.txt" in content


def test_every_referenced_wordlist_is_in_image() -> None:
    """S0a: jede von den Scan-Phasen erwartete Wordlist muss im Image landen.

    F-PH2-001 stellte phase2 auf raft-small-files.txt um, das Dockerfile blieb
    auf raft-medium-files.txt. ffuf_sensitive wurde dadurch in 42 Produktions-
    scans stillschweigend uebersprungen. Dieser Test haette das gefangen.
    """
    from scanner.preflight import REQUIRED_WORDLISTS

    content = _read_dockerfile()
    missing = sorted(
        f"{name} -> {path}"
        for name, path in REQUIRED_WORDLISTS.items()
        if path not in content
    )
    assert not missing, (
        "Wordlist wird im Code referenziert, aber nicht ins Image gelegt: "
        + "; ".join(missing)
    )


def test_entrypoint() -> None:
    """Entrypoint must invoke scanner module via python3."""
    content = _read_dockerfile()
    assert '"-m", "scanner"' in content
    assert "python3" in content

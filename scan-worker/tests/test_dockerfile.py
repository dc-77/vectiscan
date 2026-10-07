"""Tests for scan-worker Dockerfile correctness."""

import re
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"

EXPECTED_TOOLS: dict[str, str] = {
    "nmap": "nmap",
    "subfinder": "subfinder",
    "dnsx": "dnsx",
    "gobuster": "gobuster",
    "httpx": "httpx",
    "ffuf": "ffuf",
    "feroxbuster": "feroxbuster",
    # amass entfernt (F-P0B-003, 2026-05-07).
    # nuclei, dalfox, gowitness, katana entfernt (07.10.2026), siehe
    # test_removed_tools_stay_out.
    "testssl.sh": "testssl.sh",
    "nikto": "nikto",
    "wafw00f": "wafw00f",
    "webtech": "webtech",
}

# Am 07.10.2026 aus dem Image genommen: keine Scan-Phase rief sie noch auf,
# ihre Binaries brachten aber kritische Trivy-Befunde mit.
REMOVED_TOOLS = ("nuclei", "dalfox", "gowitness", "katana")

# Werden in der Stufe gotools mit aktuellem Go gebaut. Ein Release-Download
# braechte die alte Go-Laufzeit und damit CVE-2025-68121 zurueck.
GO_BUILT_TOOLS = ("subfinder", "dnsx", "gobuster", "httpx", "ffuf")


def _read_dockerfile() -> str:
    assert DOCKERFILE.exists(), f"Dockerfile not found at {DOCKERFILE}"
    return DOCKERFILE.read_text()


INSTRUCTIONS = {
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV", "ADD", "COPY",
    "ENTRYPOINT", "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL",
    "HEALTHCHECK", "SHELL",
}


def _instruction_starts(content: str) -> list[tuple[int, str]]:
    """(Zeilennummer, Zeile) je Zeile, die eine neue Instruktion beginnt.

    Fortsetzungszeilen (vorige Zeile endet auf Backslash) und Kommentare
    zaehlen nicht. Docker entfernt Kommentarzeilen innerhalb einer
    Fortsetzung, ohne die Fortsetzung zu beenden -- das bildet der Parser
    hier nach.
    """
    starts: list[tuple[int, str]] = []
    continuing = False
    for no, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not continuing:
            starts.append((no, line))
        continuing = line.endswith("\\")
    return starts


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


def test_no_orphaned_continuation_lines() -> None:
    """Jede Instruktionszeile muss mit einem Dockerfile-Schluesselwort beginnen.

    S0a: Beim Anhaengen einer `&& test -s ...`-Zeile an einen RUN-Block fehlte
    der Continuation-Backslash der Vorzeile. Das Ergebnis war
    `dockerfile parse error: unknown instruction: &&` -- gefunden erst im
    CI-Build, also 15 Minuten spaeter. Dieser Test findet es in einer Sekunde.
    """
    bad = [
        f"Zeile {no}: {line[:70]}"
        for no, line in _instruction_starts(_read_dockerfile())
        if line.split(None, 1)[0].upper() not in INSTRUCTIONS
    ]
    assert not bad, (
        "Zeile beginnt keine gueltige Instruktion -- fehlt in der Vorzeile ein "
        "Backslash? " + "; ".join(bad)
    )


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


def test_removed_tools_stay_out() -> None:
    """Entfernte Werkzeuge: nicht installiert und von keinem Paket verlangt.

    07.10.2026: nuclei, dalfox, gowitness und katana lagen im Image, ohne dass
    eine Scan-Phase sie aufrief, und brachten 7 von 13 kritischen
    Trivy-Befunden mit. Wer eines davon wieder braucht, nimmt es hier und in
    REMOVED_TOOLS bewusst heraus und baut es wie die anderen in gotools.
    """
    from scanner.packages import PACKAGE_CONFIG

    installs = [
        line.strip() for line in _read_dockerfile().splitlines()
        if not line.strip().startswith("#")
        and any(tool in line for tool in REMOVED_TOOLS)
    ]
    assert not installs, f"Entferntes Werkzeug wieder im Dockerfile: {installs}"

    wanted = sorted(
        f"{package}.{key}: {tool}"
        for package, config in PACKAGE_CONFIG.items()
        for key, tools in config.items()
        if key.endswith("_tools") and isinstance(tools, list)
        for tool in tools
        if tool in REMOVED_TOOLS
    )
    assert not wanted, f"Paket verlangt ein Werkzeug, das nicht im Image ist: {wanted}"


def test_go_tools_built_with_current_go() -> None:
    """Go-Werkzeuge kommen aus der Stufe gotools, nicht als Release-Download."""
    content = _read_dockerfile()
    assert "FROM debian:bookworm-slim AS gotools" in content
    assert re.search(r"^ARG GO_SHA256=[0-9a-f]{64}$", content, re.M), \
        "Go-Archiv ohne feste Pruefsumme"
    for tool in GO_BUILT_TOOLS:
        assert f"/{tool}/releases/download" not in content, \
            f"{tool} kommt wieder als Release, damit mit alter Go-Laufzeit"
        assert re.search(rf"go install .*github\.com/\S*{tool}\S*@v", content), \
            f"{tool} wird in gotools nicht mit fester Version gebaut"
        assert f"/out/{tool}" in content, f"{tool} wird nicht aus gotools kopiert"

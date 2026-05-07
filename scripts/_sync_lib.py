"""Helper-Library fuer Sync-Skripte (EOL-Daten, Threat-Intel, etc.).

Bietet wiederverwendbare Bausteine:
- `fetch_with_retry`           — HTTP GET mit Exponential-Backoff
- `atomic_write_python_module` — atomar geschriebene generierte Python-Module
- `has_git_changes`            — `git diff --quiet`-Check fuer eine Datei
- `commit_and_push_if_changed` — Commit + Push (CI-Bot-Identity, Token via ENV)
- `validate_min_entries`       — Sanity-Check (Datenquelle nicht leer)

Verwendet ausschliesslich die Stdlib (urllib, subprocess, json, os, ...) —
keine externen Dependencies, damit der CI-Job ohne `pip install` laeuft.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


class SyncValidationError(Exception):
    """Raised wenn die gefetchte Datenquelle Sanity-Checks nicht besteht."""


# ─────────────────────────────────────────────────────────────────────────────
# HTTP
# ─────────────────────────────────────────────────────────────────────────────

def fetch_with_retry(
    url: str,
    *,
    retries: int = 3,
    timeout: int = 30,
    headers: dict | None = None,
    backoff_base: float = 2.0,
) -> str:
    """HTTP GET mit Exponential-Backoff.

    Args:
        url: Vollstaendige URL.
        retries: Anzahl Versuche (gesamt, inkl. erstem). >=1.
        timeout: Sekunden pro Versuch.
        headers: Optional zusaetzliche Headers.
        backoff_base: Basis fuer den Exponential-Backoff
            (sleep = backoff_base ** attempt).

    Returns:
        Response body als UTF-8-Decoded-String.

    Raises:
        urllib.error.URLError / HTTPError nach Erschoepfung der Retries
        (urspruengliche Exception wird re-raised).
    """
    if retries < 1:
        raise ValueError("retries must be >= 1")

    last_exc: BaseException | None = None
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            last_exc = exc
            # 4xx (ausser 408/429) sind keine transienten Fehler
            if exc.code < 500 and exc.code not in (408, 429):
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_exc = exc

        if attempt < retries - 1:
            sleep_for = backoff_base ** attempt
            time.sleep(sleep_for)

    # Alle Versuche fehlgeschlagen
    assert last_exc is not None
    raise last_exc


# ─────────────────────────────────────────────────────────────────────────────
# Atomic File-Write
# ─────────────────────────────────────────────────────────────────────────────

def _format_dict_value(value: object) -> str:
    """JSON-konforme Repraesentation eines dict-Values, kompatibel zu Python-Literals.

    Verwendet json.dumps(ensure_ascii=False) — passt zum bisherigen
    Format von sync-eol-data.py.
    """
    return json.dumps(value, ensure_ascii=False)


def atomic_write_python_module(
    target_path: Path,
    *,
    header: str,
    data_name: str,
    data_dict: dict,
    dict_type_hint: str,
) -> None:
    """Schreibt ein generiertes Python-Modul atomar.

    Format (bleibt byte-identisch zum bisherigen sync-eol-data.py-Output):
        <header (Docstring inkl. trailing newline)>
        from __future__ import annotations

        # <comment line>
        <data_name>: <dict_type_hint> = {
            (...key...): {sortierte items},
            ...
        }

    Args:
        target_path: Ziel-Datei (wird ueberschrieben).
        header: Modul-Docstring (`\"\"\"...\"\"\"`-Block) inkl. trailing newline.
            Wird wortwoertlich an den Anfang gestellt. Kein leading newline.
        data_name: Name der Modul-Variable (z.B. "EOL_DATA_GENERATED").
        data_dict: Dict mit beliebigen JSON-serialisierbaren Values.
            Keys werden alphabetisch sortiert (durch sorted()).
        dict_type_hint: Annotation, z.B. "dict[tuple[str, str, str], dict]".

    Atomic: schreibt erst in eine Temp-Datei im selben Verzeichnis und
    nutzt dann `os.replace` — kein partieller File-Zustand bei Crash.
    """
    target_path = Path(target_path)
    parent = target_path.parent
    parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    lines.append(header)
    lines.append("\n")
    lines.append("from __future__ import annotations\n")
    lines.append("\n")
    lines.append("# (vendor, product, version_prefix) -> info dict\n")
    lines.append(f"{data_name}: {dict_type_hint} = {{\n")

    for key in sorted(data_dict.keys()):
        info = data_dict[key]
        if isinstance(info, dict):
            info_repr = ", ".join(
                f'"{k}": {_format_dict_value(v)}'
                for k, v in sorted(info.items())
            )
            value_str = "{" + info_repr + "}"
        else:
            value_str = _format_dict_value(info)

        # Key-Repraesentation: tuple/str/int → JSON-konform
        if isinstance(key, tuple):
            key_str = "(" + ", ".join(_format_dict_value(k) for k in key) + ")"
        else:
            key_str = _format_dict_value(key)

        lines.append(f"    {key_str}: {value_str},\n")

    lines.append("}\n")

    body = "".join(lines)

    # Atomic write: Temp im selben Verzeichnis (gleicher Filesystem-Mount)
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{target_path.name}.",
        suffix=".tmp",
        dir=str(parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(body)
        os.replace(tmp_path, str(target_path))
    except BaseException:
        # Aufraeumen wenn replace fehlschlug
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ─────────────────────────────────────────────────────────────────────────────
# Git Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    """Wrapper um git ohne shell."""
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )


def has_git_changes(path: Path, repo_root: Path | None = None) -> bool:
    """True wenn `git diff --quiet -- <path>` Aenderungen sieht.

    Beruecksichtigt sowohl Working-Tree- als auch Staged-Aenderungen.
    Returns False bei einem unbekannten Pfad (kein Tracking, keine Aenderung).
    """
    path = Path(path).resolve()
    root = (repo_root or path.parent).resolve()
    # Pfad relativ zu repo_root fuer git
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path  # absolut belassen — git wird das auch annehmen

    # `git diff --quiet` exit-code 0 = keine Diffs, 1 = Diffs
    proc_unstaged = subprocess.run(
        ["git", "diff", "--quiet", "--", str(rel)],
        cwd=str(root),
        capture_output=True,
        text=True,
        shell=False,
    )
    proc_staged = subprocess.run(
        ["git", "diff", "--cached", "--quiet", "--", str(rel)],
        cwd=str(root),
        capture_output=True,
        text=True,
        shell=False,
    )
    # Auch untracked Files zaehlen als "changes"
    proc_status = subprocess.run(
        ["git", "status", "--porcelain", "--", str(rel)],
        cwd=str(root),
        capture_output=True,
        text=True,
        shell=False,
    )
    has_untracked = bool(proc_status.stdout.strip())
    return (
        proc_unstaged.returncode == 1
        or proc_staged.returncode == 1
        or has_untracked
    )


def commit_and_push_if_changed(
    path: Path,
    *,
    commit_message: str,
    bot_email: str = "ci-bot@vectiscan.local",
    bot_name: str = "VectiScan CI Bot",
    push_token_env: str = "CI_PUSH_TOKEN",
) -> bool:
    """Commit + push wenn sich `path` geaendert hat.

    Args:
        path: Datei, die committed werden soll.
        commit_message: Git-Commit-Message.
        bot_email / bot_name: Identity fuer den Commit.
        push_token_env: ENV-Variable mit Push-Token (oauth2-Token mit
            write_repo-Scope). Wenn unset: Commit aber kein Push.

    Returns:
        True wenn ein Push erfolgreich war,
        False wenn keine Aenderungen oder kein Push-Token gesetzt.
    """
    path = Path(path).resolve()
    # repo-root ueber `git rev-parse --show-toplevel` (sucht nach oben)
    proc = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=str(path.parent),
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    repo_root = Path(proc.stdout.strip())

    if not has_git_changes(path, repo_root=repo_root):
        print(f"[INFO] keine Aenderungen an {path.name} — nichts zu committen.",
              file=sys.stderr)
        return False

    # Identity setzen (lokal, nicht global)
    _run_git(["config", "user.email", bot_email], repo_root)
    _run_git(["config", "user.name", bot_name], repo_root)

    rel = path.relative_to(repo_root)
    _run_git(["add", str(rel)], repo_root)
    _run_git(["commit", "-m", commit_message], repo_root)

    token = os.environ.get(push_token_env)
    if not token:
        print(f"[WARN] {push_token_env} nicht gesetzt — Commit lokal, kein Push.",
              file=sys.stderr)
        return False

    server_host = os.environ.get("CI_SERVER_HOST")
    project_path = os.environ.get("CI_PROJECT_PATH")
    if not (server_host and project_path):
        print("[WARN] CI_SERVER_HOST oder CI_PROJECT_PATH nicht gesetzt — kein Push.",
              file=sys.stderr)
        return False

    push_url = f"https://oauth2:{token}@{server_host}/{project_path}.git"
    # Branch aus CI_COMMIT_REF_NAME oder fallback main
    target_ref = os.environ.get("CI_COMMIT_REF_NAME") or "main"
    _run_git(["push", push_url, f"HEAD:{target_ref}"], repo_root)
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Sanity Checks
# ─────────────────────────────────────────────────────────────────────────────

def validate_min_entries(
    data: dict | list,
    *,
    min_count: int,
    source_name: str,
) -> None:
    """Wirft SyncValidationError wenn `data` weniger als min_count Elemente hat.

    Schuetzt vor "leerer Sync" (Quelle down → Generated-File wird leer →
    Loader liefert keine EOL-Findings mehr).
    """
    actual = len(data)
    if actual < min_count:
        raise SyncValidationError(
            f"{source_name}: nur {actual} Eintraege gefetched "
            f"(erwartet >= {min_count}). Vermutlich Quell-Datenpanne."
        )

#!/usr/bin/env python3
"""CLI-Wrapper um `_sync_lib.commit_and_push_if_changed`.

Aufruf (im GitLab-Job):
    python3 scripts/_sync_commit.py <generated_file_path> [--message "..."]

Default-Message: ``chore(sync): refresh {filename} [skip ci]``.
Push erfolgt via Token aus ENV ``CI_PUSH_TOKEN`` (siehe `_sync_lib`).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from _sync_lib import commit_and_push_if_changed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", help="Pfad zur (potentiell aktualisierten) Datei")
    ap.add_argument("--message", "-m", default=None,
                    help="Commit-Message (Default: chore(sync)-Template)")
    args = ap.parse_args()

    path = Path(args.path)
    msg = args.message or f"chore(sync): refresh {path.name} [skip ci]"

    pushed = commit_and_push_if_changed(path, commit_message=msg)
    if pushed:
        print(f"[OK] {path.name} committed + pushed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

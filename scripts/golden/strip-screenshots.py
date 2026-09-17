#!/usr/bin/env python3
"""Screenshots aus einem Roh-Tar entfernen und deterministisch neu packen.

spec/07 Abschnitt 1: Junkerwerk-Rohdaten duerfen als Golden-Fixture ins Repo,
Screenshots nicht. Das gilt hier fuer alle Fixtures. Entfernt werden alle
Bilddateien; im Tar sind das ausschliesslich Aufnahmen von Weboberflaechen
(hosts/*/phase*/screenshot_*.png, phase2/screenshots/*, phase2/gowitness/
screenshots/*).

Deterministisch heisst: Mitglieder sortiert, Besitzer und Namen genullt,
gzip ohne Zeitstempel. Zwei Laeufe ueber dasselbe Eingabe-Tar liefern
byteidentische Ausgaben, damit ein erneuter Export keinen Diff erzeugt.

Aufruf (gibt die Zahl der entfernten Bilder auf stdout aus):
    python3 strip-screenshots.py <eingabe.tar.gz> <ausgabe.tar.gz>
"""

from __future__ import annotations

import gzip
import sys
import tarfile
from pathlib import Path

IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff")


def strip(src: Path, dest: Path) -> int:
    removed = 0
    with tarfile.open(src, "r:gz") as source:
        members = sorted(source.getmembers(), key=lambda m: m.name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        # gzip mit mtime=0, damit das Ergebnis reproduzierbar ist.
        with gzip.GzipFile(filename="", mode="wb", fileobj=dest.open("wb"), mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as target:
                for member in members:
                    if member.name.lower().endswith(IMAGE_SUFFIXES):
                        removed += 1
                        continue
                    member.uid = 0
                    member.gid = 0
                    member.uname = ""
                    member.gname = ""
                    if member.isfile():
                        extracted = source.extractfile(member)
                        target.addfile(member, extracted)
                    else:
                        target.addfile(member)
    return removed


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, dest = Path(argv[1]), Path(argv[2])
    if not src.is_file():
        print(f"Eingabe fehlt: {src}", file=sys.stderr)
        return 2
    print(strip(src, dest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

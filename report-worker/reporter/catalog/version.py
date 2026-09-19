"""Katalogversion und Laufzeit-Digest.

CATALOG_VERSION folgt dem Format von POLICY_VERSION (``JJJJ-MM-TT.n``). Bump-Regel
(README, Abschnitt "Versionierung"): jede Aenderung an ``checks/``, ``ignore.yaml``
oder ``tables.py`` zieht die Version hoch. Der Digest wird zur Laufzeit ueber genau
diese Dateien berechnet (CRLF-normalisiert, BOM entfernt) und steht in jeder Ausgabe,
damit eine Aenderung ohne Bump im Audit sichtbar bleibt.

Bump-Historie:
    2026-09-19.1  Erstversion (Session S2).
    2026-09-20.1  S2b: Rueckbau der sieben Gruppenregeln `zap_no_alerts`. Die
                  Abdeckung traegt den Fall seit Issue #13 selbst.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

CATALOG_VERSION = "2026-09-20.1"

CATALOG_DIR = Path(__file__).resolve().parent
CHECKS_DIR = CATALOG_DIR / "checks"
IGNORE_FILE = CATALOG_DIR / "ignore.yaml"
TABLES_FILE = CATALOG_DIR / "tables.py"


def digest_files(catalog_dir: Path | None = None) -> list[Path]:
    """Dateien, die in den Digest eingehen, in stabiler Reihenfolge."""
    base = Path(catalog_dir) if catalog_dir else CATALOG_DIR
    files = sorted((base / "checks").glob("*.yaml"), key=lambda p: p.name)
    for extra in (base / "ignore.yaml", base / "tables.py"):
        if extra.exists():
            files.append(extra)
    return files


def catalog_digest(catalog_dir: Path | None = None) -> str:
    """sha256 ueber Dateiname plus Inhalt (CRLF -> LF, BOM entfernt) aller Katalogdateien."""
    h = hashlib.sha256()
    for path in digest_files(catalog_dir):
        data = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        h.update(path.name.encode("utf-8"))
        h.update(b"\0")
        h.update(data)
        h.update(b"\0")
    return h.hexdigest()

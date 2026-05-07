#!/usr/bin/env python3
"""Sync EdOverflow's `can-i-take-over-xyz` Service-Liste in
`scan-worker/data/takeover_data_generated.py`.

Aufruf:
    python scripts/sync-takeover-list.py [--dry-run]

Quelle: https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json
        (Lizenz: MIT — Attribution im Modul-Header.)

Hinweis: Der Audit-Eintrag (Sektion 3.3.4 / F-P0B-006) referenziert
`_data/services.yaml` — EdOverflow hat das Schema 2024 auf
`fingerprints.json` (Top-Level-Liste) im Repo-Root migriert. Felder sind
identisch (`service`, `cname`, `fingerprint`, `nxdomain`, `status`,
`vulnerable`), nur das Format wechselte von YAML zu JSON. Wir parsen
direkt JSON — keine `pyyaml`-Dependency noetig.

Filter:
    Nur Eintraege mit `vulnerable: true` ODER `status: Vulnerable`. Aktuell
    sind das ~35 Services (von ~76 Total — Rest sind "Not vulnerable" oder
    "Edge case", die wir nicht als Takeover-Risiko klassifizieren wollen).

Output-Format: Python-Modul mit
    TAKEOVER_INDICATORS_GENERATED: dict[str, dict] = {
        "github-pages": {
            "cname_patterns": ["github.io"],
            "fingerprint_strings": ["There isn't a GitHub Pages site here"],
            "status": "Vulnerable",
        },
        ...
    }

Der Loader in `scan-worker/scanner/phase0.py` kombiniert Generated +
Manual (`_TAKEOVER_POSSIBLE`) — Manual hat Vorrang bei Suffix-Kollision
(analog `saas_heuristic._build_combined_ranges()`).

Audit-Eintrag: `docs/scan-flow/Scan-Optimierung.md` Sektion 3.3.4 (F-P0B-006).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

# Lokaler Import — `_sync_lib` liegt im selben Ordner.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _sync_lib import (  # noqa: E402
    SyncValidationError,
    atomic_write_python_module,
    fetch_with_retry,
    validate_min_entries,
)


# ────────────────────────────────────────────────────────────────────
# Quelle + Konstanten
# ────────────────────────────────────────────────────────────────────
EDOVERFLOW_URL = (
    "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/"
    "master/fingerprints.json"
)

# GitHub raw-Endpoints lehnen Requests ohne User-Agent gelegentlich ab.
HTTP_HEADERS = {"User-Agent": "vectiscan-sync-takeover-list/1.0"}

# Sanity-Schwelle: weniger Eintraege = vermutlich Quell-Panne. Stand 2026-05
# liefert die EdOverflow-Liste ~35 vulnerable Services; 30 ist Floor.
MIN_TOTAL_ENTRIES = 30


# ────────────────────────────────────────────────────────────────────
# Parser
# ────────────────────────────────────────────────────────────────────

def _slugify(service: str) -> str:
    """Macht aus "AWS/S3" oder "GitHub Pages" einen kebab-case-Schluessel.

    Wird als Dict-Key in TAKEOVER_INDICATORS_GENERATED verwendet — soll stabil
    sein (gleiche Eingabe -> gleicher Output) und mit Manual-Listen-Schluesseln
    kollidierbar bleiben (`github-pages`, `aws-s3`).
    """
    s = service.strip().lower()
    # Slashes zu Bindestrich, Whitespace zu Bindestrich, Sonderzeichen weg
    s = re.sub(r"[\\/]+", "-", s)
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"[^a-z0-9\-]", "", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "unknown"


def _is_vulnerable(entry: dict) -> bool:
    """True wenn der Eintrag als ausnutzbar markiert ist.

    Akzeptiert sowohl `vulnerable: true` als auch (defensiv) `status:
    Vulnerable` — eines der beiden reicht. EdOverflow setzt beide
    konsistent, der OR-Check schuetzt vor Schema-Drift.
    """
    if entry.get("vulnerable") is True:
        return True
    status = (entry.get("status") or "").strip().lower()
    return status == "vulnerable"


def parse_fingerprints(body: str) -> dict[str, dict]:
    """Parst EdOverflow fingerprints.json.

    Returns:
        dict mit slug -> {cname_patterns, fingerprint_strings, status}.
        Eintraege ohne CNAME UND ohne Fingerprint UND ohne nxdomain-Flag
        werden uebersprungen (nicht actionable).
    """
    data = json.loads(body)
    if not isinstance(data, list):
        raise SyncValidationError(
            "fingerprints.json: erwartete Liste, bekam "
            f"{type(data).__name__}"
        )

    out: dict[str, dict] = {}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        if not _is_vulnerable(entry):
            continue

        service = (entry.get("service") or "").strip()
        if not service:
            continue

        cnames_raw = entry.get("cname") or []
        if not isinstance(cnames_raw, list):
            cnames_raw = []
        cname_patterns = sorted({c.strip().lower() for c in cnames_raw
                                  if isinstance(c, str) and c.strip()})

        fp_raw = entry.get("fingerprint") or ""
        fingerprint_strings: list[str] = []
        if isinstance(fp_raw, str) and fp_raw.strip() and fp_raw.strip() != "NXDOMAIN":
            fingerprint_strings = [fp_raw.strip()]

        nxdomain = bool(entry.get("nxdomain"))

        # actionable nur wenn mindestens eines der drei Signale brauchbar ist
        if not (cname_patterns or fingerprint_strings or nxdomain):
            continue

        slug = _slugify(service)
        out[slug] = {
            "cname_patterns": cname_patterns,
            "fingerprint_strings": fingerprint_strings,
            "nxdomain": nxdomain,
            "service": service,
            "status": entry.get("status") or "Vulnerable",
        }

    return out


# ────────────────────────────────────────────────────────────────────
# Fetch + Build
# ────────────────────────────────────────────────────────────────────

def build_indicators() -> dict[str, dict]:
    """Holt + parsed die EdOverflow-Quelle. Wirft bei Fetch-Fehlschlag."""
    print(f"[INFO] fetching EdOverflow fingerprints: {EDOVERFLOW_URL}")
    body = fetch_with_retry(
        EDOVERFLOW_URL,
        retries=3,
        timeout=30,
        headers=HTTP_HEADERS,
    )
    indicators = parse_fingerprints(body)
    print(f"  -> {len(indicators)} vulnerable Services extrahiert")
    return indicators


def _build_header(timestamp: str) -> str:
    """Modul-Docstring — Quelle + Generator + Zeitstempel."""
    return (
        '"""GENERIERT — NICHT MANUELL EDITIEREN.\n'
        '\n'
        'Subdomain-Takeover-Indikatoren aus EdOverflow can-i-take-over-xyz.\n'
        'Generator: scripts/sync-takeover-list.py\n'
        f'Stand:    {timestamp}\n'
        '\n'
        'Quelle: https://github.com/EdOverflow/can-i-take-over-xyz (MIT-Lizenz).\n'
        'Filter: nur Eintraege mit `vulnerable: true` (entspricht\n'
        '"status: Vulnerable").\n'
        '\n'
        'Manuelle Overrides + nicht-takeover-faehige Provider gehoeren in\n'
        '`scan-worker/scanner/phase0.py:_TAKEOVER_POSSIBLE/_TAKEOVER_NOT_POSSIBLE`.\n'
        'Diese haben Vorrang vor den Generated-Eintraegen (Loader-Logik in\n'
        '`phase0._build_takeover_indicators()`).\n'
        '"""\n'
    )


def write_module(entries: dict[str, dict], dest: Path) -> None:
    header = _build_header(datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    atomic_write_python_module(
        dest,
        header=header,
        data_name="TAKEOVER_INDICATORS_GENERATED",
        data_dict=entries,
        dict_type_hint="dict[str, dict]",
    )
    print(f"[INFO] wrote {len(entries)} services -> {dest}")


# ────────────────────────────────────────────────────────────────────
# CLI-Entry
# ────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="Nur fetchen + zusammenfassen, nicht schreiben")
    ap.add_argument("--out", default=None,
                    help="Override Output-Pfad (default: "
                         "scan-worker/data/takeover_data_generated.py)")
    args = ap.parse_args()

    try:
        entries = build_indicators()
    except Exception as exc:  # noqa: BLE001 — externe Quelle, generisch loggen
        print(f"[ERROR] EdOverflow-Fetch fehlgeschlagen: {exc}", file=sys.stderr)
        return 1

    # Sanity-Schwelle: Floor an aktiven Vulnerable-Services.
    try:
        validate_min_entries(
            entries, min_count=MIN_TOTAL_ENTRIES,
            source_name="edoverflow-takeover-list",
        )
    except SyncValidationError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"\n[DRY-RUN] {len(entries)} Services gefetched.")
        for slug in sorted(entries.keys())[:10]:
            info = entries[slug]
            cnames = ", ".join(info.get("cname_patterns") or []) or "—"
            print(f"  {slug}: cname=[{cnames}], "
                  f"fp={len(info.get('fingerprint_strings') or [])} string(s)")
        if len(entries) > 10:
            print(f"  ... ({len(entries) - 10} weitere)")
        return 0

    repo_root = Path(__file__).resolve().parent.parent
    dest = (Path(args.out) if args.out
            else repo_root / "scan-worker" / "data"
                            / "takeover_data_generated.py")
    write_module(entries, dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())

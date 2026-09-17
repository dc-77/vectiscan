#!/usr/bin/env python3
"""S0c Schritt 1: API-Snapshot als Golden-Fixture ablegen.

Quelle ist der mit report-prototype/scripts/fetch-all-orders.sh gezogene Ordner
report-prototype/input/_all/ (gitignored, liegt nur im Haupt-Checkout). Dieses
Skript kopiert ihn nach report-worker/tests/golden/api-snapshot/ und macht ihn
diff-tauglich: JSON wird mit sortierten Schluesseln und LF neu geschrieben, die
Inhalte selbst bleiben unveraendert.

Anonymisierung (spec/07 Abschnitt 1): Domains bleiben stehen, weil die Fakten
sonst wertlos sind. Redigiert wird nur, was kein Scanfakt ist: orders.json
fuehrt je Order die E-Mail des bestellenden Benutzers. DMARC-rua-, TLS-RPT- und
postmaster-Adressen aus dem DNS bleiben, weil die Mail-Pruefungen in S2 und S7
genau darauf laufen.

Aufruf:
    python3 scripts/golden/build-api-snapshot.py \
        --source ../../../report-prototype/input/_all
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = REPO_ROOT / "report-prototype" / "input" / "_all"
DEFAULT_DEST = REPO_ROOT / "report-worker" / "tests" / "golden" / "api-snapshot"

ORDER_FILES = ("order.json", "findings.json", "results.json")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

REDACTED_EMAIL = "redacted@example.invalid"

SECRET_RE = re.compile(r"Bearer\s+[A-Za-z0-9._-]{10,}|\"password\"\s*:\s*\"[^\"]+\"")


def write_json(path: Path, data: object) -> int:
    text = json.dumps(data, ensure_ascii=False, sort_keys=True, indent=1) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")
    return len(text.encode("utf-8"))


def redact_orders(doc: object) -> int:
    """Entfernt die Besteller-E-Mail aus der Listenantwort. Gibt Trefferzahl."""
    hits = 0
    if not isinstance(doc, dict):
        return hits
    for order in (doc.get("data") or {}).get("orders") or []:
        if isinstance(order, dict) and order.get("email"):
            order["email"] = REDACTED_EMAIL
            hits += 1
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    ap.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    args = ap.parse_args()

    source: Path = args.source.resolve()
    dest: Path = args.dest.resolve()
    if not source.is_dir():
        print(f"Quelle fehlt: {source}", file=sys.stderr)
        return 2

    orders_src = source / "orders.json"
    if not orders_src.is_file():
        print(f"orders.json fehlt in {source}", file=sys.stderr)
        return 2

    dest.mkdir(parents=True, exist_ok=True)

    orders_doc = json.loads(orders_src.read_text(encoding="utf-8"))
    redacted = redact_orders(orders_doc)
    total_bytes = write_json(dest / "orders.json", orders_doc)
    print(f"orders.json geschrieben, {redacted} Besteller-Adressen redigiert")

    order_dirs = sorted(d for d in source.iterdir() if d.is_dir() and UUID_RE.match(d.name))
    copied = 0
    suspect: list[str] = []
    for order_dir in order_dirs:
        out_dir = dest / order_dir.name
        out_dir.mkdir(exist_ok=True)
        for name in ORDER_FILES:
            src_file = order_dir / name
            if not src_file.is_file():
                print(f"  fehlt: {order_dir.name}/{name}", file=sys.stderr)
                continue
            raw = src_file.read_text(encoding="utf-8")
            if SECRET_RE.search(raw):
                suspect.append(f"{order_dir.name}/{name}")
            total_bytes += write_json(out_dir / name, json.loads(raw))
            copied += 1

    print(f"{len(order_dirs)} Orders, {copied} Dateien, {total_bytes / 1_048_576:.1f} MB")

    if suspect:
        print("ABBRUCH: moegliche Geheimnisse gefunden in:", file=sys.stderr)
        for entry in suspect:
            print(f"  {entry}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

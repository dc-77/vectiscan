#!/usr/bin/env python3
"""S0c: manifest.json und orders.txt fuer report-worker/tests/golden/ erzeugen.

manifest.json ist die einzige Wahrheit ueber das Golden-Set: welcher Auftrag
welche Rolle hat, zu welcher Domain er gehoert, und ob sein Roh-Tar vorliegt.
Der Smoke-Test in report-worker/tests/test_golden_fixtures.py parametrisiert
sich daraus.

orders.txt ist die maschinenlesbare Liste fuer den Ops-Job
ops-export-golden-tars (siehe scripts/golden/export-golden-tars.sh).

Aufruf nach jedem Tar-Export:
    python3 scripts/golden/build-manifest.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN = REPO_ROOT / "report-worker" / "tests" / "golden"

IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp")

# Auftrag -> (Rollen, Begruendung). Auswahl aus spec/07 Startprompt S0c plus
# Entscheidung DC vom 17.09.2026 (alle drei castenow-Laeufe).
#   golden   Soll-Liste und Referenz fuer den Katalogvergleich
#   drift    Wiederholungslauf fuer den Test "gleiche Fakten, gleiche Liste"
#   negative traegt Falschbefunde aus negative.json
#   coverage Lauf mit auffaelliger Laufzeit, Abdeckungsluecken muessen sichtbar werden
ROLES: dict[str, tuple[list[str], str]] = {
    "0bf16342-ed96-4b0e-a596-05aee3a62cb5": (
        ["golden", "drift", "negative"],
        "Junkerwerk Lauf 1, beide Domains; Soll-Liste in expected/junkerwerk.json",
    ),
    "2572eebc-6135-40e6-b1d2-e9dfccc20ae6": (
        ["golden", "drift", "negative"],
        "Junkerwerk Lauf 2, junkerwerk.de",
    ),
    "a6df9d9d-eccd-49d1-8dd3-b00a5e005108": (
        ["golden", "drift", "negative"],
        "Junkerwerk Lauf 3, junkerwerk.hu",
    ),
    "ae8d1d70-7925-4e3c-84de-3113f3e57b60": (
        ["drift", "negative"],
        "securess.de 19.07.2026, juengster von acht Laeufen",
    ),
    "176db198-fa4a-4520-bf18-43cbc02a229d": (
        ["drift"],
        "heuel.com, juengster von sechs Laeufen",
    ),
    "4e6b6883-a6c8-4204-8b13-b37f907322ca": (
        ["golden", "drift"],
        "castenow.de 22.07.2026 08:08, Referenzlauf; reichste Infrastruktur "
        "(Exchange, Nextcloud, Bitwarden, Icecast), spec/06 Abschnitt 2.1",
    ),
    "2d2d4f39-0816-46a0-ba96-4d36b248a86c": (
        ["drift"],
        "castenow.de 22.07.2026 15:45, zweiter Lauf am selben Tag",
    ),
    "f77ccff2-fc7a-4488-a9ba-540a42a25056": (
        ["drift", "coverage"],
        "castenow.de 19.07. bis 22.07.2026; fast drei Tage Laufzeit, die Timeouts "
        "oder Blockaden muessen im Abdeckungskapitel sichtbar werden",
    ),
    "45bb234c-d556-4a80-9c78-3ce221ea28a6": (
        ["negative"],
        "trunk-immobilien.de, traegt allein fuenf Eintraege aus negative.json",
    ),
    "fb13a98f-22c6-4d17-875c-eeeb14643beb": (
        ["negative"],
        "krause-computer.de",
    ),
}


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tar_info(path: Path) -> dict:
    members = 0
    images = 0
    with tarfile.open(path, "r:gz") as tar:
        for member in tar:
            members += 1
            if member.name.lower().endswith(IMAGE_SUFFIXES):
                images += 1
    return {
        "present": True,
        "bytes": path.stat().st_size,
        "sha256": sha256_of(path),
        "members": members,
        "images": images,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--golden", type=Path, default=GOLDEN)
    args = ap.parse_args()

    golden: Path = args.golden.resolve()
    snapshot = golden / "api-snapshot"
    orders_doc = json.loads((snapshot / "orders.json").read_text(encoding="utf-8"))
    meta = {o["id"]: o for o in orders_doc["data"]["orders"]}

    negative = json.loads((golden / "negative.json").read_text(encoding="utf-8"))
    negative_counts: dict[str, int] = {}
    for entry in negative["entries"]:
        negative_counts[entry["order"]] = negative_counts.get(entry["order"], 0) + 1

    tars_dir = golden / "tars"
    orders = []
    for order_id, (roles, note) in ROLES.items():
        api = meta.get(order_id, {})
        targets = [t.get("canonical") for t in (api.get("targets") or []) if t.get("canonical")]
        tar_path = tars_dir / f"{order_id}.tar.gz"
        entry = {
            "order_id": order_id,
            "domains": targets or ([api["domain"]] if api.get("domain") else []),
            "package": api.get("package"),
            "created": api.get("createdAt"),
            "started": api.get("startedAt"),
            "finished": api.get("finishedAt"),
            "roles": roles,
            "note": note,
            "negative_entries": negative_counts.get(order_id, 0),
            "api_snapshot": (snapshot / order_id).is_dir(),
            "tar": {"present": False, "reason": "Export noch nicht gelaufen"},
        }
        if tar_path.is_file():
            entry["tar"] = tar_info(tar_path)
        orders.append(entry)

    orders.sort(key=lambda e: (e["created"] or "", e["order_id"]))

    manifest = {
        "beschreibung": (
            "Golden-Fixtures fuer den Report-Umbau (spec/05 bis 07, Session S0c). "
            "Dateinamen tragen nur Auftrags-UUIDs, also keine Kundennamen. Domains "
            "bleiben in den Daten stehen, weil die Fakten sonst wertlos sind. "
            "Screenshots sind aus allen Tars entfernt (spec/07 Abschnitt 1)."
        ),
        "api_snapshot_orders": sum(1 for d in snapshot.iterdir() if d.is_dir()),
        "tars_erwartet": len(ROLES),
        "tars_vorhanden": sum(1 for o in orders if o["tar"]["present"]),
        "orders": orders,
    }

    (golden / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n"
    )
    (golden / "orders.txt").write_text(
        "".join(f"{o['order_id']}\n" for o in orders), encoding="utf-8", newline="\n"
    )

    print(f"manifest.json: {len(orders)} Auftraege, {manifest['tars_vorhanden']} Tars vorhanden")
    for order in orders:
        state = (
            f"{order['tar']['bytes'] / 1_048_576:.2f} MB, {order['tar']['images']} Bilder"
            if order["tar"]["present"]
            else "kein Tar"
        )
        print(f"  {order['order_id'][:8]} {','.join(order['roles']):24} {state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

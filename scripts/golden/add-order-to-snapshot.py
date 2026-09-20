#!/usr/bin/env python3
"""S2b: eine einzelne Order in den Golden-API-Snapshot aufnehmen.

Gegenstueck zu ``build-api-snapshot.py``, das den ganzen Ordner neu schreibt.
Ein Neuabzug aller Auftraege wuerde die bestehenden Fixtures veraendern, sobald
die API zwischenzeitlich etwas anders liefert (neue Felder, neu erzeugter
Bericht). Dieses Skript ruehrt nur die eine Order an, die dazukommt.

Es schreibt
    report-worker/tests/golden/api-snapshot/<orderId>/{order,findings,results}.json
und ergaenzt den Listeneintrag in
    report-worker/tests/golden/api-snapshot/orders.json
im selben Format wie build-api-snapshot.py (sortierte Schluessel, indent 1, LF).
Die Besteller-E-Mail wird wie dort redigiert; Domains und DNS-Adressen bleiben
stehen, weil sie Scanfakten sind (spec/07 Abschnitt 1).

Quelle ist die VectiScan-API. Zugangsdaten stehen in
``report-prototype/vectiscan.creds`` (Zeile 1 E-Mail, Zeile 2 Passwort), wie bei
``report-prototype/scripts/fetch-order.sh``. Die Datei ist gitignored und liegt
nur im Haupt-Checkout; aus einem Worktree heraus zeigt ``--creds`` darauf.
Die API ist nur aus dem internen Netz erreichbar.

Aufruf:
    python3 scripts/golden/add-order-to-snapshot.py <orderId>
    python3 scripts/golden/add-order-to-snapshot.py <orderId> --source <dir>

Mit ``--source`` werden die drei Dateien aus einem Verzeichnis gelesen (z.B.
dem Ergebnis von fetch-order.sh) statt von der API geholt; der Listeneintrag
kommt dann aus ``order.json``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = REPO_ROOT / "report-worker" / "tests" / "golden" / "api-snapshot"
CREDS = REPO_ROOT / "report-prototype" / "vectiscan.creds"
API_DEFAULT = "https://scan-api.vectigal.tech"

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
REDACTED_EMAIL = "redacted@example.invalid"
SECRET_RE = re.compile(r"Bearer\s+[A-Za-z0-9._-]{10,}|\"password\"\s*:\s*\"[^\"]+\"")

# Felder, die der Listeneintrag traegt und build-manifest.py liest.
LIST_KEYS = ("id", "domain", "package", "status", "createdAt", "startedAt",
             "finishedAt", "targets", "email")


def write_json(path: Path, data: object) -> None:
    text = json.dumps(data, ensure_ascii=False, sort_keys=True, indent=1) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")


def login(api: str, creds: Path) -> str:
    if not creds.is_file():
        raise SystemExit(f"Zugangsdaten fehlen: {creds}")
    lines = creds.read_text(encoding="utf-8").splitlines()
    req = urllib.request.Request(
        api + "/api/auth/login",
        data=json.dumps({"email": lines[0].strip(),
                         "password": lines[1].strip()}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["data"]["token"]


def get(api: str, token: str, path: str) -> Any:
    req = urllib.request.Request(api + path,
                                 headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("order_id")
    ap.add_argument("--source", type=Path, default=None,
                    help="Verzeichnis mit order.json, findings.json, results.json")
    ap.add_argument("--api", default=API_DEFAULT)
    ap.add_argument("--creds", type=Path, default=CREDS,
                    help="Datei mit E-Mail und Passwort (gitignored)")
    ap.add_argument("--snapshot", type=Path, default=SNAPSHOT)
    args = ap.parse_args()

    order_id: str = args.order_id
    if not UUID_RE.match(order_id):
        print(f"Keine vollstaendige UUID: {order_id}", file=sys.stderr)
        return 2

    snapshot: Path = args.snapshot.resolve()
    orders_path = snapshot / "orders.json"
    if not orders_path.is_file():
        print(f"orders.json fehlt in {snapshot}", file=sys.stderr)
        return 2

    docs: dict[str, Any] = {}
    list_entry: dict[str, Any] | None = None

    if args.source:
        src: Path = args.source.resolve()
        for name in ("order.json", "findings.json", "results.json"):
            f = src / name
            if not f.is_file():
                print(f"{name} fehlt in {src}", file=sys.stderr)
                return 2
            docs[name] = json.loads(f.read_text(encoding="utf-8"))
        inner = (docs["order.json"].get("data") or {}).get("order") \
            or (docs["order.json"].get("data") or {})
        list_entry = {k: inner.get(k) for k in LIST_KEYS if k in inner}
        list_entry["id"] = order_id
    else:
        token = login(args.api, args.creds.resolve())
        docs["order.json"] = get(args.api, token, f"/api/orders/{order_id}")
        docs["findings.json"] = get(args.api, token, f"/api/orders/{order_id}/findings")
        docs["results.json"] = get(args.api, token, f"/api/orders/{order_id}/results")
        listing = get(args.api, token, "/api/orders?limit=500")
        for o in (listing.get("data") or {}).get("orders") or []:
            if str(o.get("id")) == order_id:
                list_entry = dict(o)
                break

    if list_entry is None:
        print(f"Auftrag {order_id} steht nicht in der Auftragsliste", file=sys.stderr)
        return 1

    for name, doc in docs.items():
        if doc.get("success") is not True:
            print(f"{name}: keine gueltige API-Antwort", file=sys.stderr)
            return 1
        if SECRET_RE.search(json.dumps(doc, ensure_ascii=False)):
            print(f"ABBRUCH: moegliches Geheimnis in {name}", file=sys.stderr)
            return 1

    if list_entry.get("email"):
        list_entry["email"] = REDACTED_EMAIL

    out_dir = snapshot / order_id
    out_dir.mkdir(exist_ok=True)
    for name, doc in docs.items():
        write_json(out_dir / name, doc)

    orders_doc = json.loads(orders_path.read_text(encoding="utf-8"))
    orders = (orders_doc.get("data") or {}).get("orders")
    if not isinstance(orders, list):
        print("orders.json hat keine data.orders-Liste", file=sys.stderr)
        return 1
    orders = [o for o in orders if str(o.get("id")) != order_id]
    orders.append(list_entry)
    # Die Liste steht wie die API-Antwort: neuester Auftrag zuerst.
    orders.sort(key=lambda o: (str(o.get("createdAt") or ""), str(o.get("id"))),
                reverse=True)
    orders_doc["data"]["orders"] = orders
    write_json(orders_path, orders_doc)

    print(f"{order_id[:8]} aufgenommen: {len(docs)} Dateien, "
          f"{len(orders)} Auftraege in orders.json")
    print("Naechster Schritt: scripts/golden/build-manifest.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

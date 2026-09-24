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
        "castenow.de. Der Auftrag laeuft in der API vom 19.07. bis 22.07.2026, der "
        "Scan selbst aber nur 46 Minuten (meta.json im Tar: 19.07. 23:40 bis 20.07. "
        "00:26). Die drei Tage liegen zwischen Scanende und Auftragsabschluss, also "
        "in Bericht und Freigabe, nicht im Scan. Als Coverage-Fixture taugt der Lauf "
        "trotzdem: von neun Hosts haben nur einer ffuf_param und wpscan, sechs zap "
        "und sieben feroxbuster. Genau diese Luecken muessen im Abdeckungskapitel "
        "stehen",
    ),
    "45bb234c-d556-4a80-9c78-3ce221ea28a6": (
        ["negative"],
        "trunk-immobilien.de, traegt allein fuenf Eintraege aus negative.json",
    ),
    "fb13a98f-22c6-4d17-875c-eeeb14643beb": (
        ["negative"],
        "krause-computer.de",
    ),
    "14272c00-1145-4675-9b4c-19ce2ead403b": (
        ["coverage"],
        "dortmund-beach.com 17.09.2026, Nachweislauf S0b und erster Produktionslauf "
        "mit zap_active status=ok und vollstaendiger Alert-Liste. In den zehn "
        "aelteren Fixtures hat zap_active nie ein Ergebnis geliefert, deshalb waren "
        "web_vulnerability_active und sensitive_path_exposed nur ueber Fixtures "
        "gedeckt (Issue #14). feroxbuster und ffuf_param laufen hier ebenfalls, "
        "ffuf_sensitive laeuft in den Timeout",
    ),
    "57b3ac85-a1da-47e9-b783-d28ad9a9fa35": (
        ["golden"],
        "lumbeck-wolter.de 20.09.2026, Pilotkunde mit schriftlicher Freigabe und "
        "erster Fixture-Lauf nach den S2b-Scannerfixen. Ein Ziel, ein Host. Der "
        "AAAA 2a01:4f8:d0a:668b::2 taucht im Lauf nicht auf: Haupt- und "
        "www-Adresse teilen ihr FQDN-Set mit der A-Adresse, und die "
        "Zusammenfassung in phase0 bevorzugt IPv4. Der Lauf belegt damit den "
        "Dual-Stack-Defekt, nicht den IPv6-Scan",
    ),
    "860d0d5a-1086-4958-a9ac-4650423095f2": (
        ["golden", "drift"],
        "Junkerwerk Lauf 4, beide Domains, 20.09.2026. Erster Fixture-Lauf mit "
        "einem AAAA-Host (2a01:4f8:d0a:3124::2) und erster mit den S2b-Fixen: DNS "
        "je Domain (Issue #12), testssl ohne Severity-Filter (#9), Header und "
        "httpx je VHost (#10). Vierter Lauf im Junkerwerk-Drift-Test",
    ),
    "75338c97-6707-4d11-92bf-bb3cd2e02cde": (
        ["golden", "coverage"],
        "vectigal.tech und vectiscan.de, 20.09.2026, eigene Domains. Der einzige "
        "WebCheck-Auftrag im Satz und damit der erste Beleg fuer die Paketvariante "
        "an echten Daten (Issue #23). Kleinerer Werkzeugsatz, Hostgrenze drei, "
        "beide Ziele hinter derselben Traefik-Instanz mit Rate-Limit. Interner "
        "Nachweislauf aus S2b, wird nicht ausgeliefert",
    ),
    # Scan-Runde 23.09.2026 (S6a2): sieben Perimeter-Auftraege bei Pilotkunden mit
    # schriftlicher Freigabe, Engine catalog, Layout v3, Gate strict, gegengelesen in
    # spec/09. Soll-Listen abgeleitet (strict false), Eintraege, die spec/09 als falsch
    # belegt, tragen in expected_map_<slug>.json die Q-Nummer.
    "1fbc92b9-34ab-414e-8843-a1f1e9f15431": (
        ["golden", "drift"],
        "dortmund-beach.com, Scan-Runde 23.09.2026; Soll-Liste "
        "expected/dortmund-beach-0923.json. Traegt jQuery Migrate 3.4.1 (Namensgrenze, "
        "spec/09 Q11), Webmin auf 10000 (Q13) und csrf_token_missing mit Konfidenz Low (Q14)",
    ),
    "c3d5724c-bdbf-4da8-982f-4f1a52210e28": (
        ["golden", "drift"],
        "lumbeck-wolter.de, Scan-Runde 23.09.2026; Soll-Liste "
        "expected/lumbeck-wolter-0923.json. Regressionsfall der Dashboard-Techniktabelle: "
        "MariaDB mit Praefix 5.5.5- und PostgreSQL 9.6.0 or later (spec/09 Q11)",
    ),
    "31d67a02-b485-4d05-b228-dbdde092cc68": (
        ["golden", "drift"],
        "Junkerwerk Lauf 5, junkerwerk.de und junkerwerk.hu, Scan-Runde 23.09.2026; "
        "Soll-Liste expected/junkerwerk-0923.json. Wie c3d5724c MariaDB mit Praefix und "
        "PostgreSQL or later auf dem Hetzner-Server (spec/09 Q11); archiv.junkerwerk.de fehlt "
        "(Discovery, Q1). Nicht im Junkerwerk-Drift-Test, der Scanner hat sich seit Lauf 4 "
        "geaendert",
    ),
    "3cf01f8d-4d21-4e6d-bac2-7342f1a4d6c7": (
        ["golden"],
        "huendgen-entsorgung.de, Scan-Runde 23.09.2026; Soll-Liste "
        "expected/huendgen-0923.json. Exchange 2019 mit OWA, Duda-Plattform als "
        "geteiltes System (spec/09 Q3); die FTP-Namen fehlen (Q1)",
    ),
    "68d59573-7a93-4efa-89cc-e7b10cc4d140": (
        ["golden", "coverage"],
        "bergersysteme.com, Scan-Runde 23.09.2026; Soll-Liste "
        "expected/bergersysteme-0923.json. Vier Hosts ohne Messergebnis (leere "
        "nmap-Ausgabe, spec/09 Q9 und E4), Cloudflare-Kante und Plesk-Sammelserver (Q3), "
        "24 Namen gehen in der Discovery verloren (Q1)",
    ),
    "1f8bc977-39a7-47c7-b4ad-7b05dbac2d52": (
        ["golden", "drift"],
        "castenow.de, Scan-Runde 23.09.2026; Soll-Liste expected/castenow-0923.json. "
        "Groesster Bericht der Runde, Plesk-Sammelserver mit Fremdkunden (spec/09 Q3), "
        "jQuery Migrate (Q11), CAA vorhanden (Q4)",
    ),
    "2e56abe1-c1a6-442e-b36a-dc9f83c81da8": (
        ["golden", "drift"],
        "heuel.com, Scan-Runde 23.09.2026; Soll-Liste expected/heuel-0923.json. "
        "IPv6-Host, Vercel- und IONOS-Kanten, AbuseIPDB mit isWhitelisted (spec/09 Q12)",
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

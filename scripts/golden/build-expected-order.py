#!/usr/bin/env python3
"""S2b: Soll-Liste fuer eine Golden-Order aus dem Katalogergebnis erzeugen.

Fuer Junkerwerk kam die Soll-Liste aus dem handkuratierten Prototyp-Bericht
(``build-expected-junkerwerk.py``). Fuer eine Order ohne solchen Bericht gibt
es diesen Weg nicht. Dieses Skript schreibt deshalb auf, was der Katalog heute
liefert, und macht daraus eine Regressionssperre: eine spaetere Aenderung an
Regeln, Fakten oder Scanner faellt dann sofort auf.

Wichtig und bewusst: die Liste ist abgeleitet, nicht unabhaengig erarbeitet.
Sie beweist nicht, dass die Befunde richtig sind — das prueft DC vor dem Merge.
Sie haelt nur fest, dass sie stabil bleiben. Deshalb steht in der erzeugten
Zuordnung ``strict: false``: sie behauptet keine Vollstaendigkeit.

Markierungen (S6a2): Eintraege, die ein Gegenlesen als falsch belegt, tragen in
``expected_map_<name>.json`` zusaetzliche Schluessel neben ``checks``, etwa
``"spec09": "Q4", "warum": "..."``. Beim Neuerzeugen bleiben sie am Eintrag mit
derselben Pruefung und Gruppe stehen, auch wenn sich die ID verschiebt. Faellt ein
markierter Eintrag weg, meldet das Skript es ("Markierung entfaellt"): genau das
ist der Nachweis, dass eine Korrektur den Eintrag bewusst geaendert hat.

Aufruf:
    python3 scripts/golden/build-expected-order.py <orderId> --name dortmund-beach
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT_WORKER = REPO_ROOT / "report-worker"
sys.path.insert(0, str(REPORT_WORKER))

from reporter.catalog import evaluate, load_catalog  # noqa: E402
from reporter.facts.schema import Facts  # noqa: E402

GOLDEN = REPORT_WORKER / "tests" / "golden"


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n",
                    encoding="utf-8", newline="\n")


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def old_marks(expected_path: Path, map_path: Path) -> dict[tuple[str, str, str], dict]:
    """Markierungen der bisherigen Zuordnung, je (Liste, Pruefung, Gruppe)."""
    expected, mapping = _read_json(expected_path), _read_json(map_path)
    marks: dict[tuple[str, str, str], dict] = {}
    for liste in ("findings", "positives"):
        by_id = {e["id"]: e for e in expected.get(liste) or []}
        for eid, entry in (mapping.get(liste) or {}).items():
            extra = {k: v for k, v in entry.items() if k != "checks"}
            if extra and eid in by_id:
                marks[(liste, by_id[eid]["check"], by_id[eid]["group"])] = extra
    return marks


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("order_id")
    ap.add_argument("--name", required=True, help="Dateiname ohne Endung")
    args = ap.parse_args()

    facts_path = GOLDEN / "facts" / f"{args.order_id}.json"
    if not facts_path.is_file():
        print(f"Golden-Facts fehlen: {facts_path}\n"
              f"Erst 'python -m reporter.facts --golden' laufen lassen.",
              file=sys.stderr)
        return 2

    facts = Facts.from_dict(json.loads(facts_path.read_text(encoding="utf-8")))
    out = evaluate(facts, load_catalog())

    manifest = json.loads((GOLDEN / "manifest.json").read_text(encoding="utf-8"))
    entry = next((o for o in manifest["orders"] if o["order_id"] == args.order_id), {})

    findings: list[dict] = []
    positives: list[dict] = []
    for r in sorted(out.results, key=lambda r: (r.check_id, r.group_key)):
        if r.kind != "check":
            continue
        if r.status == "fail":
            findings.append({
                "id": f"VS-2026-{len(findings) + 1:03d}",
                "check": r.check_id,
                "family": r.family,
                "cat": r.category,
                "scale": r.scale,
                "level": r.level,
                "group": r.group_label,
                "affected": list(r.affected),
                "title": r.title,
            })
        elif r.status == "pass" and r.positive:
            positives.append({
                "id": f"VS-2026-P{len(positives) + 1:02d}",
                "check": r.check_id,
                "family": r.family,
                "cat": r.category,
                "group": r.group_label,
                "title": ((r.texts.positive.title if r.texts.positive else None)
                          or r.title),
            })

    expected = {
        "source": f"reporter.catalog {out.catalog_version} auf "
                  f"tests/golden/facts/{args.order_id}.json",
        "hinweis": "Abgeleitet aus dem Katalogergebnis, nicht unabhaengig erarbeitet. "
                   "Die Liste ist eine Regressionssperre; die inhaltliche Pruefung "
                   "liegt bei DC (Issue #14).",
        "customer": None,
        "domains": entry.get("domains") or [],
        "package": entry.get("package"),
        "order_ids": [args.order_id],
        "findings": findings,
        "positives": positives,
    }
    expected_path = GOLDEN / "expected" / f"{args.name}.json"
    map_path = REPORT_WORKER / "tests" / "catalog" / f"expected_map_{args.name}.json"
    marks = old_marks(expected_path, map_path)
    previous = _read_json(map_path)
    write_json(expected_path, expected)

    def entry(liste: str, e: dict) -> dict:
        return {"checks": [e["check"]], **marks.pop((liste, e["check"], e["group"]), {})}

    mapping = {
        "hinweis": f"Zuordnung der Soll-Liste tests/golden/expected/{args.name}.json. "
                   "strict bleibt false, solange die Liste abgeleitet und nicht "
                   "unabhaengig erarbeitet ist.",
        # Freitext-Hinweise der bisherigen Zuordnung (z.B. hinweis_spec09) bleiben stehen.
        **{k: v for k, v in previous.items() if k.startswith("hinweis_")},
        "strict": False,
        "orders": {"main": args.order_id},
        "findings": {f["id"]: entry("findings", f) for f in findings},
        "positives": {p["id"]: entry("positives", p) for p in positives},
        "subsumed": {},
        "expected_coverage_differences": [],
        "expected_member_differences": [],
    }
    write_json(map_path, mapping)
    for (liste, check, group), extra in sorted(marks.items()):
        print(f"Markierung entfaellt: {liste} {check} / {group}: {extra}")

    print(f"{len(findings)} Befunde, {len(positives)} Positivaussagen "
          f"-> tests/golden/expected/{args.name}.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

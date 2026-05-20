"""Replay-Tool: ValidationGate gegen reale Order-Findings laufen lassen.

Spec: docs/report-erstellung/01_Fehleranalyse_und_Korrekturplan.md Phase A
Plan: M1 Verifikation gegen secumetrix (7629dd77-...) + heuel (12bdbf3a-...)

Modi:
  1) Aus DB ziehen (braucht DATABASE_URL = postgres://... auf vectigal-docker02):
       python -m scripts.replay_gate --order-id 7629dd77-...
  2) Aus JSON-Dump lokal (z.B. via API-Endpoint /api/orders/<id>/findings):
       python -m scripts.replay_gate --findings-json path/to/findings.json
  3) Beide Realreports auf einmal (DB-Mode):
       python -m scripts.replay_gate --replay-m1-set

Output: Console-Summary + JSON-Detail (errors/warnings nach Check gruppiert).
Exit-Code: 0 wenn die Gate fuer alle Inputs durchgeht (wuerde STRICT erlauben),
           1 wenn mindestens ein Input mind. 1 Error hat.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

# Erlaube Aufruf via `python scripts/replay_gate.py` direkt aus report-worker/
_HERE = Path(__file__).resolve().parent
_REPORTER_ROOT = _HERE.parent
if str(_REPORTER_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPORTER_ROOT))

from reporter.validation.gate import ValidationGate, ValidationLevel  # noqa: E402


# Die zwei Realreport-Orders aus dem M1-Spec.
M1_REPLAY_ORDER_PREFIXES = {
    "secumetrix": "7629dd77",
    "heuel": "12bdbf3a",
}


def _fetch_from_db(order_id: str) -> tuple[dict, dict | None]:
    """Lese findings_data + tech_profiles aus reports-Tabelle.

    Nutzt psycopg2 mit DATABASE_URL. Wenn der Prefix nicht eindeutig ist,
    waehlt der neueste Report (version DESC).
    """
    import psycopg2

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise SystemExit(
            "DATABASE_URL fehlt — DB-Mode benoetigt Connection-String zu "
            "vectigal-docker02. Alternativ --findings-json benutzen."
        )

    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT r.findings_data::text, r.tech_profiles::text
                  FROM reports r
                  JOIN orders o ON r.order_id = o.id
                 WHERE o.id::text LIKE %s
                 ORDER BY r.version DESC, r.created_at DESC
                 LIMIT 1
                """,
                (f"{order_id}%",),
            )
            row = cur.fetchone()
            if not row:
                raise SystemExit(f"Kein Report fuer Order-Prefix {order_id} in DB gefunden.")
            findings_data = json.loads(row[0])
            tech_profiles = json.loads(row[1]) if row[1] else None
            return findings_data, tech_profiles


def _load_from_json(path: Path) -> tuple[dict, dict | None]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    # Akzeptiere zwei Shapes:
    #   - direkt das findings_data Dict
    #   - api-response: {"success": true, "data": {"findings": [...], "tech_profiles": ...}}
    if isinstance(raw, dict) and raw.get("success") and "data" in raw:
        data = raw["data"]
        findings_data = {
            "findings": data.get("findings") or [],
            "positive_findings": data.get("positive_findings") or [],
            "recommendations": data.get("recommendations") or [],
            "severity_counts": data.get("severity_counts") or {},
            "overall_risk": data.get("overall_risk"),
            "overall_description": data.get("overall_description"),
            "package": data.get("package", "perimeter"),
        }
        return findings_data, data.get("tech_profiles")
    return raw, raw.get("tech_profiles")


def _run_one(label: str, findings_data: dict, tech_profiles: dict | None,
             *, package: str) -> dict:
    """Run gate (WARN mode) und produziere ein Summary."""
    gate = ValidationGate(level=ValidationLevel.WARN)
    ctx = {
        "package": package,
        "order_id": label,
        "domain": "(replay)",
        "tech_profiles": tech_profiles,
    }
    result = gate.run(findings_data, report_data={}, context=ctx)

    by_check_errors: dict[str, int] = {}
    by_check_warnings: dict[str, int] = {}
    for issue in result.errors:
        by_check_errors[issue.check] = by_check_errors.get(issue.check, 0) + 1
    for issue in result.warnings:
        by_check_warnings[issue.check] = by_check_warnings.get(issue.check, 0) + 1

    return {
        "label": label,
        "passed": result.passed,
        "error_count": len(result.errors),
        "warning_count": len(result.warnings),
        "by_check_errors": by_check_errors,
        "by_check_warnings": by_check_warnings,
        "checks_run": result.checks_run,
        "checks_skipped": result.checks_skipped,
        "first_errors": [
            {
                "check": i.check,
                "finding_id": i.finding_id,
                "message": i.message,
                "detail": i.detail,
            }
            for i in result.errors[:10]
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="ValidationGate-Replay")
    parser.add_argument("--order-id", help="DB-Mode: Order-UUID-Prefix")
    parser.add_argument("--findings-json", type=Path,
                        help="JSON-Dump (findings_data oder /findings-API-Response)")
    parser.add_argument("--package", default="perimeter")
    parser.add_argument("--replay-m1-set", action="store_true",
                        help="Beide M1-Realreports (secumetrix + heuel) via DB")
    parser.add_argument("--expect-min-errors", type=int, default=0,
                        help="Akzeptanzkriterium: mind. N Errors erwartet (Default 0)")
    args = parser.parse_args()

    summaries: list[dict[str, Any]] = []

    if args.replay_m1_set:
        for label, prefix in M1_REPLAY_ORDER_PREFIXES.items():
            findings_data, tech_profiles = _fetch_from_db(prefix)
            summaries.append(_run_one(
                f"{label} ({prefix})", findings_data, tech_profiles,
                package=args.package,
            ))
    elif args.order_id:
        findings_data, tech_profiles = _fetch_from_db(args.order_id)
        summaries.append(_run_one(
            args.order_id, findings_data, tech_profiles, package=args.package,
        ))
    elif args.findings_json:
        findings_data, tech_profiles = _load_from_json(args.findings_json)
        summaries.append(_run_one(
            str(args.findings_json), findings_data, tech_profiles,
            package=args.package,
        ))
    else:
        parser.error("Eine von --order-id / --findings-json / --replay-m1-set angeben.")
        return 2

    # Console-Output
    print("=" * 78)
    print("VALIDATION-GATE REPLAY")
    print("=" * 78)
    any_fail = False
    for s in summaries:
        print(f"\n• {s['label']}")
        print(f"  passed:          {s['passed']}")
        print(f"  errors:          {s['error_count']}")
        print(f"  warnings:        {s['warning_count']}")
        print(f"  by check (err):  {s['by_check_errors']}")
        print(f"  by check (warn): {s['by_check_warnings']}")
        print(f"  checks_run:      {s['checks_run']}")
        print(f"  checks_skipped:  {s['checks_skipped']}")
        if s["first_errors"]:
            print(f"  first errors:")
            for e in s["first_errors"]:
                fid = e["finding_id"] or "-"
                print(f"    [{e['check']}] {fid}: {e['message']}")
        if not s["passed"]:
            any_fail = True

    print()
    print("=" * 78)
    if args.expect_min_errors > 0:
        total_errors = sum(s["error_count"] for s in summaries)
        ok = total_errors >= args.expect_min_errors
        print(f"Akzeptanz: erwartet >= {args.expect_min_errors} Errors gesamt -- "
              f"gefunden {total_errors} ({'OK' if ok else 'FAIL'})")
        return 0 if ok else 1
    return 1 if any_fail else 0


if __name__ == "__main__":
    sys.exit(main())

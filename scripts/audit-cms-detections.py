#!/usr/bin/env python3
"""Audit aller CMS-Detections (PR-CMS-Fix, 2026-05-03).

Iteriert ueber alle scan_results mit tool_name='cms_fingerprint' (oder
ueber findings_data.cms-Felder), klassifiziert die Erkennung als:

  STRONG    → mehrere Beweise (probe_hits ≥ 2, davon ≥1 body match auf
              spezifischem Pattern wie 'magento'/'wordpress')
  OK        → 1 spezifischer body match + 1 cookie/header
  WEAK      → nur generic probe-Hit (z.B. '/admin → 200') ohne body match
  FALSE_POS → bekannte Falsch-Positiv-Patterns (z.B. (?i)mage matchte
              'image' im Body)

Usage:
    python scripts/audit-cms-detections.py [--limit N] [--verbose]
    docker compose exec report-worker python /app/scripts/audit-cms-detections.py
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from typing import Any

import psycopg2
import psycopg2.extras


# Bekannte False-Positive-Pattern (die im alten Code matchten)
FP_PATTERNS = [
    (r"\(\?i\)mage\b", "Magento (?i)mage matched 'image'"),
    (r"\(\?i\)craft\b", "Craft CMS (?i)craft matched 'aircraft'"),
]

# Spezifische Marker (echte Hits)
STRONG_MARKERS = {
    "Magento": [r"magento", r"mage\.cookies", r"/skin/frontend/", r"magento_theme"],
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "Drupal": [r"drupal", r"sites/default"],
    "TYPO3": [r"typo3", r"typo3temp"],
    "Joomla": [r"joomla"],
    "Shopware": [r"shopware"],
    "Craft CMS": [r"craft\s?cms", r"craftcms\.com", r"/cpresources/"],
    "Strapi": [r"strapi[\.\-/]", r"strapi\.io"],
    "Ghost": [r"ghost-"],
    "PrestaShop": [r"prestashop\.com", r"ps_version"],
    "NEOS": [r"neos-"],
    "Contao": [r"contao"],
}


def classify_probe_hits(cms: str, hits: list[str]) -> tuple[str, list[str]]:
    """Returns (classification, reasons)."""
    reasons: list[str] = []
    has_specific_body = False
    has_generic_probe = False
    has_cookie = False
    fp_indicators: list[str] = []

    strong_markers = [m.lower() for m in STRONG_MARKERS.get(cms, [])]

    for h in hits:
        h_low = h.lower()
        # FP-Detection: alte Patterns
        for fp_re, fp_label in FP_PATTERNS:
            if re.search(fp_re, h):
                fp_indicators.append(fp_label)
        # Body-Match-Klassifizierung
        if "body match" in h_low:
            after = h_low.split("body match:", 1)[-1].strip()
            # Pattern wirklich spezifisch fuer dieses CMS?
            if any(m in after for m in strong_markers):
                has_specific_body = True
                reasons.append(f"specific_body: {after}")
            else:
                # Generischer Match wie "(?i)mage" oder "(?i)craft"
                reasons.append(f"weak_body: {after}")
        elif "cookie" in h_low:
            has_cookie = True
            reasons.append(f"cookie_match")
        elif "→" in h and re.search(r"\b(200|301|302)\b", h):
            # /admin/ → 200 etc.
            path = h.split("→", 1)[0].strip()
            if path in ("/admin/", "/admin/login", "/admin", "/login",
                         "/checkout/cart/", "/user/login", "/modules/", "/_health"):
                has_generic_probe = True
                reasons.append(f"generic_probe: {path}")
            else:
                reasons.append(f"specific_probe: {path}")

    if fp_indicators:
        return "FALSE_POS", reasons + [f"FP: {f}" for f in fp_indicators]
    if has_specific_body and (has_cookie or len([r for r in reasons if r.startswith("specific")]) >= 2):
        return "STRONG", reasons
    if has_specific_body or has_cookie:
        return "OK", reasons
    if has_generic_probe and not has_specific_body:
        return "WEAK", reasons
    return "WEAK", reasons or ["no_strong_signal"]


def audit(verbose: bool = False, limit: int | None = None) -> int:
    db_url = os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan")
    conn = psycopg2.connect(db_url)

    sql = """
        SELECT order_id, host_ip, raw_output, created_at
          FROM scan_results
         WHERE tool_name = 'cms_fingerprint'
           AND raw_output IS NOT NULL
         ORDER BY created_at DESC
    """
    if limit:
        sql += f" LIMIT {int(limit)}"

    summary: Counter = Counter()
    fp_examples: list[dict] = []
    strong_examples: list[dict] = []

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql)
        rows = cur.fetchall()
    conn.close()

    print(f"[audit] {len(rows)} cms_fingerprint scan-results")

    for row in rows:
        try:
            data = json.loads(row["raw_output"])
        except (json.JSONDecodeError, TypeError):
            continue
        candidates = data.get("candidates") or []
        if isinstance(data, list):
            candidates = data
        # Anderes Format moeglich — robust
        if not candidates and isinstance(data, dict):
            cms_field = data.get("cms")
            if cms_field:
                candidates = [{"cms": cms_field, "details": data}]
        for c in candidates:
            cms = c.get("cms") or "?"
            details = c.get("details") or {}
            hits = details.get("probe_hits") or []
            if not hits:
                continue
            klass, reasons = classify_probe_hits(cms, hits)
            summary[(cms, klass)] += 1
            if klass == "FALSE_POS" and len(fp_examples) < 25:
                fp_examples.append({
                    "order_id": str(row["order_id"])[:8],
                    "host_ip": str(row["host_ip"]),
                    "cms": cms,
                    "hits": hits,
                    "reasons": reasons,
                })
            elif klass == "STRONG" and len(strong_examples) < 5:
                strong_examples.append({
                    "order_id": str(row["order_id"])[:8],
                    "host_ip": str(row["host_ip"]),
                    "cms": cms,
                    "hits": hits[:3],
                })

    print("\n=== Klassifizierungs-Verteilung pro CMS ===")
    cms_groups: dict[str, dict] = {}
    for (cms, klass), n in summary.items():
        cms_groups.setdefault(cms, {})[klass] = n
    for cms in sorted(cms_groups):
        d = cms_groups[cms]
        total = sum(d.values())
        parts = []
        for k in ("STRONG", "OK", "WEAK", "FALSE_POS"):
            v = d.get(k, 0)
            if v:
                parts.append(f"{k}={v}")
        print(f"  {cms:18} total={total:>4}  {' '.join(parts)}")

    if fp_examples:
        print(f"\n=== FALSE-POSITIVE-Beispiele ({len(fp_examples)}) ===")
        for ex in fp_examples[:15]:
            print(f"  [{ex['cms']:10}] order={ex['order_id']} host={ex['host_ip']}")
            for h in ex["hits"][:3]:
                print(f"      hit: {h}")
            for r in ex["reasons"][:3]:
                print(f"      reason: {r}")

    if verbose and strong_examples:
        print(f"\n=== STRONG-Beispiele (Reference) ===")
        for ex in strong_examples:
            print(f"  [{ex['cms']:10}] order={ex['order_id']} host={ex['host_ip']}")
            for h in ex["hits"]:
                print(f"      {h}")

    print(f"\n[audit] done. Tip: re-run nach Pipeline-Deploy mit fixed Patterns "
          f"sollte FALSE_POS-Rate auf 0 sinken.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    return audit(verbose=args.verbose, limit=args.limit)


if __name__ == "__main__":
    sys.exit(main())

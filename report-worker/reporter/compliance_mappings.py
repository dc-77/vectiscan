"""Compliance-Mapping-Aggregator (M5 Track 5c, Doc 02 Anhang D).

Buendelt die per-Finding-Mappings auf die vier Frameworks:
  - NIS2 / §30 BSIG
  - BSI IT-Grundschutz
  - ISO 27001 Annex A
  - DSGVO Art. 32 + verwandte

Output ist `dict[finding_id, {nis2, bsi, iso27001, dsgvo}]` und wird in
``report_data["compliance_mappings"]`` befuellt. Renderer (Anhang D + inline
Compliance-Zeile pro Befund) lesen das.
"""

from __future__ import annotations

import logging
from typing import Any

from reporter.compliance.bsi_grundschutz import (
    map_finding_to_bsi, get_baustein_title,
)
from reporter.compliance.dsgvo import (
    map_finding_to_dsgvo, get_article_title,
)
from reporter.compliance.iso27001 import (
    map_finding_to_iso27001, get_control_title,
)
from reporter.compliance.nis2_bsig import (
    map_finding_to_bsig, get_bsig_ref,
)

logger = logging.getLogger(__name__)


def build_compliance_mappings(
    findings: list[dict[str, Any]] | None,
) -> dict[str, dict[str, str]]:
    """Erzeugt pro Finding einen Compliance-Mapping-Eintrag.

    Returns: dict mapping (external_id or id) -> {
        "nis2": "§30 Abs. 2 Nr. 5 BSIG",
        "bsi":  "NET.3.2",
        "iso27001": "A.8.20",
        "dsgvo":    "Art. 32 Abs. 1 lit. b",
        "nis2_title": "Schwachstellenmanagement",
        "bsi_title":  "Firewall",
        "iso27001_title": "Netzwerksicherheit",
        "dsgvo_title": "Vertraulichkeit ...",
    }
    """
    findings = findings or []
    out: dict[str, dict[str, str]] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        if f.get("is_positive_finding"):
            continue
        fid = f.get("external_id") or f.get("id")
        if not fid:
            continue

        try:
            nis2_key = map_finding_to_bsig(f)
            nis2_ref = get_bsig_ref(nis2_key)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("nis2_mapping_failed fid=%s err=%s", fid, exc)
            nis2_ref = ""
            nis2_key = ""

        try:
            bsi_ref = map_finding_to_bsi(f)
        except Exception as exc:  # pragma: no cover
            logger.warning("bsi_mapping_failed fid=%s err=%s", fid, exc)
            bsi_ref = ""

        try:
            iso_ref = map_finding_to_iso27001(f)
        except Exception as exc:  # pragma: no cover
            logger.warning("iso_mapping_failed fid=%s err=%s", fid, exc)
            iso_ref = ""

        try:
            dsgvo_ref = map_finding_to_dsgvo(f)
        except Exception as exc:  # pragma: no cover
            logger.warning("dsgvo_mapping_failed fid=%s err=%s", fid, exc)
            dsgvo_ref = ""

        out[fid] = {
            "nis2": nis2_ref,
            "nis2_key": nis2_key,
            "bsi": bsi_ref,
            "bsi_title": get_baustein_title(bsi_ref) if bsi_ref else "",
            "iso27001": iso_ref,
            "iso27001_title": get_control_title(iso_ref) if iso_ref else "",
            "dsgvo": dsgvo_ref,
            "dsgvo_title": get_article_title(dsgvo_ref) if dsgvo_ref else "",
        }
    return out


__all__ = ["build_compliance_mappings"]

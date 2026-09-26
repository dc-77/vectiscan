"""Faktenfamilien: welche Pruefungen dieselbe Messung lesen (S6b-3, spec/10 R4).

Eine Einschraenkung "Daten reichen nicht aus" ist falsch, wenn dasselbe Subjekt fuer dieselbe
Faktenfamilie gemessen ist: DMARC fuer dortmund-beach.com ist mit ``dmarc_none`` belegt, auch
wenn ``dmarc_quarantine`` mangels Richtlinie nichts sagen kann. Solche Zeilen entfallen im
Bericht, und das Gate meldet jede verbleibende Einschraenkung, die einem Befund oder einem
"unauffaellig" derselben Familie am selben Subjekt widerspricht.

Familien trennen, was getrennt gemessen wird: die Laufzeit eines Zertifikats (``cert_validity``)
ist aus dem Verbindungsaufbau bekannt, seine Vertrauenskette (``cert_chain``) nur aus einem
testssl-Lauf. Eine bekannte Laufzeit darf eine ungepruefte Kette nicht verdecken. Name und
Selbstsignatur liefert auch httpx; sie sind eigene Familien, sonst stuende "Kette nicht geprueft"
als Widerspruch neben "Zertifikat passt nicht zum Namen" (krause-computer, trunk-immobilien).
"""
from __future__ import annotations

from typing import Iterable, Optional

from reporter.catalog.schema import CheckResult

FACT_FAMILIES: dict[str, tuple[str, ...]] = {
    "spf": ("spf_missing", "spf_permissive", "spf_softfail"),
    "dmarc": ("dmarc_missing", "dmarc_none", "dmarc_quarantine"),
    "mta_sts": ("mta_sts_missing",),
    "tls_rpt": ("tls_rpt_missing",),
    "dane": ("dane_missing",),
    "tls_protocols": ("tls_legacy_protocols", "tls_no_13", "tls_no_fallback_scsv"),
    "tls_ciphers": ("tls_weak_ciphers",),
    "cert_validity": ("cert_expired", "cert_expiring", "cert_expiring_later"),
    "cert_chain": ("cert_chain_incomplete",),
    "cert_name": ("cert_hostname_mismatch",),
    "cert_self_signed": ("cert_self_signed",),
    "http_headers": ("security_headers_incomplete", "csp_missing", "csp_weak", "header_duplicate"),
    "hsts": ("hsts_missing", "hsts_short"),
}

# Gruende, die nur "hier fehlt etwas" sagen. Gruende mit Information (Teilmessung, Messung an
# einer Weiterleitung, Parkseite) bleiben stehen, auch wenn eine andere Regel der Familie misst.
SUPPRESSIBLE_REASONS = frozenset({"insufficient_facts", "cert_unknown", "unreachable", "precondition_not_met"})

_FAMILY_OF: dict[str, str] = {check: fam for fam, checks in FACT_FAMILIES.items() for check in checks}


def family_of(check_id: str) -> Optional[str]:
    return _FAMILY_OF.get(check_id)


def measured(results: Iterable[CheckResult]) -> set[tuple[str, str]]:
    """(Familie, Gruppe) aller gemessenen Subjekte: fehlgeschlagen oder Positivbedingung getroffen."""
    out: set[tuple[str, str]] = set()
    for r in results:
        fam = family_of(r.check_id)
        if fam and (r.status == "fail" or r.affirmed):
            out.add((fam, r.group_key))
    return out


def suppressed(result: CheckResult, gemessen: set[tuple[str, str]]) -> bool:
    """Ist diese "nicht pruefbar"-Zeile durch eine Messung derselben Familie ueberholt?"""
    if result.status != "not_testable" or (result.reason_code or "insufficient_facts") not in SUPPRESSIBLE_REASONS:
        return False
    fam = family_of(result.check_id)
    return fam is not None and (fam, result.group_key) in gemessen


__all__ = ["FACT_FAMILIES", "SUPPRESSIBLE_REASONS", "family_of", "measured", "suppressed"]

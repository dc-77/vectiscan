"""CVSS-Check: prueft CVSS-Score und Vektor-Konsistenz.

Adressiert aus Doc 01 (Fehleranalyse_und_Korrekturplan.md):
- P1-01: CVSS-Score 0.0 obwohl Impact-Vektor-Teile gesetzt (C/I/A != N).
- P1-02: Score und Vektor passen nicht zusammen (Library-Validierung).
- P2-05: Inkonsistente Vektor-Formatierung (fehlt `CVSS:3.1/`-Prefix).

Hygiene-Findings (`cvss_vector in ("—", "-", "")` und `score == 0`) werden
geskipt — die landen in M2.

Library `cvss` ist optional; falls nicht installiert, wird Score-vs-Vector
nicht library-validiert (aber Substring-Checks laufen weiterhin).
"""
from __future__ import annotations

from typing import Any

from reporter.validation.gate import ValidationIssue

try:
    from cvss import CVSS3
    _CVSS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _CVSS_AVAILABLE = False

# CVSS-Score-Vektor-Tokens, die einen Impact > None implizieren
_IMPACT_TOKENS = ("C:L", "C:M", "C:H", "I:L", "I:M", "I:H", "A:L", "A:M", "A:H")
_HYGIENE_VECTORS = {"", "—", "-", "None", "n/a"}


def check(
    findings_data: dict,
    report_data: dict,
    context: dict,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    findings = findings_data.get("findings", []) or []

    if not _CVSS_AVAILABLE:
        issues.append(ValidationIssue(
            check="cvss",
            severity="warning",
            finding_id=None,
            message=(
                "cvss-Python-Library nicht installiert — "
                "Score-vs-Vektor-Validierung wird geskipt "
                "(Substring-Checks laufen weiter)."
            ),
            detail={"library": "cvss"},
        ))

    for f in findings:
        fid = f.get("id")
        vector_raw = f.get("cvss_vector")
        vector = (vector_raw or "").strip()
        score = f.get("cvss_score")

        try:
            score_f = float(score) if score is not None else None
        except (TypeError, ValueError):
            score_f = None

        # Hygiene-Skip (M2-Thema)
        is_hygiene_vec = vector in _HYGIENE_VECTORS
        if is_hygiene_vec and (score_f is None or score_f == 0.0):
            continue

        # P1-01: Score 0.0 aber Impact-Tokens im Vektor
        if score_f == 0.0 and any(tok in vector for tok in _IMPACT_TOKENS):
            present = [tok for tok in _IMPACT_TOKENS if tok in vector]
            issues.append(ValidationIssue(
                check="cvss",
                severity="error",
                finding_id=fid,
                message=(
                    "CVSS-Score ist 0.0, aber Vektor enthaelt Impact-Tokens "
                    f"({', '.join(present)})"
                ),
                detail={
                    "cvss_score": score_f,
                    "cvss_vector": vector,
                    "impact_tokens": present,
                },
            ))

        # P2-05: Vektor vorhanden aber ohne CVSS:3.1/-Prefix
        if vector and not is_hygiene_vec and not vector.startswith("CVSS:3.1/"):
            issues.append(ValidationIssue(
                check="cvss",
                severity="error",
                finding_id=fid,
                message=(
                    f"CVSS-Vektor ohne CVSS:3.1/-Prefix: {vector!r}"
                ),
                detail={"cvss_vector": vector},
            ))
            # Library-Validation skip wenn Prefix fehlt (wuerde sicher crashen).
            continue

        # P1-02: Score vs Vektor (Library)
        if (
            _CVSS_AVAILABLE
            and vector
            and not is_hygiene_vec
            and vector.startswith("CVSS:3.1/")
            and score_f is not None
        ):
            try:
                computed = float(CVSS3(vector).base_score)
            except Exception as e:  # ungueltiger Vektor → Error
                issues.append(ValidationIssue(
                    check="cvss",
                    severity="error",
                    finding_id=fid,
                    message=f"CVSS-Vektor ungueltig: {e}",
                    detail={"vector": vector, "exception": str(e)},
                ))
                continue
            if abs(computed - score_f) > 0.1:
                issues.append(ValidationIssue(
                    check="cvss",
                    severity="error",
                    finding_id=fid,
                    message=(
                        f"CVSS-Score {score_f} weicht von Vektor-berechnetem "
                        f"Base-Score {computed} ab"
                    ),
                    detail={
                        "cvss_score": score_f,
                        "computed": computed,
                        "vector": vector,
                    },
                ))

    return issues

"""Validation-Gate Package (M1).

Spec: docs/report-erstellung/01_Fehleranalyse_und_Korrekturplan.md Phase A
Plan: ~/.claude/plans/ich-m-chte-gerne-das-iterative-nova.md M1

Re-Export der zentralen Typen. Auto-Discovery passiert NICHT hier — die
einzelnen Check-Module werden in `gate.py` zur Laufzeit per `__import__`
geladen, damit das Gate auch dann funktioniert, wenn der Check-Builder-Agent
sein Modul noch nicht gemerged hat.
"""

from reporter.validation.gate import (
    ValidationFailedError,
    ValidationGate,
    ValidationIssue,
    ValidationLevel,
    ValidationResult,
)

__all__ = [
    "ValidationFailedError",
    "ValidationGate",
    "ValidationIssue",
    "ValidationLevel",
    "ValidationResult",
]

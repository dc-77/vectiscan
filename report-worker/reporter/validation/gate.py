"""Validation-Gate fuer M1: prueft findings_data + report_data vor PDF-Upload.

Spec: docs/report-erstellung/01_Fehleranalyse_und_Korrekturplan.md Phase A
Plan: ~/.claude/plans/ich-m-chte-gerne-das-iterative-nova.md M1
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

import structlog

log = structlog.get_logger()


class ValidationLevel(str, Enum):
    OFF = "off"      # nur fuer lokale Tests
    WARN = "warn"    # Defekte werden geloggt + in reports.validation_warnings persistiert,
                     # Build geht durch. Default in Prod waehrend M1.
    STRICT = "strict"  # Defekte blockieren den Build (Order -> failed). Default ab M2-Ende.


@dataclass
class ValidationIssue:
    check: str           # e.g. "titles", "ids", "cvss"
    severity: str        # "error" | "warning"
    finding_id: str | None
    message: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    passed: bool
    level: ValidationLevel
    errors: list[ValidationIssue] = field(default_factory=list)
    warnings: list[ValidationIssue] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    checks_skipped: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "level": self.level.value,
            "errors": [i.__dict__ for i in self.errors],
            "warnings": [i.__dict__ for i in self.warnings],
            "checks_run": self.checks_run,
            "checks_skipped": self.checks_skipped,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
        }


# Alle Checks, die das Gate aufruft. Jeder Check ist ein Callable
# `check(findings_data: dict, report_data: dict, context: dict) -> list[ValidationIssue]`.
# Reihenfolge stabil. Wenn ein Modul fehlt (Check-Builder noch nicht gemerged),
# wird das im Result als skipped vermerkt — Gate selbst crasht nicht.
CHECK_REGISTRY: list[tuple[str, str]] = [
    ("titles", "reporter.validation.checks.titles"),
    ("ids", "reporter.validation.checks.ids"),
    ("cvss", "reporter.validation.checks.cvss"),
    ("consistency", "reporter.validation.checks.consistency"),
    ("tech_table", "reporter.validation.checks.tech_table"),
    ("eol", "reporter.validation.checks.eol"),
    ("plan", "reporter.validation.checks.plan"),
]


class ValidationGate:
    """Orchestriert alle Validation-Checks.

    Usage:
        gate = ValidationGate.from_env()
        result = gate.run(findings_data, report_data, context={"package": ..., "order_id": ...})
        if not result.passed and gate.level == ValidationLevel.STRICT:
            raise ValidationFailedError(result)
    """

    def __init__(self, level: ValidationLevel = ValidationLevel.WARN):
        self.level = level

    @classmethod
    def from_env(cls) -> "ValidationGate":
        raw = os.environ.get("VECTISCAN_VALIDATION_LEVEL", "warn").lower().strip()
        try:
            level = ValidationLevel(raw)
        except ValueError:
            log.warning("validation_level_invalid", raw=raw, fallback="warn")
            level = ValidationLevel.WARN
        return cls(level=level)

    def run(
        self,
        findings_data: dict,
        report_data: dict | None = None,
        context: dict | None = None,
    ) -> ValidationResult:
        result = ValidationResult(passed=True, level=self.level)
        if self.level == ValidationLevel.OFF:
            log.info("validation_gate_off")
            return result

        ctx = context or {}
        rd = report_data or {}

        for check_name, module_path in CHECK_REGISTRY:
            check_fn = self._load_check(check_name, module_path)
            if check_fn is None:
                result.checks_skipped.append(check_name)
                continue
            try:
                issues = check_fn(findings_data, rd, ctx) or []
            except Exception as e:
                log.exception("validation_check_crashed", check=check_name, error=str(e))
                # Ein Check-Crash darf den Build nicht auf passed=False zwingen,
                # wird aber als WARNING dokumentiert.
                result.warnings.append(
                    ValidationIssue(
                        check=check_name,
                        severity="warning",
                        finding_id=None,
                        message=f"Check crashed: {e}",
                        detail={"exception_type": type(e).__name__},
                    )
                )
                continue
            result.checks_run.append(check_name)
            for issue in issues:
                if issue.severity == "error":
                    result.errors.append(issue)
                else:
                    result.warnings.append(issue)

        result.passed = len(result.errors) == 0
        log.info(
            "validation_gate_complete",
            level=self.level.value,
            passed=result.passed,
            errors=len(result.errors),
            warnings=len(result.warnings),
            checks_run=result.checks_run,
            checks_skipped=result.checks_skipped,
        )
        return result

    def _load_check(self, name: str, module_path: str) -> Callable | None:
        try:
            mod = __import__(module_path, fromlist=["check"])
            return getattr(mod, "check", None)
        except ImportError:
            return None


class ValidationFailedError(RuntimeError):
    """STRICT-Gate-Fehler: Build wird abgebrochen, Order auf failed gesetzt."""

    def __init__(self, result: ValidationResult):
        self.result = result
        msg = f"Validation failed with {len(result.errors)} errors"
        super().__init__(msg)

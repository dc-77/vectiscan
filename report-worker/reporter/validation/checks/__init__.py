"""Validation-Check-Module (M1).

Jedes Modul exportiert eine Funktion `check(findings_data, report_data, context)`
die eine Liste von `ValidationIssue` zurueckgibt.

Erwartete Module (siehe `reporter.validation.gate.CHECK_REGISTRY`):
- titles
- ids
- cvss
- consistency
- tech_table
- eol
- plan

Die Module werden vom Check-Builder-Agent geliefert; das Gate kann auch
ohne sie laufen (Module landen dann in `checks_skipped`).
"""
